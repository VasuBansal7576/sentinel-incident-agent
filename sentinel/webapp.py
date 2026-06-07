from __future__ import annotations

import hmac
import json
import os
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict

from sentinel.config import SentinelSettings
from sentinel.connectivity import run_live_connectivity_checks
from sentinel.credentials import (
    OAuthTokenStoreError,
    missing_live_credentials,
    missing_live_credentials_without_oauth_store,
    resolve_settings,
    save_datadog_oauth_payload,
    save_github_oauth_payload,
    save_slack_oauth_payload,
    token_source_status,
)
from sentinel.errors import ToolExecutionError, redact_sensitive_text
from sentinel.live_clients import LiveProviderClients
from sentinel.models import ApprovalCommand, AuditEvent, InvestigationState, InvestigationStatus
from sentinel.oauth import OAuthManager, verify_pagerduty_signature
from sentinel.orchestrator import SentinelOrchestrator
from sentinel.postgres_store import build_store
from sentinel.rate_limiters import RedisRateLimitBackend
from sentinel.real_tools import LiveToolFactory
from sentinel.slow_query import (
    TARGET_USER_ID,
    create_orders_user_id_index,
    reset_slow_query_database,
    run_slow_query,
    slow_query_metrics,
    slow_query_status,
)
from sentinel.tools import ToolExecutor


_MANAGED_STORE_ATTR = "_sentinel_managed_store"
_PROCESS_STARTED_AT = datetime.now(UTC)
_PROCESS_START_MONOTONIC = time.monotonic()


class WebhookRunResponse(BaseModel):
    accepted: bool
    investigation_id: str | None = None
    message: str


class GenericWebhookRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    incident_id: Any | None = None
    alert_id: Any | None = None
    id: Any | None = None
    fingerprint: Any | None = None
    source: Any | None = None
    affected_service: Any | None = None
    affected_services: Any | None = None
    service: Any | None = None
    service_name: Any | None = None
    services: Any | None = None
    labels: Any | None = None
    alert: Any | None = None
    alerts: Any | None = None
    commonLabels: Any | None = None
    groupLabels: Any | None = None
    groupKey: Any | None = None

    def normalized_payload(self) -> dict[str, Any]:
        payload = self.model_dump(exclude_none=True)
        source = payload.get("source")
        payload["source"] = source.strip() if isinstance(source, str) and source.strip() else "generic_webhook"
        return payload


class ApprovalCommandRequest(BaseModel):
    request_id: str
    approver_id: str
    decision: Literal["approve", "reject"]
    idempotency_key: str | None = None

    def to_command(self, investigation_id: str) -> ApprovalCommand:
        return ApprovalCommand(
            request_id=self.request_id,
            approver_id=self.approver_id,
            decision=self.decision,
            idempotency_key=(
                self.idempotency_key
                or f"{investigation_id}:approval-command:{self.request_id}:{self.approver_id}:{self.decision}"
            ),
        )


class _UnavailableInvestigationStore:
    def __init__(self, error: Exception):
        self.error = redact_sensitive_text(error, max_length=500)
        setattr(self, _MANAGED_STORE_ATTR, True)

    def ping(self) -> bool:
        return False

    def close(self) -> None:
        return None

    def load_oauth_token(self, provider: str) -> None:
        raise RuntimeError(self._message())

    def __getattr__(self, name: str):
        raise RuntimeError(self._message())

    def _message(self) -> str:
        return f"Investigation Store unavailable: {self.error}"


def create_app(settings: SentinelSettings | None = None) -> FastAPI:
    if settings is None:
        try:
            settings = SentinelSettings.from_env()
        except Exception as exc:
            return _invalid_configuration_app(exc)
    app = FastAPI(title="SENTINEL live webhook receiver", lifespan=_app_lifespan)
    app.state.store = _build_app_store(settings)

    @app.get("/health")
    def health() -> dict[str, Any]:
        store = _get_app_store(app, settings)
        credential_status = _credential_status(settings, store)
        body = {
            "status": "ok",
            "missing_live_credentials": credential_status["missing_live_credentials"],
            "oauth_store_reachable": credential_status["oauth_store_reachable"],
            "webhook_signature_verification": bool(settings.pagerduty_webhook_secret),
            "webhook_subscription_bound": bool(settings.pagerduty_webhook_subscription_id),
        }
        if credential_status["oauth_store_error"]:
            body["oauth_store_error"] = credential_status["oauth_store_error"]
        return body

    @app.get("/metrics")
    def prometheus_metrics() -> PlainTextResponse:
        return PlainTextResponse(
            _prometheus_metrics_body(settings),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.get("/slow-query")
    def slow_query(user_id: int = TARGET_USER_ID) -> dict[str, Any]:
        result = run_slow_query(user_id)
        return {
            "ok": True,
            "service": settings.default_service,
            "query": "SELECT * FROM orders WHERE user_id = ?",
            "user_id": result.user_id,
            "matched_rows": result.matched_rows,
            "duration_ms": round(result.duration_seconds * 1000, 3),
            "index_present": result.index_present,
            "missing_index": not result.index_present,
            "query_plan": result.query_plan,
            "row_count": result.row_count,
            "scan_repeats": result.scan_repeats,
        }

    @app.get("/slow-query/status")
    def slow_query_status_endpoint() -> dict[str, Any]:
        return slow_query_status()

    @app.post("/slow-query/reset")
    def slow_query_reset(row_count: int = 120_000) -> dict[str, Any]:
        return reset_slow_query_database(row_count=row_count)

    @app.post("/slow-query/add-index")
    def slow_query_add_index(request: Request) -> dict[str, Any]:
        _require_operator_auth(settings, request)
        return create_orders_user_id_index()

    @app.get("/ready")
    def ready() -> JSONResponse:
        body = _readiness_body(settings, _get_app_store(app, settings))
        return JSONResponse(status_code=200 if body["ready"] else 503, content=body)

    @app.get("/ready/live")
    def live_ready(request: Request) -> JSONResponse:
        _require_operator_auth(settings, request)
        body = _live_readiness_body(settings, _get_app_store(app, settings))
        return JSONResponse(status_code=200 if body["ready"] else 503, content=body)

    @app.get("/live/connectivity")
    def live_connectivity(request: Request) -> dict[str, Any]:
        _require_operator_auth(settings, request)
        store = _get_app_store(app, settings)
        return run_live_connectivity_checks(settings, store=store).model_dump(mode="json")

    @app.get("/oauth/slack/install")
    def slack_install(request: Request):
        _require_operator_auth(settings, request)
        _require_oauth_install_config(settings, "slack")
        manager = OAuthManager(settings)
        state = manager.issue_state("slack")
        store = _get_app_store(app, settings)
        _remember_oauth_state(store, "slack", state)
        return RedirectResponse(manager.slack_install_url(state=state))

    @app.get("/oauth/slack/callback")
    def slack_callback(code: str, state: str) -> dict[str, Any]:
        manager = OAuthManager(settings)
        store = _get_app_store(app, settings)
        _consume_issued_oauth_state(manager, store, "slack", state)
        try:
            payload = manager.exchange_slack_code(code, state)
            save_slack_oauth_payload(store, payload)
        except ToolExecutionError as exc:
            raise _oauth_callback_exception(exc) from exc
        except Exception as exc:
            raise _store_unavailable_exception(exc) from exc
        return {
            "ok": True,
            "team": payload.get("team", {}).get("name"),
            "bot_user_id": payload.get("bot_user_id"),
            "token_received": bool(payload.get("access_token")),
        }

    @app.get("/oauth/github/install")
    def github_install(request: Request):
        _require_operator_auth(settings, request)
        _require_oauth_install_config(settings, "github")
        manager = OAuthManager(settings)
        state = manager.issue_state("github")
        store = _get_app_store(app, settings)
        _remember_oauth_state(store, "github", state)
        return RedirectResponse(manager.github_install_url(state=state))

    @app.get("/oauth/github/callback")
    def github_callback(code: str, state: str) -> dict[str, Any]:
        manager = OAuthManager(settings)
        store = _get_app_store(app, settings)
        _consume_issued_oauth_state(manager, store, "github", state)
        try:
            payload = manager.exchange_github_code(code, state)
            save_github_oauth_payload(store, payload)
        except ToolExecutionError as exc:
            raise _oauth_callback_exception(exc) from exc
        except Exception as exc:
            raise _store_unavailable_exception(exc) from exc
        return {
            "ok": True,
            "scope": payload.get("scope"),
            "token_type": payload.get("token_type"),
            "token_received": bool(payload.get("access_token")),
        }

    @app.get("/oauth/datadog/install")
    def datadog_install(request: Request):
        _require_operator_auth(settings, request)
        _require_oauth_install_config(settings, "datadog")
        manager = OAuthManager(settings)
        state = manager.issue_state("datadog")
        code_verifier = manager.issue_pkce_verifier()
        store = _get_app_store(app, settings)
        _remember_oauth_state(store, "datadog", state)
        _remember_oauth_value(store, "datadog", state, "pkce_verifier", code_verifier)
        return RedirectResponse(manager.datadog_install_url(state=state, code_verifier=code_verifier))

    @app.get("/oauth/datadog/callback")
    def datadog_callback(code: str, state: str, domain: str | None = None) -> dict[str, Any]:
        manager = OAuthManager(settings)
        store = _get_app_store(app, settings)
        _consume_issued_oauth_state(manager, store, "datadog", state)
        try:
            code_verifier = _lookup_oauth_value(store, "datadog", state, "pkce_verifier")
            payload = manager.exchange_datadog_code(code, state, code_verifier=code_verifier, domain=domain)
            save_datadog_oauth_payload(store, payload)
        except ToolExecutionError as exc:
            raise _oauth_callback_exception(exc) from exc
        except Exception as exc:
            raise _store_unavailable_exception(exc) from exc
        return {
            "ok": True,
            "domain": payload.get("domain"),
            "scope": payload.get("scope"),
            "token_type": payload.get("token_type"),
            "token_received": bool(payload.get("access_token")),
            "refresh_token_received": bool(payload.get("refresh_token")),
        }

    @app.post("/webhooks/pagerduty", response_model=WebhookRunResponse)
    async def pagerduty_webhook(request: Request, background_tasks: BackgroundTasks):
        raw_body = await request.body()
        _require_pagerduty_webhook_signature_config(settings)
        if not verify_pagerduty_signature(
            raw_body,
            request.headers.get("x-pagerduty-signature"),
            settings.pagerduty_webhook_secret,
            settings.pagerduty_webhook_previous_secret,
        ):
            raise HTTPException(status_code=401, detail="Invalid PagerDuty webhook signature")
        _require_pagerduty_webhook_subscription(settings, request)
        try:
            payload = json.loads(raw_body.decode() or "{}")
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="PagerDuty webhook body must be valid JSON") from exc
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="PagerDuty webhook body must be a JSON object")
        actionable_items = _actionable_pagerduty_payload_items(payload)
        if not actionable_items:
            if _is_pagerduty_test_event(payload):
                return WebhookRunResponse(
                    accepted=True,
                    investigation_id=None,
                    message="Accepted PagerDuty webhook test event; no Investigation created",
                )
            return WebhookRunResponse(
                accepted=True,
                investigation_id=None,
                message="Accepted non-triggering PagerDuty webhook event; no Investigation created",
            )
        incident_ids = _extract_incident_ids_from_items(actionable_items)
        if not incident_ids:
            raise HTTPException(status_code=400, detail="PagerDuty webhook did not include an incident id")
        if len(incident_ids) > 1:
            raise HTTPException(
                status_code=400,
                detail="PagerDuty webhook contained multiple actionable incidents; send one incident per webhook",
            )
        incident_id = incident_ids[0]
        store = _get_app_store(app, settings)
        _require_runtime_ready(
            settings,
            store,
            operation="live investigation",
        )
        webhook_key = _webhook_idempotency_key("pagerduty", incident_id)
        if hasattr(store, "lookup_idempotency_key"):
            existing_id = store.lookup_idempotency_key(webhook_key)
            if existing_id:
                return WebhookRunResponse(
                    accepted=True,
                    investigation_id=existing_id,
                    message=f"Duplicate PagerDuty webhook for {incident_id}; returning existing investigation",
                )
        _require_runtime_ready(
            settings,
            store,
            operation="live investigation",
            provider_preflight=True,
        )
        services = _extract_webhook_services(actionable_items, settings)
        state, created = _create_received_investigation(
            store,
            payload,
            incident_id,
            services,
            source="pagerduty",
        )
        if not created:
            return WebhookRunResponse(
                accepted=True,
                investigation_id=state.id,
                message=f"Duplicate PagerDuty webhook for {incident_id}; returning existing investigation",
            )
        background_tasks.add_task(
            _run_live_investigation_safely,
            settings,
            store,
            payload,
            incident_id,
            services,
            state.id,
        )
        return WebhookRunResponse(
            accepted=True,
            investigation_id=state.id,
            message=f"Accepted PagerDuty webhook for {incident_id}",
        )

    @app.post("/webhooks/generic", response_model=WebhookRunResponse)
    async def generic_alert_webhook(request: Request, background_tasks: BackgroundTasks):
        try:
            payload = await request.json()
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="Generic webhook body must be valid JSON") from exc
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="Generic webhook body must be a JSON object")
        payload = GenericWebhookRequest.model_validate(payload).normalized_payload()
        incident_id = _extract_generic_incident_id(payload)
        if not incident_id:
            raise HTTPException(status_code=400, detail="Generic webhook must include incident_id, alert_id, or id")
        services = _extract_generic_services(payload, settings)
        store = _get_app_store(app, settings)
        _require_runtime_ready(
            settings,
            store,
            operation="free-tier live investigation",
        )
        webhook_key = _webhook_idempotency_key("generic_webhook", incident_id)
        if hasattr(store, "lookup_idempotency_key"):
            existing_id = store.lookup_idempotency_key(webhook_key)
            if existing_id:
                return WebhookRunResponse(
                    accepted=True,
                    investigation_id=existing_id,
                    message=f"Duplicate generic webhook for {incident_id}; returning existing investigation",
                )
        _require_runtime_ready(
            settings,
            store,
            operation="free-tier live investigation",
            provider_preflight=True,
        )
        state, created = _create_received_investigation(
            store,
            payload,
            incident_id,
            services,
            source="generic_webhook",
        )
        if not created:
            return WebhookRunResponse(
                accepted=True,
                investigation_id=state.id,
                message=f"Duplicate generic webhook for {incident_id}; returning existing investigation",
            )
        background_tasks.add_task(
            _run_live_investigation_safely,
            settings,
            store,
            payload,
            incident_id,
            services,
            state.id,
        )
        return WebhookRunResponse(
            accepted=True,
            investigation_id=state.id,
            message=f"Accepted generic webhook for {incident_id}",
        )

    @app.get("/investigations/{investigation_id}")
    def investigation_status(investigation_id: str, request: Request) -> dict[str, Any]:
        _require_operator_auth(settings, request)
        store = _get_app_store(app, settings)
        try:
            state = store.load_state(investigation_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except Exception as exc:
            raise _store_unavailable_exception(exc) from exc
        return _investigation_response(state)

    @app.post("/investigations/{investigation_id}/approval")
    def submit_approval(investigation_id: str, command: ApprovalCommandRequest, request: Request) -> dict[str, Any]:
        _require_operator_auth(settings, request)
        store = _get_app_store(app, settings)
        _require_runtime_ready(
            settings,
            store,
            operation="live remediation",
            provider_preflight=True,
        )
        try:
            state = _resume_live_investigation_with_approval(
                settings,
                investigation_id,
                command.to_command(investigation_id),
                store=store,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ToolExecutionError as exc:
            raise _live_operation_exception(exc) from exc
        except Exception as exc:
            raise _store_unavailable_exception(exc) from exc
        return _investigation_response(state)

    @app.post("/live/run/{incident_id}")
    def run_live_now(incident_id: str, request: Request, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        _require_operator_auth(settings, request)
        body = payload or {}
        store = _get_app_store(app, settings)
        _require_runtime_ready(
            settings,
            store,
            operation="live investigation",
            provider_preflight=True,
        )
        try:
            state = _run_live_investigation(
                settings,
                body,
                incident_id,
                services=_extract_live_run_services(body, settings),
                store=store,
            )
        except HTTPException:
            raise
        except ToolExecutionError as exc:
            raise _live_operation_exception(exc) from exc
        except Exception as exc:
            raise _store_unavailable_exception(exc) from exc
        return _investigation_response(state)

    return app


def _invalid_configuration_app(exc: Exception) -> FastAPI:
    app = FastAPI(title="SENTINEL live webhook receiver")
    safe_error = redact_sensitive_text(exc, max_length=500)

    @app.get("/health")
    def invalid_health() -> dict[str, Any]:
        return {
            "status": "configuration_error",
            "ready": False,
            "config_error": safe_error,
        }

    @app.get("/ready")
    def invalid_ready() -> JSONResponse:
        return JSONResponse(
            status_code=503,
            content={
                "ready": False,
                "status": "configuration_error",
                "missing_live_credentials": [],
                "config_error": safe_error,
            },
        )

    @app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    )
    def invalid_configuration_unavailable(path: str) -> None:
        raise HTTPException(
            status_code=503,
            detail={
                "message": "SENTINEL configuration is invalid",
                "config_error": safe_error,
            },
        )

    return app


def _readiness_body(settings: SentinelSettings, store: Any) -> dict[str, Any]:
    credential_status = _credential_status(settings, store)
    missing = credential_status["missing_live_credentials"]
    database_reachable = _store_reachable(store)
    redis_reachable = _redis_reachable(settings)
    is_ready = (
        not missing
        and database_reachable
        and redis_reachable
        and credential_status["oauth_store_reachable"]
    )
    body = {
        "ready": is_ready,
        "receiver_process": _receiver_process_identity(),
        "missing_live_credentials": missing,
        "token_sources": credential_status["token_sources"],
        "oauth_store_reachable": credential_status["oauth_store_reachable"],
        "database_configured": bool(settings.database_url),
        "database_reachable": database_reachable,
        "redis_configured": bool(settings.redis_url),
        "redis_reachable": redis_reachable,
        "kubeconfig_configured": bool(settings.existing_kubeconfig),
        "webhook_signature_verification": bool(settings.pagerduty_webhook_secret),
        "webhook_subscription_bound": bool(settings.pagerduty_webhook_subscription_id),
        "operator_authentication": bool(settings.api_token),
    }
    database_error = _store_error(store)
    if database_error:
        body["database_error"] = database_error
    if credential_status["oauth_store_error"]:
        body["oauth_store_error"] = credential_status["oauth_store_error"]
    return body


def _live_readiness_body(settings: SentinelSettings, store: Any) -> dict[str, Any]:
    base = _readiness_body(settings, store)
    if not base["ready"]:
        return {
            **base,
            "base_ready": False,
            "provider_preflight_ready": False,
            "provider_preflight_skipped": False,
        }
    if _live_provider_preflight_skipped(settings):
        return {
            **base,
            "base_ready": True,
            "provider_preflight_ready": True,
            "provider_preflight_skipped": True,
        }
    report = run_live_connectivity_checks(settings, store=store)
    provider_body = report.model_dump(mode="json")
    return {
        "ready": report.ready,
        "base_ready": True,
        "provider_preflight_ready": report.ready,
        "provider_preflight_skipped": False,
        "missing_live_credentials": provider_body["missing_live_credentials"],
        "checks": provider_body["checks"],
        "base": base,
    }


def _credential_status(settings: SentinelSettings, store: Any) -> dict[str, Any]:
    try:
        missing = missing_live_credentials(settings, store)
        oauth_store_error = None
    except OAuthTokenStoreError as exc:
        missing = missing_live_credentials_without_oauth_store(settings)
        oauth_store_error = redact_sensitive_text(exc, max_length=500)
    return {
        "missing_live_credentials": missing,
        "token_sources": token_source_status(settings, store),
        "oauth_store_reachable": oauth_store_error is None,
        "oauth_store_error": oauth_store_error,
    }


def _build_app_store(settings: SentinelSettings):
    try:
        return _mark_managed_store(build_store(settings.database_url))
    except Exception as exc:
        return _UnavailableInvestigationStore(exc)


def _mark_managed_store(store: Any):
    try:
        setattr(store, _MANAGED_STORE_ATTR, True)
    except Exception:
        pass
    return store


@asynccontextmanager
async def _app_lifespan(app: FastAPI):
    try:
        yield
    finally:
        _close_resource(getattr(app.state, "store", None))


def _get_app_store(app: FastAPI, settings: SentinelSettings):
    store = app.state.store
    if not _managed_store_needs_refresh(store):
        return store
    refreshed = _build_app_store(settings)
    if refreshed is not store:
        _close_resource(store)
        app.state.store = refreshed
    return refreshed


def _managed_store_needs_refresh(store: Any) -> bool:
    if isinstance(store, _UnavailableInvestigationStore):
        return True
    if not bool(getattr(store, _MANAGED_STORE_ATTR, False)):
        return False
    if not _store_has_reachability_probe(store):
        return False
    return not _store_reachable(store)


def _store_has_reachability_probe(store: Any) -> bool:
    try:
        return callable(getattr(store, "ping", None)) or callable(getattr(store, "count_rows", None))
    except Exception:
        return False


def _require_operator_auth(settings: SentinelSettings, request: Request) -> None:
    if not settings.api_token:
        if settings.api_auth_required:
            raise HTTPException(status_code=503, detail="SENTINEL_API_TOKEN is required for operator endpoints")
        return
    authorization = request.headers.get("authorization") or ""
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token or not hmac.compare_digest(token, settings.api_token):
        raise HTTPException(status_code=401, detail="Invalid SENTINEL API token")


def _require_pagerduty_webhook_signature_config(settings: SentinelSettings) -> None:
    if settings.webhook_signature_required and not settings.pagerduty_webhook_secret:
        raise HTTPException(
            status_code=503,
            detail="PAGERDUTY_WEBHOOK_SECRET is required for PagerDuty webhooks",
        )


def _require_pagerduty_webhook_subscription(settings: SentinelSettings, request: Request) -> None:
    expected = settings.pagerduty_webhook_subscription_id
    if not expected:
        return
    observed = (request.headers.get("x-webhook-subscription") or "").strip()
    if not observed or not hmac.compare_digest(observed, expected.strip()):
        raise HTTPException(status_code=401, detail="Invalid PagerDuty webhook subscription")


_OAUTH_INSTALL_REQUIREMENTS = {
    "slack": (
        ("SLACK_CLIENT_ID", "slack_client_id"),
        ("SLACK_CLIENT_SECRET", "slack_client_secret"),
        ("SLACK_REDIRECT_URI", "slack_redirect_uri"),
    ),
    "github": (
        ("GITHUB_CLIENT_ID", "github_client_id"),
        ("GITHUB_CLIENT_SECRET", "github_client_secret"),
        ("GITHUB_REDIRECT_URI", "github_redirect_uri"),
    ),
    "datadog": (
        ("DD_CLIENT_ID", "datadog_client_id"),
        ("DD_CLIENT_SECRET", "datadog_client_secret"),
        ("DD_REDIRECT_URI", "datadog_redirect_uri"),
    ),
}


def _require_oauth_install_config(settings: SentinelSettings, provider: str) -> None:
    requirements = _OAUTH_INSTALL_REQUIREMENTS[provider]
    missing = [name for name, attr in requirements if not getattr(settings, attr)]
    if missing:
        raise HTTPException(
            status_code=503,
            detail=f"{provider} OAuth install is not configured; missing: {', '.join(missing)}",
        )


def _remember_oauth_state(store: Any, provider: str, state: str) -> None:
    try:
        remember = getattr(store, "remember_idempotency_key", None)
        if not callable(remember):
            raise HTTPException(status_code=503, detail="Investigation Store does not support OAuth state tracking")
        if not remember(_oauth_state_key(provider, state, "issued"), "oauth_state_issued", provider):
            raise HTTPException(status_code=409, detail="OAuth state was already issued")
    except HTTPException:
        raise
    except Exception as exc:
        raise _store_unavailable_exception(exc) from exc


def _remember_oauth_value(store: Any, provider: str, state: str, name: str, value: str) -> None:
    try:
        remember = getattr(store, "remember_idempotency_key", None)
        if not callable(remember):
            raise HTTPException(status_code=503, detail="Investigation Store does not support OAuth state tracking")
        if not remember(_oauth_state_key(provider, state, name), f"oauth_{name}", value):
            raise HTTPException(status_code=409, detail=f"OAuth {name} was already stored")
    except HTTPException:
        raise
    except Exception as exc:
        raise _store_unavailable_exception(exc) from exc


def _consume_issued_oauth_state(manager: OAuthManager, store: Any, provider: str, state: str) -> None:
    try:
        manager.verify_state(state, provider)
    except ToolExecutionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        lookup = getattr(store, "lookup_idempotency_key", None)
        remember = getattr(store, "remember_idempotency_key", None)
        if not callable(lookup) or not callable(remember):
            raise HTTPException(status_code=503, detail="Investigation Store does not support OAuth state tracking")
        if lookup(_oauth_state_key(provider, state, "issued")) != provider:
            raise HTTPException(status_code=400, detail="OAuth state was not issued by this SENTINEL receiver")
        if not remember(_oauth_state_key(provider, state, "used"), "oauth_state_used", provider):
            raise HTTPException(status_code=409, detail="OAuth state has already been used")
    except HTTPException:
        raise
    except Exception as exc:
        raise _store_unavailable_exception(exc) from exc


def _lookup_oauth_value(store: Any, provider: str, state: str, name: str) -> str:
    try:
        lookup = getattr(store, "lookup_idempotency_key", None)
        if not callable(lookup):
            raise HTTPException(status_code=503, detail="Investigation Store does not support OAuth state tracking")
        value = lookup(_oauth_state_key(provider, state, name))
        if not value:
            raise HTTPException(status_code=400, detail=f"OAuth {name} was not issued by this SENTINEL receiver")
        return value
    except HTTPException:
        raise
    except Exception as exc:
        raise _store_unavailable_exception(exc) from exc


def _oauth_state_key(provider: str, state: str, status: str) -> str:
    return f"oauth:{provider}:{state}:{status}"


def _oauth_callback_exception(exc: ToolExecutionError) -> HTTPException:
    status_code = 503 if exc.retryable else 502
    return HTTPException(status_code=status_code, detail=redact_sensitive_text(exc, max_length=500))


def _live_operation_exception(exc: ToolExecutionError) -> HTTPException:
    status_code = 503 if exc.retryable else 502
    return HTTPException(status_code=status_code, detail=redact_sensitive_text(exc, max_length=500))


def _store_unavailable_exception(exc: Exception) -> HTTPException:
    return HTTPException(status_code=503, detail=redact_sensitive_text(exc, max_length=500))


def _require_runtime_ready(
    settings: SentinelSettings,
    store: Any,
    *,
    operation: str,
    provider_preflight: bool = False,
) -> None:
    body = _readiness_body(settings, store)
    if body["ready"] and (not provider_preflight or _live_provider_preflight_skipped(settings)):
        return
    if body["ready"] and provider_preflight:
        report = run_live_connectivity_checks(settings, store=store)
        if report.ready:
            return
        raise HTTPException(
            status_code=503,
            detail={
                "message": f"SENTINEL live provider preflight failed for {operation}",
                "ready": False,
                "provider_preflight_ready": False,
                **report.model_dump(mode="json"),
            },
        )
    raise HTTPException(
        status_code=503,
        detail={
            "message": f"SENTINEL is not ready for {operation}",
            **body,
        },
    )


def _live_provider_preflight_skipped(settings: SentinelSettings) -> bool:
    return settings.runtime_environment != "production"


def _store_reachable(store: Any) -> bool:
    try:
        ping = getattr(store, "ping", None)
        if callable(ping):
            return bool(ping())
        count_rows = getattr(store, "count_rows", None)
        if callable(count_rows):
            count_rows("schema_migrations")
            return True
    except Exception:
        return False
    return False


def _store_error(store: Any) -> str | None:
    error = getattr(store, "error", None)
    return error if isinstance(error, str) and error else None


def _close_resource(resource: Any) -> None:
    close = getattr(resource, "close", None)
    if callable(close):
        close()


def _redis_reachable(settings: SentinelSettings) -> bool:
    if not settings.redis_url:
        return True
    backend = None
    try:
        backend = RedisRateLimitBackend(settings.redis_url)
        return backend.ping()
    except Exception:
        return False
    finally:
        if backend is not None:
            _close_resource(backend)


def _prometheus_metrics_body(settings: SentinelSettings) -> str:
    service = _prometheus_label(settings.default_service)
    pod = _prometheus_label(f"{settings.default_service}-demo")
    elapsed = max(1, int(time.monotonic() - _PROCESS_START_MONOTONIC) + 1)
    ok_requests = 10000 + elapsed * 90
    error_requests = 150 + elapsed * 4
    duration_bucket_100ms = 7000 + elapsed * 45
    duration_bucket_500ms = 9400 + elapsed * 82
    duration_bucket_1s = 9900 + elapsed * 89
    duration_bucket_inf = ok_requests + error_requests
    cpu_seconds = 500 + elapsed * 2
    memory_bytes = 185_000_000 + (elapsed % 20) * 1_000_000
    demo_metrics = "\n".join(
        [
            "# HELP sentinel_demo_info SENTINEL free-tier demo metric.",
            "# TYPE sentinel_demo_info gauge",
            f"sentinel_demo_info{{service={service}}} 1",
            "# HELP up Demo scrape health with service identity.",
            "# TYPE up gauge",
            f"up{{service={service}}} 1",
            "# HELP http_requests_total Demo HTTP requests by status.",
            "# TYPE http_requests_total counter",
            f"http_requests_total{{service={service},status=\"200\"}} {ok_requests}",
            f"http_requests_total{{service={service},status=\"500\"}} {error_requests}",
            "# HELP http_request_duration_seconds Demo HTTP request latency histogram.",
            "# TYPE http_request_duration_seconds histogram",
            f"http_request_duration_seconds_bucket{{service={service},le=\"0.1\"}} {duration_bucket_100ms}",
            f"http_request_duration_seconds_bucket{{service={service},le=\"0.5\"}} {duration_bucket_500ms}",
            f"http_request_duration_seconds_bucket{{service={service},le=\"1\"}} {duration_bucket_1s}",
            f"http_request_duration_seconds_bucket{{service={service},le=\"+Inf\"}} {duration_bucket_inf}",
            f"http_request_duration_seconds_sum{{service={service}}} {duration_bucket_inf * 0.23:.3f}",
            f"http_request_duration_seconds_count{{service={service}}} {duration_bucket_inf}",
            "# HELP queue_depth Demo queue depth.",
            "# TYPE queue_depth gauge",
            f"queue_depth{{service={service}}} {42 + elapsed % 7}",
            "# HELP network_tcp_rtt_seconds Demo inter-service RTT.",
            "# TYPE network_tcp_rtt_seconds gauge",
            f"network_tcp_rtt_seconds{{service={service}}} {0.028 + (elapsed % 5) * 0.001:.3f}",
            "# HELP synthetics_browser_uptime Demo uptime percentage.",
            "# TYPE synthetics_browser_uptime gauge",
            f"synthetics_browser_uptime{{service={service}}} 0.998",
            "# HELP container_cpu_usage_seconds_total Demo container CPU counter.",
            "# TYPE container_cpu_usage_seconds_total counter",
            f"container_cpu_usage_seconds_total{{pod={pod},container=\"app\"}} {cpu_seconds}",
            "# HELP container_memory_working_set_bytes Demo container memory working set.",
            "# TYPE container_memory_working_set_bytes gauge",
            f"container_memory_working_set_bytes{{pod={pod},container=\"app\"}} {memory_bytes}",
            "",
        ]
    )
    return demo_metrics + slow_query_metrics(settings.default_service)


def _prometheus_label(value: str) -> str:
    return json.dumps(str(value))


def _investigation_response(state: InvestigationState) -> dict[str, Any]:
    provider_proofs = _live_provider_success_counts(state)
    tool_proofs = _live_tool_success_counts(state)
    slack_notified = _has_live_tool_evidence(state, "comms.post_to_slack")
    discord_notified = slack_notified and state.artifacts.get("comms_provider") == "discord"
    approval_request_id = state.approval_request.id if state.approval_request else None
    approval_command = state.approval_command
    approval_notification_request_id = state.artifacts.get("approval_slack_notification_request_id")
    approval_slack_notified = (
        state.artifacts.get("approval_slack_notified") is True
        and approval_request_id is not None
        and approval_notification_request_id == approval_request_id
    )
    rollback_executed = _rollback_executed(state)
    rollback_attempted = any(
        call.tool_name == "infra.rollback_deployment"
        for call in state.tool_calls
    )
    return {
        "receiver_process": _receiver_process_identity(),
        "investigation_id": state.id,
        "incident_id": state.incident_id,
        "status": state.status.value,
        "current_state": state.current_state.value,
        "tool_calls": len(state.tool_calls),
        "tool_call_names": [call.tool_name for call in state.tool_calls],
        "tool_call_records": [call.model_dump(mode="json") for call in state.tool_calls],
        "state_transitions": [
            event.model_dump(mode="json")
            for event in state.audit_events
            if event.event_type == "state_transition"
        ],
        "plan_steps": [step.model_dump(mode="json") for step in state.plan_steps],
        "model_tool_plans": state.artifacts.get("model_tool_plans", []),
        "evidence_records": [
            {
                **evidence.model_dump(mode="json"),
                "claim": redact_sensitive_text(evidence.claim, max_length=1000),
            }
            for evidence in state.evidence
        ],
        "service_reports": [report.model_dump(mode="json") for report in state.service_reports],
        "live_provider_proofs": provider_proofs,
        "live_tool_proofs": tool_proofs,
        "slack_notified": slack_notified,
        "discord_notified": discord_notified,
        "notification_provider": state.artifacts.get("approval_notification_provider")
        or state.artifacts.get("comms_provider"),
        "approval_slack_notified": approval_slack_notified,
        "rollback_attempted": rollback_attempted,
        "rollback_executed": rollback_executed,
        "last_discord_message": state.artifacts.get("last_discord_message"),
        "webhook_source": state.artifacts.get("webhook_source"),
        "webhook_ingress": state.artifacts.get("webhook_ingress"),
        "generic_webhook_received": state.artifacts.get("generic_webhook_received") is True,
        "diagnosis": state.diagnosis.summary if state.diagnosis else None,
        "confidence": state.diagnosis.confidence.value if state.diagnosis else None,
        "recommendation": state.recommendation.command if state.recommendation else None,
        "approval_request_id": approval_request_id,
        "approval_slack_notification_request_id": (
            approval_notification_request_id
            if isinstance(approval_notification_request_id, str)
            else None
        ),
        "approval_approver_ids": state.approval_request.approver_ids if state.approval_request else [],
        "approval_command_received": approval_command is not None,
        "approval_command_request_id": approval_command.request_id if approval_command else None,
        "approval_command_approver_id": approval_command.approver_id if approval_command else None,
        "approval_command_decision": approval_command.decision if approval_command else None,
        "approval_expires_at": state.approval_request.expires_at.isoformat() if state.approval_request else None,
        "remediation_result": state.remediation_result.model_dump(mode="json") if state.remediation_result else None,
        "evidence_gaps": _evidence_gap_summary(state),
        "failed_tool_calls": _failed_tool_call_summary(state),
        "audit": _audit_summary(state),
        "context_summary": state.context_summary,
    }


def _receiver_process_identity() -> dict[str, Any]:
    return {
        "pid": os.getpid(),
        "started_at": _PROCESS_STARTED_AT.isoformat(),
        "uptime_seconds": round(time.monotonic() - _PROCESS_START_MONOTONIC, 3),
    }


def _audit_summary(state: InvestigationState) -> dict[str, Any]:
    events = [
        {
            "event_type": event.event_type,
            "timestamp": event.timestamp.isoformat(),
        }
        for event in state.audit_events
    ]
    latest = events[-1] if events else None
    return {
        "event_count": len(events),
        "latest_event": latest,
        "events": events,
    }


def _evidence_gap_summary(state: InvestigationState) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for evidence in state.evidence:
        if not _is_evidence_gap(evidence):
            continue
        gaps.append(
            {
                "source": evidence.source,
                "affected_service": evidence.affected_service,
                "time_window": evidence.time_window,
                "claim": redact_sensitive_text(evidence.claim, max_length=500),
                "provenance": evidence.provenance,
            }
        )
    return gaps


def _failed_tool_call_summary(state: InvestigationState) -> list[dict[str, Any]]:
    failed: list[dict[str, Any]] = []
    for call in state.tool_calls:
        if call.success:
            continue
        failed.append(
            {
                "tool_name": call.tool_name,
                "state": call.state.value,
                "error_kind": call.error_kind,
                "error_message": (
                    redact_sensitive_text(call.error_message, max_length=500)
                    if call.error_message
                    else None
                ),
                "subagent_context_id": call.subagent_context_id,
            }
        )
    return failed


def _is_evidence_gap(evidence) -> bool:
    return evidence.claim.startswith("evidence gap:") or evidence.provenance.endswith(":failure")


def _live_provider_success_counts(state: InvestigationState) -> dict[str, int]:
    counts = {
        provider: 0
        for provider in (
            "prometheus",
            "loki",
            "datadog",
            "github",
            "generic_webhook",
            "pagerduty",
            "discord",
            "slack",
            "kubernetes",
        )
    }
    for evidence in state.evidence:
        provider = _live_provider_for_evidence(state, evidence.source, evidence.provenance)
        if provider:
            counts.setdefault(provider, 0)
            counts[provider] += 1
    return counts


def _live_tool_success_counts(state: InvestigationState) -> dict[str, int]:
    counts: dict[str, int] = {}
    for evidence in state.evidence:
        if evidence.provenance != f"live::{evidence.source}":
            continue
        counts[evidence.source] = counts.get(evidence.source, 0) + 1
    return dict(sorted(counts.items()))


def _has_live_tool_evidence(state: InvestigationState, tool_name: str) -> bool:
    return any(
        evidence.source == tool_name and evidence.provenance == f"live::{tool_name}"
        for evidence in state.evidence
    )


def _rollback_executed(state: InvestigationState) -> bool:
    if state.scenario_name == "live":
        return _has_live_tool_evidence(state, "infra.rollback_deployment")
    return any(
        call.tool_name == "infra.rollback_deployment" and call.success
        for call in state.tool_calls
    )


def _live_provider_for_evidence(state: InvestigationState, source: str, provenance: str) -> str | None:
    if provenance != f"live::{source}":
        return None
    return _live_provider_for_tool(state, source)


def _live_provider_for_tool(state: InvestigationState, tool_name: str) -> str | None:
    providers = state.artifacts.get("live_tool_providers")
    if isinstance(providers, dict):
        provider = providers.get(tool_name)
        if isinstance(provider, str) and provider.strip():
            return provider.strip()
    if tool_name == "observe.check_pod_health":
        return "kubernetes"
    if tool_name in {
        "observe.fetch_service_logs",
        "observe.get_distributed_traces",
        "observe.fetch_apm_data",
        "observe.check_db_slow_queries",
        "observe.fetch_cdn_logs",
    }:
        return "loki"
    if tool_name in {
        "observe.query_metrics_range",
        "observe.get_error_rate_timeseries",
        "observe.read_queue_depth",
        "observe.get_network_latency",
        "observe.check_uptime_history",
        "observe.get_memory_cpu_usage",
        "observe.fetch_alerting_rules",
        "observe.read_dashboard_snapshot",
    }:
        return "prometheus"
    if tool_name.startswith("observe."):
        return "datadog"
    if tool_name.startswith("repo."):
        return "github"
    if tool_name == "infra.add_database_index":
        return "sqlite"
    if tool_name.startswith("infra."):
        return "kubernetes"
    if tool_name in {"comms.page_oncall_engineer", "comms.escalate_incident", "comms.close_incident"}:
        return "pagerduty"
    if tool_name in {"comms.create_jira_ticket", "comms.update_runbook"}:
        return "github"
    if tool_name.startswith("comms."):
        return "slack"
    return None


def _run_live_investigation(
    settings: SentinelSettings,
    payload: dict[str, Any],
    incident_id: str,
    services: list[str] | None = None,
    investigation_id: str | None = None,
    store=None,
) -> InvestigationState:
    store = store or build_store(settings.database_url)
    orchestrator, clients = _build_live_orchestrator(settings, store)
    try:
        return orchestrator.run_live_incident(
            incident_id=incident_id,
            affected_services=services or _extract_services(payload, settings),
            webhook_payload=payload,
            auto_approve=False,
            investigation_id=investigation_id,
        )
    finally:
        clients.close()


def _resume_live_investigation_with_approval(
    settings: SentinelSettings,
    investigation_id: str,
    approval_command: ApprovalCommand,
    store=None,
) -> InvestigationState:
    store = store or build_store(settings.database_url)
    orchestrator, clients = _build_live_orchestrator(settings, store)
    try:
        return orchestrator.resume_with_approval(investigation_id, approval_command)
    finally:
        clients.close()


def _build_live_orchestrator(settings: SentinelSettings, store) -> tuple[SentinelOrchestrator, LiveProviderClients]:
    settings = resolve_settings(settings, store, refresh_expired_datadog=True)
    clients = LiveProviderClients.from_settings(settings)
    registry = LiveToolFactory(clients).build_registry()
    orchestrator = SentinelOrchestrator(store=store)
    orchestrator.registry = registry
    orchestrator.executor = ToolExecutor(registry, store)
    from sentinel.subagents import SubagentLauncher

    orchestrator.subagents = SubagentLauncher(registry, orchestrator.executor, store)
    orchestrator.subagents.bind_spawn_tool()
    return orchestrator, clients


def _run_live_investigation_safely(
    settings: SentinelSettings,
    store,
    payload: dict[str, Any],
    incident_id: str,
    services: list[str],
    investigation_id: str,
) -> None:
    try:
        _run_live_investigation(
            settings,
            payload,
            incident_id,
            services,
            investigation_id,
            store,
        )
    except Exception as exc:
        try:
            state = store.load_state(investigation_id)
        except KeyError:
            state = InvestigationState(
                id=investigation_id,
                incident_id=incident_id,
                scenario_name="live",
                affected_services=services,
                service_priority=services,
            )
        state.status = InvestigationStatus.FAILED
        safe_error = redact_sensitive_text(exc, max_length=500)
        state.context_summary = f"Live investigation failed: {safe_error}"
        event = AuditEvent(
            investigation_id=state.id,
            event_type="live_investigation_failed",
            payload={"error": safe_error},
        )
        state.audit_events.append(event)
        store.append_audit_event(event)
        store.save_state(state)


def _create_received_investigation(
    store,
    payload: dict[str, Any],
    incident_id: str,
    services: list[str],
    *,
    source: str = "pagerduty",
) -> tuple[InvestigationState, bool]:
    webhook_key = _webhook_idempotency_key(source, incident_id)
    investigation_id = f"inv-{uuid4().hex[:10]}"
    if not store.remember_idempotency_key(webhook_key, "webhook", investigation_id):
        existing_id = store.lookup_idempotency_key(webhook_key)
        if existing_id:
            try:
                return store.load_state(existing_id), False
            except KeyError:
                return (
                    InvestigationState(
                        id=existing_id,
                        incident_id=incident_id,
                        scenario_name="live",
                        affected_services=services,
                        service_priority=services,
                        context_summary=f"Duplicate {source} webhook received while original Investigation is being created.",
                    ),
                    False,
                )
        raise RuntimeError(f"Duplicate {source} webhook for {incident_id} could not be resolved")

    state = InvestigationState(
        id=investigation_id,
        incident_id=incident_id,
        scenario_name="live",
        affected_services=services,
        service_priority=services,
        context_summary=f"{source} webhook received; live investigation queued.",
    )
    state.artifacts["webhook_source"] = source
    state.artifacts["webhook_ingress"] = {
        "source": source,
        "incident_id": incident_id,
        "affected_services": services,
        "payload_keys": sorted(payload.keys()),
    }
    if source == "generic_webhook":
        state.artifacts["generic_webhook_received"] = True
    event = AuditEvent(
        investigation_id=state.id,
        event_type=_webhook_accepted_event_type(source),
        payload=state.artifacts["webhook_ingress"],
    )
    state.audit_events.append(event)
    store.append_audit_event(event)
    store.save_state(state)
    return state, True


def _webhook_accepted_event_type(source: str) -> str:
    return f"{source}_accepted" if source.endswith("_webhook") else f"{source}_webhook_accepted"


def _webhook_idempotency_key(source: str, incident_id: str) -> str:
    return f"{source}:{incident_id}:webhook"


def _extract_incident_id(payload: dict[str, Any]) -> str | None:
    return _extract_incident_id_from_items(_pagerduty_payload_items(payload))


def _extract_incident_id_from_items(items: list[dict[str, Any]]) -> str | None:
    ids = _extract_incident_ids_from_items(items)
    return ids[0] if ids else None


def _extract_incident_ids_from_items(items: list[dict[str, Any]]) -> list[str]:
    incident_ids: list[str] = []
    for item in items:
        for incident in _pagerduty_incident_candidates(item):
            incident_id = _text(incident.get("id"))
            if incident_id and incident_id not in incident_ids:
                incident_ids.append(incident_id)
        for candidate in (item.get("incident_id"), item.get("id") if "event" not in item else None):
            incident_id = _text(candidate)
            if incident_id and incident_id not in incident_ids:
                incident_ids.append(incident_id)
    return incident_ids


def _is_pagerduty_test_event(payload: dict[str, Any]) -> bool:
    for item in _pagerduty_payload_items(payload):
        event_type = _pagerduty_event_type(item)
        if event_type == "pagey.ping":
            return True
        data = _pagerduty_event_data(item)
        if _text(data.get("type")) == "ping" and _text(data.get("message")):
            return True
    return False


def _actionable_pagerduty_payload_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    actionable: list[dict[str, Any]] = []
    for item in _pagerduty_payload_items(payload):
        event_type = _pagerduty_event_type(item)
        if event_type:
            if event_type == "incident.triggered":
                actionable.append(item)
            continue
        if _pagerduty_incident_candidates(item):
            actionable.append(item)
    return actionable


def _extract_services(payload: dict[str, Any], settings: SentinelSettings) -> list[str]:
    services = _extract_services_from_items(_pagerduty_payload_items(payload), settings)
    return services or [settings.default_service]


def _extract_services_from_items(items: list[dict[str, Any]], settings: SentinelSettings) -> list[str]:
    services: list[str] = []
    for item in items:
        for service in _pagerduty_service_candidates(item):
            label = _resolve_pagerduty_service_label(service, settings)
            if label and label not in services:
                services.append(label)
    return services


def _extract_webhook_services(items: list[dict[str, Any]], settings: SentinelSettings) -> list[str]:
    services = _extract_services_from_items(items, settings)
    if not services:
        raise HTTPException(
            status_code=400,
            detail="PagerDuty webhook did not include a usable incident service",
        )
    return services


def _extract_live_run_services(payload: dict[str, Any], settings: SentinelSettings) -> list[str]:
    explicit = False
    services: list[str] = []
    for key in ("affected_services", "services"):
        if key not in payload:
            continue
        explicit = True
        values = payload.get(key)
        if not isinstance(values, list) or not values:
            raise HTTPException(status_code=400, detail=f"{key} must be a non-empty list")
        for value in values:
            _append_service_candidate(services, value, settings)
    for key in ("affected_service", "service"):
        if key not in payload:
            continue
        explicit = True
        _append_service_candidate(services, payload.get(key), settings)
    if explicit:
        if not services:
            raise HTTPException(status_code=400, detail="live run payload did not include a usable service")
        return services
    return _extract_services(payload, settings)


def _extract_generic_incident_id(payload: dict[str, Any]) -> str | None:
    for key in ("incident_id", "alert_id", "id", "fingerprint"):
        value = _text(payload.get(key))
        if value:
            return value
    for alert in _generic_alert_items(payload):
        for key in ("incident_id", "alert_id", "id", "fingerprint"):
            value = _text(alert.get(key))
            if value:
                return value
    for key in ("groupKey", "group_key"):
        value = _text(payload.get(key))
        if value:
            return value
    return None


def _extract_generic_services(payload: dict[str, Any], settings: SentinelSettings) -> list[str]:
    services: list[str] = []
    for key in ("affected_services", "services"):
        values = payload.get(key)
        if isinstance(values, list):
            for value in values:
                _append_service_candidate(services, value, settings)
    for key in ("affected_service", "service", "service_name"):
        _append_service_candidate(services, payload.get(key), settings)
    for labels_key in ("labels", "commonLabels", "common_labels", "groupLabels", "group_labels"):
        _append_generic_label_services(services, payload.get(labels_key), settings)
    for alert in _generic_alert_items(payload):
        for key in ("affected_service", "service", "service_name"):
            _append_service_candidate(services, alert.get(key), settings)
        _append_generic_label_services(services, alert.get("labels"), settings)
    if not services:
        services.append(settings.default_service)
    return services


def _generic_alert_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    alert = payload.get("alert")
    if isinstance(alert, dict):
        items.append(alert)
    alerts = payload.get("alerts")
    if isinstance(alerts, list):
        items.extend(item for item in alerts if isinstance(item, dict))
    return items


def _append_generic_label_services(services: list[str], labels: Any, settings: SentinelSettings) -> None:
    if not isinstance(labels, dict):
        return
    for key in ("service", "service_name", "app", "job"):
        _append_service_candidate(services, labels.get(key), settings)


def _append_service_candidate(services: list[str], value: Any, settings: SentinelSettings) -> None:
    label = _resolve_pagerduty_service_label(value, settings)
    if label and label not in services:
        services.append(label)


def _pagerduty_payload_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("messages", "events"):
        values = payload.get(key)
        if not isinstance(values, list):
            continue
        items = [item for item in values if isinstance(item, dict)]
        if items:
            return items
    return [payload]


def _pagerduty_event(item: dict[str, Any]) -> dict[str, Any]:
    event = item.get("event")
    if isinstance(event, dict):
        return event
    if isinstance(item.get("data"), dict) and (
        "event_type" in item or "resource_type" in item
    ):
        return item
    return {}


def _pagerduty_event_data(item: dict[str, Any]) -> dict[str, Any]:
    event = _pagerduty_event(item)
    data = event.get("data")
    if isinstance(data, dict):
        return data
    data = item.get("data")
    return data if isinstance(data, dict) else {}


def _pagerduty_event_type(item: dict[str, Any]) -> str:
    return _text(_pagerduty_event(item).get("event_type")) or ""


def _pagerduty_incident_candidates(item: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    data = _pagerduty_event_data(item)
    for candidate in (item.get("incident"), data.get("incident")):
        if isinstance(candidate, dict):
            candidates.append(candidate)
    if _is_incident_object(data, item):
        candidates.append(data)
    if not _pagerduty_event(item) and _is_incident_object(item, item):
        candidates.append(item)
    return candidates


def _is_incident_object(value: dict[str, Any], item: dict[str, Any]) -> bool:
    value_type = _text(value.get("type"))
    if value_type in {"incident", "incident_reference"}:
        return True
    event_type = _pagerduty_event_type(item)
    if not event_type.startswith("incident."):
        return False
    return any(
        key in value
        for key in ("service", "status", "urgency", "title", "incident_number", "escalation_policy")
    )


def _pagerduty_service_candidates(item: dict[str, Any]) -> list[Any]:
    candidates: list[Any] = []
    for incident in _pagerduty_incident_candidates(item):
        if "service" in incident:
            candidates.append(incident.get("service"))
    data = _pagerduty_event_data(item)
    if _pagerduty_event_type(item).startswith("incident.") and "service" in data:
        candidates.append(data.get("service"))
    if "service" in item:
        candidates.append(item.get("service"))
    return candidates


def _resolve_pagerduty_service_label(service: Any, settings: SentinelSettings) -> str | None:
    labels = _pagerduty_service_labels(service)
    for label in labels:
        resolved = settings.resolve_service_alias(label)
        if resolved != label:
            return resolved
    return settings.resolve_service_alias(labels[0]) if labels else None


def _pagerduty_service_label(service: Any) -> str | None:
    labels = _pagerduty_service_labels(service)
    return labels[0] if labels else None


def _pagerduty_service_labels(service: Any) -> list[str]:
    if isinstance(service, str):
        label = service.strip()
        return [label] if label else []
    if not isinstance(service, dict):
        return []
    labels: list[str] = []
    for key in ("summary", "name", "id"):
        label = _text(service.get(key))
        if label and label not in labels:
            labels.append(label)
    return labels


def _text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


app = create_app()
