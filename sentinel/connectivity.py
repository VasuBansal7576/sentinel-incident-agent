from __future__ import annotations

import re
import time
from typing import Any, Callable

from pydantic import BaseModel, Field

from sentinel.config import SentinelSettings
from sentinel.credentials import (
    OAuthTokenStoreError,
    missing_live_credentials,
    missing_live_credentials_without_oauth_store,
    resolve_settings,
)
from sentinel.errors import ToolExecutionError, redact_sensitive_text
from sentinel.live_clients import (
    LiveProviderClients,
    datadog_point_has_finite_numeric_value,
    prometheus_result_has_finite_numeric_value,
)
from sentinel.postgres_store import build_store
from sentinel.rate_limiters import RedisRateLimitBackend


class ConnectivityCheck(BaseModel):
    name: str
    provider: str
    passed: bool
    duration_ms: float
    detail: str
    sample: dict[str, Any] = Field(default_factory=dict)
    error_kind: str | None = None
    retryable: bool | None = None


class ConnectivityReport(BaseModel):
    ready: bool
    missing_live_credentials: list[str]
    checks: list[ConnectivityCheck]


def run_live_connectivity_checks(
    settings: SentinelSettings | None = None,
    *,
    store=None,
) -> ConnectivityReport:
    if settings is None:
        try:
            settings = SentinelSettings.from_env()
        except Exception as exc:
            return ConnectivityReport(
                ready=False,
                missing_live_credentials=[],
                checks=[_failed_check("sentinel.config", "sentinel", exc)],
            )
    owned_store = None
    state_store_check: ConnectivityCheck | None = None
    if store is None:
        if settings.production_infrastructure_required and not settings.database_url:
            state_store_check = _missing_required_infra_check(
                "sentinel.state_store",
                "DATABASE_URL",
                "PostgreSQL Investigation Store",
            )
        else:
            try:
                store = build_store(settings.database_url)
                owned_store = store
            except Exception as exc:
                return ConnectivityReport(
                    ready=False,
                    missing_live_credentials=missing_live_credentials(settings, None),
                    checks=[_failed_check("sentinel.state_store", "sentinel", exc)],
                )

    try:
        state_store_check = state_store_check or _state_store_check(settings, store)
        if not state_store_check.passed:
            checks = [state_store_check]
            if settings.production_infrastructure_required and not settings.redis_url:
                checks.append(_redis_check(settings))
            return ConnectivityReport(
                ready=False,
                missing_live_credentials=_missing_live_credentials_for_report(settings, store),
                checks=checks,
            )
        redis_check = _redis_check(settings)
        if not redis_check.passed:
            return ConnectivityReport(
                ready=False,
                missing_live_credentials=_missing_live_credentials_for_report(settings, store),
                checks=[state_store_check, redis_check],
            )
        early_missing = _oauth_scope_missing_for_report(settings, store)
        if early_missing:
            return ConnectivityReport(
                ready=False,
                missing_live_credentials=early_missing,
                checks=[state_store_check, redis_check],
            )

        try:
            resolved = resolve_settings(settings, store, refresh_expired_datadog=True)
        except OAuthTokenStoreError as exc:
            return ConnectivityReport(
                ready=False,
                missing_live_credentials=missing_live_credentials_without_oauth_store(settings),
                checks=[
                    state_store_check,
                    redis_check,
                    _failed_check("sentinel.oauth_store", "sentinel", exc),
                ],
            )
        except Exception as exc:
            return ConnectivityReport(
                ready=False,
                missing_live_credentials=[],
                checks=[
                    state_store_check,
                    redis_check,
                    _failed_check("datadog.oauth_refresh", "datadog", exc),
                ],
            )
        missing = missing_live_credentials(resolved, store)
        if missing:
            return ConnectivityReport(
                ready=False,
                missing_live_credentials=missing,
                checks=[state_store_check, redis_check],
            )

        clients = LiveProviderClients.from_settings(resolved)
        try:
            return _run_provider_checks(resolved, clients, infrastructure_checks=[state_store_check, redis_check])
        finally:
            clients.close()
    finally:
        _close_resource(owned_store)


def _run_provider_checks(
    resolved: SentinelSettings,
    clients: LiveProviderClients,
    *,
    infrastructure_checks: list[ConnectivityCheck] | None = None,
) -> ConnectivityReport:
    service = resolved.default_service
    checks = list(infrastructure_checks or [])

    if getattr(clients, "prometheus", None) is not None and getattr(clients, "loki", None) is not None:
        checks.extend([
            _check(
                "loki.logs",
                "loki",
                lambda: clients.loki.query_range(f'{{service="{service}"}}', limit=1),
                _requires_non_empty_list_field("events"),
            ),
            _check(
                "prometheus.metrics",
                "prometheus",
                lambda: clients.prometheus.query_range(
                    f'sentinel_demo_info{{service="{_prometheus_label_value(service)}"}}'
                ),
                _requires_prometheus_metric_datapoint,
            ),
            _check(
                "loki.apm_traces",
                "loki",
                lambda: clients.loki.query_range(f'{{service="{service}"}} |= "trace"', limit=1),
                _requires_non_empty_list_field("events"),
            ),
            _check(
                "prometheus.alerting_rules",
                "prometheus",
                clients.prometheus.alerting_rules,
                _requires_non_empty_list_field("groups"),
            ),
        ])
    else:
        checks.extend([
            _check(
                "datadog.logs",
                "datadog",
                lambda: clients.datadog.search_logs(
                    f"service:{service}",
                    limit=1,
                    max_pages=1,
                    allow_truncated=True,
                ),
                _requires_non_empty_list_field("events"),
            ),
            _check(
                "datadog.metrics",
                "datadog",
                lambda: clients.datadog.query_metric("avg:system.cpu.user{*}"),
                _requires_datadog_metric_datapoint,
            ),
            _check(
                "datadog.apm_spans",
                "datadog",
                lambda: clients.datadog.search_spans(
                    f"service:{service}",
                    limit=1,
                    max_pages=1,
                    allow_truncated=True,
                ),
                _requires_non_empty_list_field("spans"),
            ),
        ])

    checks.extend([
        _check(
            "github.commits",
            "github",
            lambda: {"items": clients.github.commits(per_page=1, max_pages=1, allow_truncated=True)},
            _requires_non_empty_list_field("items"),
        ),
        _check(
            "github.pull_requests",
            "github",
            lambda: {"items": clients.github.pull_requests(state="all", per_page=1, max_pages=1, allow_truncated=True)},
            _requires_non_empty_list_field("items"),
        ),
        _check(
            "github.deployments",
            "github",
            lambda: {"items": clients.github.deployments(per_page=1, max_pages=1, allow_truncated=True)},
            _requires_non_empty_list_field("items"),
        ),
    ])

    if bool(getattr(clients.pagerduty, "enabled", True)):
        checks.extend([
            _check(
                "pagerduty.incidents",
                "pagerduty",
                lambda: {"items": clients.pagerduty.list_incidents(max_pages=1, allow_truncated=True)},
                _requires_non_empty_list_field("items"),
            ),
            _check(
                "pagerduty.on_calls",
                "pagerduty",
                lambda: {"items": clients.pagerduty.on_calls(max_pages=1, allow_truncated=True)},
                _requires_non_empty_list_field("items"),
            ),
        ])
    else:
        checks.append(
            _check(
                "generic_webhook.approver",
                "generic_webhook",
                lambda: clients.generic_alerts.on_call_context("connectivity-check"),
                _requires_non_empty_list_field("oncalls"),
            )
        )

    if bool(getattr(clients.slack, "enabled", True)):
        checks.extend([
            _check("slack.auth", "slack", clients.slack.oauth_test, _requires_true_field("ok")),
            _check(
                "slack.default_channel",
                "slack",
                clients.slack.channel_info,
                _requires_object_field("channel"),
            ),
            _check(
                "slack.channels",
                "slack",
                lambda: {"items": clients.slack.list_channels(max_pages=1, allow_truncated=True)},
                _requires_non_empty_list_field("items"),
            ),
        ])
    else:
        checks.append(
            _check(
                "discord.webhook",
                "discord",
                lambda: clients.discord.post_to_discord("SENTINEL connectivity check"),
                _requires_true_field("ok"),
            )
        )

    checks.extend([
        _check(
            "kubernetes.pods",
            "kubernetes",
            lambda: clients.kubernetes.list_pods(service),
            _requires_non_empty_list_field("items"),
        ),
        _check("kubernetes.deployments", "kubernetes", clients.kubernetes.list_deployments, _requires_non_empty_list_field("items")),
        _check("kubernetes.rollout_revisions", "kubernetes", lambda: clients.kubernetes.rollout_revisions(service), _requires_executable_rollout_target),
    ])

    return ConnectivityReport(
        ready=all(check.passed for check in checks),
        missing_live_credentials=[],
        checks=checks,
    )


def _state_store_check(settings: SentinelSettings, store: Any) -> ConnectivityCheck:
    if settings.production_infrastructure_required and not settings.database_url:
        return _missing_required_infra_check(
            "sentinel.state_store",
            "DATABASE_URL",
            "PostgreSQL Investigation Store",
        )
    return _check(
        "sentinel.state_store",
        "sentinel",
        lambda: {"ok": _state_store_ping(store)},
        _requires_true_field("ok"),
    )


def _redis_check(settings: SentinelSettings) -> ConnectivityCheck:
    if not settings.redis_url:
        if settings.production_infrastructure_required:
            return _missing_required_infra_check(
                "sentinel.redis",
                "REDIS_URL",
                "Redis rate-limit backend",
            )
        return ConnectivityCheck(
            name="sentinel.redis",
            provider="sentinel",
            passed=True,
            duration_ms=0.0,
            detail="not configured",
            sample={"configured": False},
        )
    backend = None
    try:
        backend = RedisRateLimitBackend(settings.redis_url)
        return _check(
            "sentinel.redis",
            "sentinel",
            lambda: {"ok": backend.ping(), "configured": True},
            _requires_true_field("ok"),
        )
    finally:
        _close_resource(backend)


def _missing_required_infra_check(name: str, env_var: str, component: str) -> ConnectivityCheck:
    return ConnectivityCheck(
        name=name,
        provider="sentinel",
        passed=False,
        duration_ms=0.0,
        detail=f"{env_var} is required for production {component}",
        sample={"configured": False},
    )


def _state_store_ping(store: Any) -> bool:
    ping = getattr(store, "ping", None)
    if callable(ping):
        if ping():
            return True
        error = getattr(store, "error", None)
        if isinstance(error, str) and error:
            raise RuntimeError(error)
        raise RuntimeError("state store ping returned false")
    count_rows = getattr(store, "count_rows", None)
    if callable(count_rows):
        count_rows("schema_migrations")
        return True
    raise RuntimeError("state store does not expose a readiness probe")


def _check(
    name: str,
    provider: str,
    fn: Callable[[], dict[str, Any]],
    validator: Callable[[dict[str, Any]], None],
) -> ConnectivityCheck:
    started = time.perf_counter()
    try:
        data = fn()
        validator(data)
        return ConnectivityCheck(
            name=name,
            provider=provider,
            passed=True,
            duration_ms=(time.perf_counter() - started) * 1000,
            detail="ok",
            sample=_sample(data),
        )
    except Exception as exc:
        return ConnectivityCheck(
            name=name,
            provider=provider,
            passed=False,
            duration_ms=(time.perf_counter() - started) * 1000,
            detail=redact_sensitive_text(exc, max_length=500),
            sample={},
            **_error_metadata(exc),
        )


def _failed_check(name: str, provider: str, exc: Exception) -> ConnectivityCheck:
    return ConnectivityCheck(
        name=name,
        provider=provider,
        passed=False,
        duration_ms=0.0,
        detail=redact_sensitive_text(exc, max_length=500),
        sample={},
        **_error_metadata(exc),
    )


def _error_metadata(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, ToolExecutionError):
        return {"error_kind": exc.kind.value, "retryable": exc.retryable}
    return {}


def _missing_live_credentials_for_report(
    settings: SentinelSettings,
    store: Any | None,
) -> list[str]:
    try:
        return missing_live_credentials(settings, store)
    except OAuthTokenStoreError:
        return missing_live_credentials_without_oauth_store(settings)


def _oauth_scope_missing_for_report(
    settings: SentinelSettings,
    store: Any | None,
) -> list[str]:
    try:
        missing = missing_live_credentials(settings, store)
    except OAuthTokenStoreError:
        return []
    return [item for item in missing if "_OAUTH_TOKEN_SCOPE:" in item]


def _close_resource(resource: Any | None) -> None:
    close = getattr(resource, "close", None)
    if callable(close):
        close()


def _requires_list_field(field: str) -> Callable[[dict[str, Any]], None]:
    def validate(data: dict[str, Any]) -> None:
        if not isinstance(data, dict):
            raise ValueError("response must be an object")
        if not isinstance(data.get(field), list):
            raise ValueError(f"response field '{field}' must be a list")

    return validate


def _requires_non_empty_list_field(field: str) -> Callable[[dict[str, Any]], None]:
    def validate(data: dict[str, Any]) -> None:
        _requires_list_field(field)(data)
        if not data[field]:
            raise ValueError(f"response field '{field}' must contain at least one provider record")

    return validate


def _requires_executable_rollout_target(data: dict[str, Any]) -> None:
    _requires_non_empty_list_field("revisions")(data)
    previous_revision = data.get("previous_revision")
    if (
        not isinstance(previous_revision, str)
        or not re.fullmatch(r"revision:[1-9]\d*", previous_revision.strip())
    ):
        raise ValueError(
            "response field 'previous_revision' must contain an executable revision:<positive integer> rollback target"
        )


def _requires_datadog_metric_datapoint(data: dict[str, Any]) -> None:
    _requires_non_empty_list_field("series")(data)
    for series in data["series"]:
        if not isinstance(series, dict):
            continue
        pointlist = series.get("pointlist")
        if not isinstance(pointlist, list):
            continue
        if any(datadog_point_has_finite_numeric_value(point) for point in pointlist):
            return
    raise ValueError("response field 'series' must contain at least one finite numeric Datadog datapoint")


def _requires_prometheus_metric_datapoint(data: dict[str, Any]) -> None:
    _requires_non_empty_list_field("result")(data)
    for item in data["result"]:
        if prometheus_result_has_finite_numeric_value(item):
            return
    raise ValueError("response field 'result' must contain at least one finite numeric Prometheus datapoint")


def _prometheus_label_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _requires_object_field(field: str) -> Callable[[dict[str, Any]], None]:
    def validate(data: dict[str, Any]) -> None:
        if not isinstance(data, dict):
            raise ValueError("response must be an object")
        if not isinstance(data.get(field), dict):
            raise ValueError(f"response field '{field}' must be an object")

    return validate


def _requires_true_field(field: str) -> Callable[[dict[str, Any]], None]:
    def validate(data: dict[str, Any]) -> None:
        if not isinstance(data, dict):
            raise ValueError("response must be an object")
        if data.get(field) is not True:
            raise ValueError(f"response field '{field}' must be true")

    return validate


def _sample(data: dict[str, Any]) -> dict[str, Any]:
    sample: dict[str, Any] = {}
    for key, value in data.items():
        if key.startswith("_") or "token" in key.lower() or "authorization" in key.lower():
            continue
        if isinstance(value, list):
            sample[key] = {"count": len(value)}
        elif isinstance(value, dict):
            sample[key] = {"keys": sorted(str(item) for item in value.keys())[:10]}
        elif isinstance(value, (str, int, float, bool)) or value is None:
            sample[key] = value
        else:
            sample[key] = type(value).__name__
    return sample
