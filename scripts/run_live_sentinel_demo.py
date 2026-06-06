from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.config import SentinelSettings
from sentinel.connectivity import run_live_connectivity_checks
from sentinel.errors import redact_sensitive_text
from sentinel.live_receiver_preflight import (
    normalize_receiver_base_url,
    response_body as _body,
    run_http_receiver_check,
)
from sentinel.models import InvestigationStatus, StateName
from sentinel.oauth import pagerduty_signature_header
from sentinel.webapp import create_app


PROPOSAL_STATUSES = {
    InvestigationStatus.WAITING_FOR_APPROVAL.value,
}
TERMINAL_STATUSES = {
    InvestigationStatus.WAITING_FOR_APPROVAL.value,
    InvestigationStatus.COMPLETED.value,
    InvestigationStatus.FAILED.value,
    InvestigationStatus.INSUFFICIENT_CONFIDENCE.value,
}
MIN_LIVE_TOOL_CALLS = 20
REQUIRED_LIVE_PROVIDERS = ("datadog", "github", "pagerduty", "slack", "kubernetes")
REQUIRED_PROPOSAL_TOOL_PROOFS = (
    "observe.fetch_service_logs",
    "observe.get_error_rate_timeseries",
    "observe.fetch_apm_data",
    "repo.get_deploy_history",
    "repo.get_rollback_targets",
    "observe.check_pod_health",
    "comms.page_oncall_engineer",
    "comms.post_to_slack",
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the live SENTINEL demo through the FastAPI PagerDuty webhook receiver."
    )
    parser.add_argument("incident_id", nargs="?", default="LIVE-MANUAL-INCIDENT")
    parser.add_argument("--service", default=None)
    parser.add_argument(
        "--base-url",
        default=os.getenv("SENTINEL_BASE_URL"),
        help="Deployed SENTINEL receiver URL. If omitted, runs the FastAPI app in-process.",
    )
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument(
        "--http-timeout-seconds",
        type=float,
        default=None,
        help="Per-request HTTP timeout for deployed receiver mode. Defaults to min(20, --timeout-seconds).",
    )
    parser.add_argument("--poll-interval", type=float, default=5.0)
    parser.add_argument(
        "--api-token",
        default=os.getenv("SENTINEL_API_TOKEN"),
        help="Bearer token for SENTINEL operator endpoints such as investigation polling.",
    )
    args = parser.parse_args()

    try:
        settings = SentinelSettings.from_env()
    except Exception as exc:
        summary = {
            "mode": "http" if args.base_url else "inprocess",
            "status": "invalid_config",
            "error": redact_sensitive_text(exc, max_length=500),
        }
        print(json.dumps(summary, indent=2))
        raise SystemExit(_exit_code(summary)) from exc
    if args.base_url:
        with httpx.Client(timeout=_http_timeout_seconds(args.timeout_seconds, args.http_timeout_seconds)) as client:
            summary = run_http_demo(settings, args, client)
    else:
        summary = run_inprocess_demo(settings, args)
    print(json.dumps(summary, indent=2))
    raise SystemExit(_exit_code(summary))


def run_inprocess_demo(settings: SentinelSettings, args) -> dict:
    app = create_app(settings)
    connectivity = run_live_connectivity_checks(settings, store=app.state.store)
    if connectivity.missing_live_credentials:
        return {
            "mode": "inprocess",
            "status": "missing_credentials",
            "missing": connectivity.missing_live_credentials,
            "checks": connectivity.model_dump(mode="json")["checks"],
        }
    if not connectivity.ready:
        return {
            "mode": "inprocess",
            "status": "not_ready",
            **connectivity.model_dump(mode="json"),
        }

    service = args.service or settings.default_service
    raw = _webhook_body(args.incident_id, service)
    headers = _webhook_headers(settings, raw)

    client = TestClient(app)
    response = client.post("/webhooks/pagerduty", content=raw, headers=headers)
    if response.status_code >= 400:
        return {
            "mode": "inprocess",
            "status": "webhook_failed",
            "code": response.status_code,
            "body": _body(response),
        }

    accepted = response.json()
    investigation_id = accepted["investigation_id"]
    try:
        status = _poll(client, investigation_id, args.timeout_seconds, args.poll_interval, _operator_headers(settings, args))
    except TimeoutError as exc:
        return {
            "mode": "inprocess",
            "requested_incident_id": args.incident_id,
            "investigation_id": investigation_id,
            "status": "timeout",
            "error": str(exc),
        }
    except RuntimeError as exc:
        return {
            "mode": "inprocess",
            "requested_incident_id": args.incident_id,
            "investigation_id": investigation_id,
            "status": "poll_failed",
            "error": str(exc),
        }
    state = app.state.store.load_state(investigation_id)
    return {
        "mode": "inprocess",
        "requested_incident_id": args.incident_id,
        "investigation_id": state.id,
        "incident_id": state.incident_id,
        "status": status["status"],
        "current_state": status["current_state"],
        "webhook_received": True,
        "tool_calls": len(state.tool_calls),
        "live_provider_proofs": status.get("live_provider_proofs", {}),
        "live_tool_proofs": status.get("live_tool_proofs", {}),
        "diagnosis": state.diagnosis.summary if state.diagnosis else None,
        "confidence": state.diagnosis.confidence.value if state.diagnosis else None,
        "recommendation": state.recommendation.command if state.recommendation else None,
        "approval_request_id": state.approval_request.id if state.approval_request else None,
        "approval_slack_notification_request_id": status.get("approval_slack_notification_request_id"),
        "slack_notified": bool(status.get("slack_notified")),
        "approval_slack_notified": bool(status.get("approval_slack_notified")),
        "rollback_attempted": any(call.tool_name == "infra.rollback_deployment" for call in state.tool_calls),
        "rollback_executed": bool(status.get("rollback_executed")),
    }


def run_http_demo(settings: SentinelSettings, args, client: httpx.Client) -> dict:
    try:
        base_url = normalize_receiver_base_url(args.base_url)
    except ValueError as exc:
        return {"mode": "http", "status": "receiver_base_url_invalid", "error": str(exc)}
    try:
        preflight = run_http_receiver_check(
            base_url,
            client,
            operator_headers=_operator_headers(settings, args),
        )
        if preflight["status"] != "ready":
            return preflight

        service = args.service or settings.default_service
        raw = _webhook_body(args.incident_id, service)
        response = client.post(f"{base_url}/webhooks/pagerduty", content=raw, headers=_webhook_headers(settings, raw))
        if response.status_code >= 400:
            return {
                "mode": "http",
                "base_url": base_url,
                "status": "webhook_failed",
                "code": response.status_code,
                "body": _body(response),
            }

        accepted = response.json()
        investigation_id = accepted["investigation_id"]
        try:
            status = _poll_http(
                client,
                base_url,
                investigation_id,
                args.timeout_seconds,
                args.poll_interval,
                _operator_headers(settings, args),
            )
        except TimeoutError as exc:
            return {
                "mode": "http",
                "base_url": base_url,
                "requested_incident_id": args.incident_id,
                "investigation_id": investigation_id,
                "status": "timeout",
                "error": str(exc),
            }
        except RuntimeError as exc:
            return {
                "mode": "http",
                "base_url": base_url,
                "requested_incident_id": args.incident_id,
                "investigation_id": investigation_id,
                "status": "poll_failed",
                "error": str(exc),
            }
        return {
            "mode": "http",
            "base_url": base_url,
            "requested_incident_id": args.incident_id,
            "investigation_id": investigation_id,
            "incident_id": status.get("incident_id"),
            "status": status.get("status"),
            "current_state": status.get("current_state"),
            "webhook_received": True,
            "tool_calls": status.get("tool_calls"),
            "live_provider_proofs": status.get("live_provider_proofs", {}),
            "live_tool_proofs": status.get("live_tool_proofs", {}),
            "diagnosis": status.get("diagnosis"),
            "confidence": status.get("confidence"),
            "recommendation": status.get("recommendation"),
            "approval_request_id": status.get("approval_request_id"),
            "approval_slack_notification_request_id": status.get("approval_slack_notification_request_id"),
            "slack_notified": bool(status.get("slack_notified")),
            "approval_slack_notified": bool(status.get("approval_slack_notified")),
            "rollback_attempted": bool(status.get("rollback_attempted")),
            "rollback_executed": bool(status.get("rollback_executed")),
        }
    except httpx.HTTPError as exc:
        return {"mode": "http", "base_url": base_url, "status": "receiver_unreachable", "error": str(exc)}


def _pagerduty_payload(incident_id: str, service: str) -> dict:
    return {
        "event": {
            "event_type": "incident.triggered",
            "occurred_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "data": {
                "id": incident_id,
                "type": "incident",
                "service": {"summary": service},
            },
        }
    }


def _webhook_body(incident_id: str, service: str) -> bytes:
    return json.dumps(_pagerduty_payload(incident_id, service), separators=(",", ":")).encode()


def _webhook_headers(settings: SentinelSettings, raw: bytes) -> dict[str, str]:
    headers = {"content-type": "application/json"}
    if settings.pagerduty_webhook_secret:
        headers["x-pagerduty-signature"] = pagerduty_signature_header(
            raw,
            settings.pagerduty_webhook_secret,
        )
    if settings.pagerduty_webhook_subscription_id:
        headers["x-webhook-subscription"] = settings.pagerduty_webhook_subscription_id
    return headers


def _operator_headers(settings: SentinelSettings, args) -> dict[str, str]:
    token = getattr(args, "api_token", None) or settings.api_token
    if not token:
        return {}
    return {"authorization": f"Bearer {token}"}


def _poll(
    client: TestClient,
    investigation_id: str,
    timeout_seconds: int,
    poll_interval: float,
    headers: dict[str, str],
) -> dict:
    deadline = time.monotonic() + timeout_seconds
    latest: dict | None = None
    while time.monotonic() < deadline:
        response = client.get(f"/investigations/{investigation_id}", headers=headers)
        if response.status_code >= 400:
            raise RuntimeError(f"poll failed: {response.status_code} {_body(response)}")
        latest = response.json()
        if not isinstance(latest, dict) or not latest.get("status"):
            raise RuntimeError(f"poll returned malformed investigation status: {latest}")
        if latest["status"] in TERMINAL_STATUSES:
            return latest
        time.sleep(poll_interval)
    raise TimeoutError(f"Investigation {investigation_id} did not reach proposal state: {latest}")


def _poll_http(
    client: httpx.Client,
    base_url: str,
    investigation_id: str,
    timeout_seconds: int,
    poll_interval: float,
    headers: dict[str, str],
) -> dict:
    deadline = time.monotonic() + timeout_seconds
    latest: dict | None = None
    while time.monotonic() < deadline:
        response = client.get(f"{base_url}/investigations/{investigation_id}", headers=headers)
        if response.status_code >= 400:
            raise RuntimeError(f"poll failed: {response.status_code} {_body(response)}")
        latest = response.json()
        if not isinstance(latest, dict) or not latest.get("status"):
            raise RuntimeError(f"poll returned malformed investigation status: {latest}")
        if latest["status"] in TERMINAL_STATUSES:
            return latest
        time.sleep(poll_interval)
    raise TimeoutError(f"Investigation {investigation_id} did not reach proposal state: {latest}")


def _exit_code(summary: dict) -> int:
    if summary.get("status") in {
        "missing_credentials",
        "not_ready",
        "ready_failed",
        "ready_malformed",
        "connectivity_failed",
        "connectivity_malformed",
        "receiver_unreachable",
        "receiver_base_url_invalid",
        "invalid_config",
    }:
        return 2
    requested_incident_id = summary.get("requested_incident_id")
    if requested_incident_id and summary.get("incident_id") != requested_incident_id:
        return 1
    if (
        summary.get("status") in PROPOSAL_STATUSES
        and summary.get("current_state") == StateName.RESPONSE_PROPOSAL.value
        and _tool_call_count(summary) >= MIN_LIVE_TOOL_CALLS
        and _diagnosis_ready(summary)
        and summary.get("recommendation")
        and summary.get("approval_request_id")
        and _live_proofs_ready(summary)
        and summary.get("slack_notified")
        and summary.get("approval_slack_notified")
        and _approval_notification_matches(summary)
        and not summary.get("rollback_attempted")
        and not summary.get("rollback_executed")
    ):
        return 0
    return 1


def _tool_call_count(summary: dict) -> int:
    try:
        return int(summary.get("tool_calls") or 0)
    except (TypeError, ValueError):
        return 0


def _live_proofs_ready(summary: dict) -> bool:
    return _provider_proofs_ready(summary) and _tool_proofs_ready(summary)


def _provider_proofs_ready(summary: dict) -> bool:
    proofs = summary.get("live_provider_proofs")
    if not isinstance(proofs, dict):
        return False
    return all(_positive_count(proofs.get(provider)) for provider in REQUIRED_LIVE_PROVIDERS)


def _tool_proofs_ready(summary: dict) -> bool:
    proofs = summary.get("live_tool_proofs")
    if not isinstance(proofs, dict):
        return False
    return all(_positive_count(proofs.get(tool_name)) for tool_name in REQUIRED_PROPOSAL_TOOL_PROOFS)


def _diagnosis_ready(summary: dict) -> bool:
    diagnosis = summary.get("diagnosis")
    confidence = summary.get("confidence")
    return (
        isinstance(diagnosis, str)
        and bool(diagnosis.strip())
        and isinstance(confidence, str)
        and bool(confidence.strip())
    )


def _approval_notification_matches(summary: dict) -> bool:
    request_id = summary.get("approval_request_id")
    notification_request_id = summary.get("approval_slack_notification_request_id")
    return (
        isinstance(request_id, str)
        and bool(request_id.strip())
        and notification_request_id == request_id
    )


def _positive_count(value) -> bool:
    try:
        return int(value) > 0
    except (TypeError, ValueError):
        return False


def _http_timeout_seconds(workflow_timeout_seconds: int | float, explicit_timeout_seconds: float | None) -> float:
    if explicit_timeout_seconds is not None:
        return max(0.1, float(explicit_timeout_seconds))
    return max(0.1, min(20.0, float(workflow_timeout_seconds)))


if __name__ == "__main__":
    main()
