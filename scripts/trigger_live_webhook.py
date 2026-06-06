from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.live_receiver_preflight import (
    normalize_receiver_base_url,
    operator_auth_headers as _operator_headers,
    receiver_preflight_failure,
    response_body as _body,
    run_http_receiver_check,
)
from sentinel.oauth import pagerduty_signature_header


TERMINAL_STATUSES = {"completed", "failed", "insufficient_confidence"}
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
REQUIRED_APPROVED_TOOL_PROOFS = (
    *REQUIRED_PROPOSAL_TOOL_PROOFS,
    "infra.rollback_deployment",
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Trigger and poll a live SENTINEL PagerDuty webhook run.")
    parser.add_argument("incident_id", help="PagerDuty incident id to include in the webhook payload.")
    parser.add_argument("--service", default=os.getenv("SENTINEL_DEFAULT_SERVICE", "payment-service"))
    parser.add_argument("--base-url", default=os.getenv("SENTINEL_BASE_URL", "http://localhost:8000"))
    parser.add_argument("--poll-seconds", type=int, default=120)
    parser.add_argument(
        "--http-timeout-seconds",
        type=float,
        default=None,
        help="Per-request HTTP timeout. Defaults to min(20, --poll-seconds).",
    )
    parser.add_argument("--poll-interval", type=float, default=5.0)
    parser.add_argument("--approve", action="store_true", help="Submit structured approval after proposal.")
    parser.add_argument(
        "--approver-id",
        default=os.getenv("SENTINEL_APPROVER_ID"),
        help="Authorized approver id. Defaults to the first approver returned by the receiver status API.",
    )
    parser.add_argument(
        "--api-token",
        default=os.getenv("SENTINEL_API_TOKEN"),
        help="Bearer token for SENTINEL operator endpoints such as polling and approval.",
    )
    args = parser.parse_args()

    try:
        base_url = normalize_receiver_base_url(args.base_url)
    except ValueError as exc:
        print(json.dumps({"status": "receiver_base_url_invalid", "error": str(exc)}, indent=2))
        raise SystemExit(2) from exc
    payload = {
        "event": {
            "event_type": "incident.triggered",
            "occurred_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "data": {
                "incident": {
                    "id": args.incident_id,
                    "service": {"summary": args.service},
                }
            },
        }
    }
    raw = json.dumps(payload, separators=(",", ":")).encode()
    headers = _webhook_headers(
        raw,
        secret=os.getenv("PAGERDUTY_WEBHOOK_SECRET"),
        subscription_id=os.getenv("PAGERDUTY_WEBHOOK_SUBSCRIPTION_ID"),
    )
    operator_headers = _operator_headers(args.api_token)

    try:
        with httpx.Client(timeout=_http_timeout_seconds(args.poll_seconds, args.http_timeout_seconds)) as client:
            preflight = _receiver_preflight(client, base_url, operator_headers)
            if preflight is not None:
                print(json.dumps(preflight, indent=2))
                raise SystemExit(2)

            response = client.post(f"{base_url}/webhooks/pagerduty", content=raw, headers=headers)
            if response.status_code >= 400:
                print(json.dumps({"status": "webhook_failed", "code": response.status_code, "body": _body(response)}, indent=2))
                raise SystemExit(1)

            accepted = response.json()
            investigation_id = accepted["investigation_id"]
            print(json.dumps({"status": "accepted", **accepted}, indent=2))

            deadline = time.monotonic() + args.poll_seconds
            approval_submitted = False
            while time.monotonic() < deadline:
                status_response = client.get(f"{base_url}/investigations/{investigation_id}", headers=operator_headers)
                if status_response.status_code >= 400:
                    print(json.dumps({"status": "poll_failed", "code": status_response.status_code, "body": _body(status_response)}, indent=2))
                    raise SystemExit(1)

                status = status_response.json()
                print(json.dumps(status, indent=2))
                investigation_status = status["status"]
                if (
                    args.approve
                    and not approval_submitted
                    and investigation_status == "waiting_for_approval"
                    and status.get("approval_request_id")
                ):
                    if not _proposal_ready(status, args.incident_id):
                        print(json.dumps({"status": "proposal_not_ready", "body": status}, indent=2))
                        raise SystemExit(1)
                    approver_id = args.approver_id or _approval_approver_id(status)
                    if not approver_id:
                        print(json.dumps({"status": "approval_approver_missing", "body": status}, indent=2))
                        raise SystemExit(1)
                    approval = {
                        "request_id": status["approval_request_id"],
                        "approver_id": approver_id,
                        "decision": "approve",
                        "idempotency_key": (
                            f"{investigation_id}:approval-command:"
                            f"{status['approval_request_id']}:{approver_id}:approve"
                        ),
                    }
                    approval_response = client.post(
                        f"{base_url}/investigations/{investigation_id}/approval",
                        json=approval,
                        headers=operator_headers,
                    )
                    print(
                        json.dumps(
                            {
                                "status": "approval_submitted",
                                "code": approval_response.status_code,
                                "body": _body(approval_response),
                            },
                            indent=2,
                        )
                    )
                    if approval_response.status_code >= 400:
                        raise SystemExit(1)
                    approval_submitted = True
                elif investigation_status == "waiting_for_approval" and not args.approve:
                    if _proposal_ready(status, args.incident_id):
                        return
                    print(json.dumps({"status": "proposal_not_ready", "body": status}, indent=2))
                    raise SystemExit(1)
                elif investigation_status in TERMINAL_STATUSES:
                    if args.approve and _approved_completion_ready(status, args.incident_id, approval_submitted):
                        raise SystemExit(0)
                    print(json.dumps({"status": "terminal_not_successful", "body": status}, indent=2))
                    raise SystemExit(1)

                time.sleep(args.poll_interval)
    except httpx.HTTPError as exc:
        print(json.dumps(_receiver_unreachable(base_url, exc), indent=2))
        raise SystemExit(2) from exc

    print(json.dumps({"status": "timeout", "investigation_id": investigation_id}, indent=2))
    raise SystemExit(1)


def _receiver_preflight(client: httpx.Client, base_url: str, operator_headers: dict[str, str]) -> dict | None:
    summary = run_http_receiver_check(
        base_url,
        client,
        operator_headers=operator_headers,
    )
    failure = receiver_preflight_failure(summary, include_receiver_context=False)
    if failure and summary.get("status") == "receiver_unreachable":
        failure["base_url"] = summary.get("base_url")
    return failure


def _webhook_headers(raw: bytes, *, secret: str | None, subscription_id: str | None) -> dict[str, str]:
    headers = {"content-type": "application/json"}
    if secret:
        headers["x-pagerduty-signature"] = pagerduty_signature_header(raw, secret)
    if subscription_id:
        headers["x-webhook-subscription"] = subscription_id
    return headers


def _receiver_unreachable(base_url: str, exc: httpx.HTTPError) -> dict[str, str]:
    return {"status": "receiver_unreachable", "base_url": base_url, "error": str(exc)}


def _proposal_ready(status: dict, requested_incident_id: str) -> bool:
    return (
        status.get("incident_id") == requested_incident_id
        and status.get("status") == "waiting_for_approval"
        and status.get("current_state") == "response_proposal"
        and _tool_call_count(status) >= MIN_LIVE_TOOL_CALLS
        and _diagnosis_ready(status)
        and bool(status.get("recommendation"))
        and bool(status.get("approval_request_id"))
        and _live_proofs_ready(status, REQUIRED_PROPOSAL_TOOL_PROOFS)
        and status.get("slack_notified") is True
        and status.get("approval_slack_notified") is True
        and _approval_notification_matches(status)
        and not status.get("rollback_attempted")
        and not status.get("rollback_executed")
    )


def _approval_approver_id(status: dict) -> str | None:
    approvers = status.get("approval_approver_ids")
    if not isinstance(approvers, list):
        return None
    for approver in approvers:
        if isinstance(approver, str) and approver.strip():
            return approver.strip()
    return None


def _approved_completion_ready(status: dict, requested_incident_id: str, approval_submitted: bool) -> bool:
    return (
        approval_submitted
        and status.get("incident_id") == requested_incident_id
        and status.get("status") == "completed"
        and status.get("current_state") == "post_mortem"
        and _tool_call_count(status) >= MIN_LIVE_TOOL_CALLS
        and _diagnosis_ready(status)
        and _live_proofs_ready(status, REQUIRED_APPROVED_TOOL_PROOFS)
        and status.get("slack_notified") is True
        and status.get("approval_slack_notified") is True
        and _approval_notification_matches(status)
        and status.get("rollback_attempted") is True
        and status.get("rollback_executed") is True
        and _remediation_executed(status)
    )


def _tool_call_count(status: dict) -> int:
    try:
        return int(status.get("tool_calls") or 0)
    except (TypeError, ValueError):
        return 0


def _live_proofs_ready(status: dict, required_tool_proofs: tuple[str, ...]) -> bool:
    return _provider_proofs_ready(status) and _tool_proofs_ready(status, required_tool_proofs)


def _provider_proofs_ready(status: dict) -> bool:
    proofs = status.get("live_provider_proofs")
    if not isinstance(proofs, dict):
        return False
    return all(_positive_count(proofs.get(provider)) for provider in REQUIRED_LIVE_PROVIDERS)


def _tool_proofs_ready(status: dict, required_tool_proofs: tuple[str, ...]) -> bool:
    proofs = status.get("live_tool_proofs")
    if not isinstance(proofs, dict):
        return False
    return all(_positive_count(proofs.get(tool_name)) for tool_name in required_tool_proofs)


def _remediation_executed(status: dict) -> bool:
    result = status.get("remediation_result")
    return isinstance(result, dict) and result.get("status") == "executed"


def _approval_notification_matches(status: dict) -> bool:
    request_id = status.get("approval_request_id")
    notification_request_id = status.get("approval_slack_notification_request_id")
    return (
        isinstance(request_id, str)
        and bool(request_id.strip())
        and notification_request_id == request_id
    )


def _diagnosis_ready(status: dict) -> bool:
    diagnosis = status.get("diagnosis")
    confidence = status.get("confidence")
    return (
        isinstance(diagnosis, str)
        and bool(diagnosis.strip())
        and isinstance(confidence, str)
        and bool(confidence.strip())
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
