import json
import os
import time
from datetime import UTC, datetime

import httpx
import pytest
from fastapi.testclient import TestClient

from sentinel.config import SentinelSettings
from sentinel.credentials import missing_live_credentials
from sentinel.live_receiver_preflight import run_http_receiver_check
from sentinel.models import InvestigationStatus
from sentinel.oauth import pagerduty_signature_header
from sentinel.webapp import create_app


pytestmark = pytest.mark.live

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


def test_live_pagerduty_webhook_investigates_and_posts_slack_proposal():
    settings = SentinelSettings.from_env()
    app = create_app(settings)
    missing = missing_live_credentials(settings, app.state.store)
    if not os.getenv("RUN_LIVE_E2E_TESTS"):
        pytest.skip("RUN_LIVE_E2E_TESTS unset")
    if missing:
        pytest.fail(f"RUN_LIVE_E2E_TESTS is set but live E2E credentials are missing: {missing}")

    incident_id = _live_incident_id()
    raw = _webhook_body(incident_id, _live_service(settings))
    headers = _webhook_headers(raw, settings)

    client = TestClient(app)
    response = client.post("/webhooks/pagerduty", content=raw, headers=headers)

    assert response.status_code == 200, response.text
    investigation_id = response.json()["investigation_id"]
    status = _poll_investigation(client, investigation_id, settings)
    state = app.state.store.load_state(investigation_id)

    _assert_live_proposal_status(status)
    assert state.diagnosis is not None
    assert state.recommendation is not None
    assert state.approval_request is not None
    assert any(call.tool_name == "comms.post_to_slack" and call.success for call in state.tool_calls)
    assert not any(call.tool_name == "infra.rollback_deployment" for call in state.tool_calls)


def test_live_pagerduty_webhook_approval_executes_verified_rollback():
    settings = SentinelSettings.from_env()
    app = create_app(settings)
    missing = missing_live_credentials(settings, app.state.store)
    if not os.getenv("RUN_LIVE_APPROVAL_E2E_TESTS"):
        pytest.skip("RUN_LIVE_APPROVAL_E2E_TESTS unset")
    if missing:
        pytest.fail(
            f"RUN_LIVE_APPROVAL_E2E_TESTS is set but live E2E credentials are missing: {missing}"
        )

    incident_id = _live_incident_id()
    raw = _webhook_body(incident_id, _live_service(settings))
    headers = _webhook_headers(raw, settings)
    operator_headers = _operator_headers(settings)

    client = TestClient(app)
    response = client.post("/webhooks/pagerduty", content=raw, headers=headers)

    assert response.status_code == 200, response.text
    investigation_id = response.json()["investigation_id"]
    proposal = _poll_investigation(client, investigation_id, settings)
    _assert_live_proposal_status(proposal)
    approver_id = _approval_approver_id(proposal)
    assert approver_id, proposal

    approval_response = client.post(
        f"/investigations/{investigation_id}/approval",
        json={
            "request_id": proposal["approval_request_id"],
            "approver_id": approver_id,
            "decision": "approve",
            "idempotency_key": (
                f"{investigation_id}:approval-command:"
                f"{proposal['approval_request_id']}:{approver_id}:approve"
            ),
        },
        headers=operator_headers,
    )
    assert approval_response.status_code == 200, approval_response.text

    completed = _poll_completed_investigation(client, investigation_id, operator_headers)
    state = app.state.store.load_state(investigation_id)

    _assert_live_approved_completion(completed, incident_id)
    assert state.remediation_result is not None
    assert state.remediation_result.status == "executed"
    assert state.post_mortem is not None
    assert any(call.tool_name == "infra.rollback_deployment" and call.success for call in state.tool_calls)


def test_live_deployed_receiver_http_webhook_investigates_and_posts_slack_proposal():
    settings = SentinelSettings.from_env()
    base_url = (os.getenv("SENTINEL_LIVE_RECEIVER_URL") or "").rstrip("/")
    if not os.getenv("RUN_LIVE_HTTP_E2E_TESTS"):
        pytest.skip("RUN_LIVE_HTTP_E2E_TESTS unset")
    if not base_url:
        pytest.fail("RUN_LIVE_HTTP_E2E_TESTS is set but SENTINEL_LIVE_RECEIVER_URL is missing")

    incident_id = _live_incident_id()
    raw = _webhook_body(incident_id, _live_service(settings))
    headers = _webhook_headers(raw, settings)
    operator_headers = _operator_headers(settings)

    with httpx.Client(timeout=20) as client:
        _assert_http_receiver_ready(client, base_url, operator_headers)
        response = client.post(f"{base_url}/webhooks/pagerduty", content=raw, headers=headers)
        assert response.status_code == 200, response.text
        investigation_id = response.json()["investigation_id"]
        status = _poll_http_investigation(client, base_url, investigation_id, operator_headers)

    assert status["incident_id"] == incident_id
    _assert_live_proposal_status(status)


def test_live_deployed_receiver_http_approval_executes_verified_rollback():
    settings = SentinelSettings.from_env()
    base_url = (os.getenv("SENTINEL_LIVE_RECEIVER_URL") or "").rstrip("/")
    if not os.getenv("RUN_LIVE_HTTP_APPROVAL_E2E_TESTS"):
        pytest.skip("RUN_LIVE_HTTP_APPROVAL_E2E_TESTS unset")
    if not base_url:
        pytest.fail(
            "RUN_LIVE_HTTP_APPROVAL_E2E_TESTS is set but SENTINEL_LIVE_RECEIVER_URL is missing"
        )

    incident_id = _live_incident_id()
    raw = _webhook_body(incident_id, _live_service(settings))
    headers = _webhook_headers(raw, settings)
    operator_headers = _operator_headers(settings)

    with httpx.Client(timeout=20) as client:
        _assert_http_receiver_ready(client, base_url, operator_headers)
        response = client.post(f"{base_url}/webhooks/pagerduty", content=raw, headers=headers)
        assert response.status_code == 200, response.text
        investigation_id = response.json()["investigation_id"]
        proposal = _poll_http_investigation(client, base_url, investigation_id, operator_headers)
        _assert_live_proposal_status(proposal)
        approver_id = _approval_approver_id(proposal)
        assert approver_id, proposal

        approval_response = client.post(
            f"{base_url}/investigations/{investigation_id}/approval",
            json={
                "request_id": proposal["approval_request_id"],
                "approver_id": approver_id,
                "decision": "approve",
                "idempotency_key": (
                    f"{investigation_id}:approval-command:"
                    f"{proposal['approval_request_id']}:{approver_id}:approve"
                ),
            },
            headers=operator_headers,
        )
        assert approval_response.status_code == 200, approval_response.text
        completed = _poll_http_completed_investigation(
            client,
            base_url,
            investigation_id,
            operator_headers,
        )

    _assert_live_approved_completion(completed, incident_id)


def _assert_http_receiver_ready(
    client: httpx.Client,
    base_url: str,
    operator_headers: dict[str, str],
) -> None:
    summary = run_http_receiver_check(
        base_url,
        client,
        operator_headers=operator_headers,
    )
    assert summary["status"] == "ready", json.dumps(summary, indent=2)


def _poll_investigation(client: TestClient, investigation_id: str, settings: SentinelSettings) -> dict:
    deadline = time.monotonic() + int(os.getenv("SENTINEL_LIVE_E2E_TIMEOUT_SECONDS", "180"))
    latest: dict | None = None
    headers = _operator_headers(settings)
    while time.monotonic() < deadline:
        response = client.get(f"/investigations/{investigation_id}", headers=headers)
        assert response.status_code == 200, response.text
        latest = response.json()
        if latest["status"] in {
            InvestigationStatus.WAITING_FOR_APPROVAL.value,
            InvestigationStatus.COMPLETED.value,
            InvestigationStatus.INSUFFICIENT_CONFIDENCE.value,
            InvestigationStatus.FAILED.value,
        }:
            return latest
        time.sleep(5)
    raise AssertionError(f"Investigation {investigation_id} did not finish live E2E proposal path: {latest}")


def _poll_http_investigation(
    client: httpx.Client,
    base_url: str,
    investigation_id: str,
    headers: dict[str, str],
) -> dict:
    deadline = time.monotonic() + int(os.getenv("SENTINEL_LIVE_E2E_TIMEOUT_SECONDS", "180"))
    latest: dict | None = None
    while time.monotonic() < deadline:
        response = client.get(f"{base_url}/investigations/{investigation_id}", headers=headers)
        assert response.status_code == 200, response.text
        latest = response.json()
        if latest["status"] in {
            InvestigationStatus.WAITING_FOR_APPROVAL.value,
            InvestigationStatus.COMPLETED.value,
            InvestigationStatus.INSUFFICIENT_CONFIDENCE.value,
            InvestigationStatus.FAILED.value,
        }:
            return latest
        time.sleep(5)
    raise AssertionError(f"Investigation {investigation_id} did not finish deployed live E2E proposal path: {latest}")


def _poll_http_completed_investigation(
    client: httpx.Client,
    base_url: str,
    investigation_id: str,
    headers: dict[str, str],
) -> dict:
    deadline = time.monotonic() + int(os.getenv("SENTINEL_LIVE_E2E_TIMEOUT_SECONDS", "180"))
    latest: dict | None = None
    while time.monotonic() < deadline:
        response = client.get(f"{base_url}/investigations/{investigation_id}", headers=headers)
        assert response.status_code == 200, response.text
        latest = response.json()
        if latest["status"] in {
            InvestigationStatus.COMPLETED.value,
            InvestigationStatus.INSUFFICIENT_CONFIDENCE.value,
            InvestigationStatus.FAILED.value,
        }:
            return latest
        time.sleep(5)
    raise AssertionError(f"Investigation {investigation_id} did not complete deployed approved live E2E path: {latest}")


def _poll_completed_investigation(
    client: TestClient,
    investigation_id: str,
    headers: dict[str, str],
) -> dict:
    deadline = time.monotonic() + int(os.getenv("SENTINEL_LIVE_E2E_TIMEOUT_SECONDS", "180"))
    latest: dict | None = None
    while time.monotonic() < deadline:
        response = client.get(f"/investigations/{investigation_id}", headers=headers)
        assert response.status_code == 200, response.text
        latest = response.json()
        if latest["status"] in {
            InvestigationStatus.COMPLETED.value,
            InvestigationStatus.INSUFFICIENT_CONFIDENCE.value,
            InvestigationStatus.FAILED.value,
        }:
            return latest
        time.sleep(5)
    raise AssertionError(f"Investigation {investigation_id} did not complete approved live E2E path: {latest}")


def _assert_live_proposal_status(status: dict) -> None:
    assert status["status"] == InvestigationStatus.WAITING_FOR_APPROVAL.value
    assert status["current_state"] == "response_proposal"
    assert status["approval_request_id"]
    assert status["approval_slack_notification_request_id"] == status["approval_request_id"]
    assert _approval_approver_id(status)
    assert status["diagnosis"]
    assert status["confidence"]
    assert status["recommendation"]
    assert status["tool_calls"] >= 20
    _assert_positive_proofs(status["live_provider_proofs"], REQUIRED_LIVE_PROVIDERS)
    _assert_positive_proofs(status["live_tool_proofs"], REQUIRED_PROPOSAL_TOOL_PROOFS)
    assert status["slack_notified"] is True
    assert status["approval_slack_notified"] is True
    assert status["rollback_attempted"] is False
    assert status["rollback_executed"] is False


def _assert_live_approved_completion(status: dict, incident_id: str) -> None:
    assert status["incident_id"] == incident_id
    assert status["status"] == InvestigationStatus.COMPLETED.value
    assert status["current_state"] == "post_mortem"
    assert status["diagnosis"]
    assert status["confidence"]
    assert status["approval_request_id"]
    assert status["approval_slack_notification_request_id"] == status["approval_request_id"]
    assert status["tool_calls"] >= 20
    _assert_positive_proofs(status["live_provider_proofs"], REQUIRED_LIVE_PROVIDERS)
    _assert_positive_proofs(status["live_tool_proofs"], REQUIRED_APPROVED_TOOL_PROOFS)
    assert status["slack_notified"] is True
    assert status["approval_slack_notified"] is True
    assert status["rollback_attempted"] is True
    assert status["rollback_executed"] is True
    assert isinstance(status["remediation_result"], dict)
    assert status["remediation_result"]["status"] == "executed"


def _assert_positive_proofs(proofs: dict, required_names: tuple[str, ...]) -> None:
    missing = [
        name
        for name in required_names
        if int(proofs.get(name, 0)) <= 0
    ]
    assert not missing, {"missing": missing, "proofs": proofs}


def _approval_approver_id(status: dict) -> str | None:
    approvers = status.get("approval_approver_ids")
    if not isinstance(approvers, list):
        return None
    for approver in approvers:
        if isinstance(approver, str) and approver.strip():
            return approver.strip()
    return None


def _webhook_body(incident_id: str, service: str) -> bytes:
    payload = {
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
    return json.dumps(payload, separators=(",", ":")).encode()


def _webhook_headers(raw: bytes, settings: SentinelSettings) -> dict[str, str]:
    headers = {"content-type": "application/json"}
    if settings.pagerduty_webhook_secret:
        headers["x-pagerduty-signature"] = pagerduty_signature_header(
            raw,
            settings.pagerduty_webhook_secret,
        )
    if settings.pagerduty_webhook_subscription_id:
        headers["x-webhook-subscription"] = settings.pagerduty_webhook_subscription_id
    return headers


def _operator_headers(settings: SentinelSettings) -> dict[str, str]:
    return {"authorization": f"Bearer {settings.api_token}"} if settings.api_token else {}


def _live_incident_id() -> str:
    return os.getenv("SENTINEL_LIVE_TEST_INCIDENT_ID", "LIVE-E2E-PAGERDUTY-INCIDENT")


def _live_service(settings: SentinelSettings) -> str:
    return os.getenv("SENTINEL_LIVE_TEST_SERVICE", settings.default_service)
