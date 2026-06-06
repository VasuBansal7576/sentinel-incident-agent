import importlib.util
import json
from pathlib import Path

import httpx
import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_trigger_webhook_proposal_ready_requires_live_proof_boundary():
    script = _load_trigger_script()
    status = _proposal_status()

    assert script._proposal_ready(status, "PD-LIVE-1") is True


def test_trigger_webhook_proposal_ready_rejects_wrong_incident():
    script = _load_trigger_script()
    status = _proposal_status(incident_id="PD-OTHER")

    assert script._proposal_ready(status, "PD-LIVE-1") is False


def test_trigger_webhook_proposal_ready_requires_twenty_tool_calls():
    script = _load_trigger_script()
    status = _proposal_status(tool_calls=19)

    assert script._proposal_ready(status, "PD-LIVE-1") is False


def test_trigger_webhook_proposal_ready_requires_all_live_provider_proofs():
    script = _load_trigger_script()
    status = _proposal_status(
        live_provider_proofs={
            "datadog": 6,
            "github": 5,
            "pagerduty": 1,
            "slack": 2,
            "kubernetes": 0,
        }
    )

    assert script._proposal_ready(status, "PD-LIVE-1") is False


def test_trigger_webhook_proposal_ready_requires_exact_live_tool_proofs():
    script = _load_trigger_script()
    status = _proposal_status(
        live_tool_proofs={**_tool_proofs(), "repo.get_rollback_targets": 0}
    )

    assert script._proposal_ready(status, "PD-LIVE-1") is False


def test_trigger_webhook_proposal_ready_rejects_rollback_attempt():
    script = _load_trigger_script()
    status = _proposal_status(rollback_attempted=True)

    assert script._proposal_ready(status, "PD-LIVE-1") is False


def test_trigger_webhook_proposal_ready_requires_approval_slack_notification():
    script = _load_trigger_script()
    status = _proposal_status(approval_slack_notified=False)

    assert script._proposal_ready(status, "PD-LIVE-1") is False


def test_trigger_webhook_proposal_ready_requires_current_approval_slack_notification_request():
    script = _load_trigger_script()

    assert (
        script._proposal_ready(
            _proposal_status(approval_slack_notification_request_id="approval-old"),
            "PD-LIVE-1",
        )
        is False
    )
    assert (
        script._proposal_ready(
            _proposal_status(approval_slack_notification_request_id=None),
            "PD-LIVE-1",
        )
        is False
    )


def test_trigger_webhook_proposal_ready_requires_diagnosis_and_confidence():
    script = _load_trigger_script()

    assert script._proposal_ready(_proposal_status(diagnosis=None), "PD-LIVE-1") is False
    assert script._proposal_ready(_proposal_status(confidence=""), "PD-LIVE-1") is False


def test_trigger_webhook_approved_completion_requires_submitted_approval_and_rollback_receipt():
    script = _load_trigger_script()
    status = _approved_completion_status()

    assert script._approved_completion_ready(status, "PD-LIVE-1", approval_submitted=True) is True
    assert script._approved_completion_ready(status, "PD-LIVE-1", approval_submitted=False) is False
    assert script._approved_completion_ready({**status, "rollback_executed": False}, "PD-LIVE-1", True) is False
    assert script._approved_completion_ready({**status, "current_state": "remediation"}, "PD-LIVE-1", True) is False
    assert script._approved_completion_ready(
        {**status, "live_provider_proofs": {**status["live_provider_proofs"], "kubernetes": 0}},
        "PD-LIVE-1",
        True,
    ) is False
    assert script._approved_completion_ready(
        {**status, "live_tool_proofs": {**status["live_tool_proofs"], "observe.fetch_apm_data": 0}},
        "PD-LIVE-1",
        True,
    ) is False
    assert script._approved_completion_ready(
        {**status, "live_tool_proofs": {**status["live_tool_proofs"], "infra.rollback_deployment": 0}},
        "PD-LIVE-1",
        True,
    ) is False
    assert script._approved_completion_ready(
        {**status, "remediation_result": {"status": "failed"}},
        "PD-LIVE-1",
        True,
    ) is False
    assert script._approved_completion_ready(
        {**status, "approval_slack_notified": False},
        "PD-LIVE-1",
        True,
    ) is False
    assert script._approved_completion_ready(
        {**status, "approval_slack_notification_request_id": "approval-old"},
        "PD-LIVE-1",
        True,
    ) is False
    assert script._approved_completion_ready({**status, "diagnosis": None}, "PD-LIVE-1", True) is False
    assert script._approved_completion_ready({**status, "confidence": ""}, "PD-LIVE-1", True) is False


def test_trigger_webhook_tool_call_count_rejects_malformed_counts():
    script = _load_trigger_script()

    assert script._tool_call_count({"tool_calls": "24"}) == 24
    assert script._tool_call_count({"tool_calls": "many"}) == 0


def test_trigger_webhook_uses_first_status_approver_when_approver_not_configured():
    script = _load_trigger_script()

    assert script._approval_approver_id({"approval_approver_ids": ["", "pd-user-42"]}) == "pd-user-42"
    assert script._approval_approver_id({"approval_approver_ids": []}) is None
    assert script._approval_approver_id({"approval_approver_ids": "pd-user-42"}) is None


def test_trigger_webhook_receiver_unreachable_summary_is_structured():
    script = _load_trigger_script()

    summary = script._receiver_unreachable("http://sentinel.example", httpx.ReadTimeout("timed out"))

    assert summary == {
        "status": "receiver_unreachable",
        "base_url": "http://sentinel.example",
        "error": "timed out",
    }


def test_trigger_webhook_headers_include_signature_and_subscription_when_configured():
    script = _load_trigger_script()

    headers = script._webhook_headers(
        b'{"event":{"data":{"id":"PD-LIVE-1"}}}',
        secret="pd-secret",
        subscription_id="PWSUB123",
    )

    assert headers["content-type"] == "application/json"
    assert headers["x-pagerduty-signature"].startswith("v1=")
    assert headers["x-webhook-subscription"] == "PWSUB123"


def test_trigger_webhook_headers_omit_optional_authenticity_headers_when_unconfigured():
    script = _load_trigger_script()

    headers = script._webhook_headers(b"{}", secret=None, subscription_id=None)

    assert headers == {"content-type": "application/json"}


def test_trigger_webhook_preflight_checks_live_connectivity_before_webhook():
    script = _load_trigger_script()
    client = _FakePreflightClient(
        ready={"ready": True},
        connectivity={"ready": True, "missing_live_credentials": [], "checks": []},
    )

    result = script._receiver_preflight(
        client,
        "http://sentinel.example",
        {"authorization": "Bearer sentinel-api-token"},
    )

    assert result is None
    assert client.get_urls == [
        "http://sentinel.example/ready/live",
        "http://sentinel.example/live/connectivity",
    ]
    assert client.get_headers[0] == {"authorization": "Bearer sentinel-api-token"}
    assert client.get_headers[1] == {"authorization": "Bearer sentinel-api-token"}


def test_trigger_webhook_preflight_rejects_invalid_base_url_before_network_or_auth():
    script = _load_trigger_script()
    client = _FakePreflightClient(
        ready={"ready": True},
        connectivity={"ready": True, "missing_live_credentials": [], "checks": []},
    )

    result = script._receiver_preflight(
        client,
        "http:///missing-host",
        {"authorization": "Bearer sentinel-api-token"},
    )

    assert result["status"] == "receiver_base_url_invalid"
    assert "host" in result["error"]
    assert client.get_urls == []
    assert client.get_headers == []


def test_trigger_webhook_preflight_returns_not_ready_when_connectivity_fails():
    script = _load_trigger_script()
    client = _FakePreflightClient(
        ready={"ready": True},
        connectivity={
            "ready": False,
            "missing_live_credentials": [],
            "checks": [
                {
                    "name": "datadog.logs",
                    "provider": "datadog",
                    "passed": False,
                    "duration_ms": 4.0,
                    "detail": "provider unavailable",
                    "sample": {},
                }
            ],
        },
    )

    result = script._receiver_preflight(
        client,
        "http://sentinel.example",
        {"authorization": "Bearer sentinel-api-token"},
    )

    assert result["status"] == "not_ready"
    assert result["checks"][0]["name"] == "datadog.logs"
    assert client.get_urls == [
        "http://sentinel.example/ready/live",
        "http://sentinel.example/live/connectivity",
    ]
    assert client.get_headers[1] == {"authorization": "Bearer sentinel-api-token"}


def test_trigger_webhook_preflight_reports_connectivity_auth_failure():
    script = _load_trigger_script()
    client = _FakePreflightClient(
        ready={"ready": True},
        connectivity={"detail": "Invalid SENTINEL API token"},
        connectivity_status_code=401,
    )

    result = script._receiver_preflight(client, "http://sentinel.example", {})

    assert result == {
        "status": "connectivity_failed",
        "endpoint": "/live/connectivity",
        "code": 401,
        "body": {"detail": "Invalid SENTINEL API token"},
    }


def test_trigger_webhook_preflight_keeps_base_url_when_receiver_is_unreachable():
    script = _load_trigger_script()
    client = _FakePreflightClient(
        ready=httpx.ReadTimeout("timed out"),
        connectivity={"ready": True, "missing_live_credentials": [], "checks": []},
    )

    result = script._receiver_preflight(
        client,
        "http://sentinel.example",
        {"authorization": "Bearer sentinel-api-token"},
    )

    assert result == {
        "status": "receiver_unreachable",
        "error": "timed out",
        "base_url": "http://sentinel.example",
    }


def test_trigger_webhook_preflight_reports_malformed_ready_success_body():
    script = _load_trigger_script()
    client = _FakePreflightClient(
        ready={"status": "ok"},
        connectivity={"ready": True, "missing_live_credentials": [], "checks": []},
    )

    result = script._receiver_preflight(
        client,
        "http://sentinel.example",
        {"authorization": "Bearer sentinel-api-token"},
    )

    assert result == {
        "status": "ready_malformed",
        "endpoint": "/ready/live",
        "body": {"status": "ok"},
    }
    assert client.get_urls == ["http://sentinel.example/ready/live"]


def test_trigger_webhook_preflight_reports_malformed_connectivity_success_body():
    script = _load_trigger_script()
    client = _FakePreflightClient(
        ready={"ready": True},
        connectivity={"status": "ok"},
    )

    result = script._receiver_preflight(
        client,
        "http://sentinel.example",
        {"authorization": "Bearer sentinel-api-token"},
    )

    assert result == {
        "status": "connectivity_malformed",
        "endpoint": "/live/connectivity",
        "body": {"status": "ok"},
    }
    assert client.get_urls == [
        "http://sentinel.example/ready/live",
        "http://sentinel.example/live/connectivity",
    ]


def test_trigger_webhook_rejects_invalid_base_url_before_opening_client(monkeypatch, capsys):
    script = _load_trigger_script()

    class FailingClient:
        def __init__(self, *, timeout):
            raise AssertionError("http client should not open for invalid receiver URL")

    monkeypatch.setattr(script.httpx, "Client", FailingClient)
    monkeypatch.setattr(
        script.sys,
        "argv",
        [
            "trigger_live_webhook.py",
            "PD-LIVE-1",
            "--base-url",
            "https://sentinel.example#fragment",
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        script.main()

    body = json.loads(capsys.readouterr().out)
    assert exit_info.value.code == 2
    assert body["status"] == "receiver_base_url_invalid"
    assert "query string or fragment" in body["error"]


def test_trigger_webhook_derives_request_timeout_from_short_poll_window(monkeypatch):
    script = _load_trigger_script()
    captured: dict[str, float] = {}

    class CapturingClient:
        def __init__(self, *, timeout):
            captured["timeout"] = timeout

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

    monkeypatch.setattr(script.httpx, "Client", CapturingClient)
    monkeypatch.setattr(
        script,
        "_receiver_preflight",
        lambda _client, base_url, _headers: {
            "status": "receiver_unreachable",
            "error": "timed out",
            "base_url": base_url,
        },
    )
    monkeypatch.setattr(
        script.sys,
        "argv",
        [
            "trigger_live_webhook.py",
            "PD-LIVE-1",
            "--base-url",
            "http://sentinel.example",
            "--poll-seconds",
            "1",
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        script.main()

    assert exit_info.value.code == 2
    assert captured["timeout"] == 1.0


def test_trigger_webhook_allows_explicit_request_timeout(monkeypatch):
    script = _load_trigger_script()
    captured: dict[str, float] = {}

    class CapturingClient:
        def __init__(self, *, timeout):
            captured["timeout"] = timeout

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

    monkeypatch.setattr(script.httpx, "Client", CapturingClient)
    monkeypatch.setattr(
        script,
        "_receiver_preflight",
        lambda _client, base_url, _headers: {
            "status": "receiver_unreachable",
            "error": "timed out",
            "base_url": base_url,
        },
    )
    monkeypatch.setattr(
        script.sys,
        "argv",
        [
            "trigger_live_webhook.py",
            "PD-LIVE-1",
            "--base-url",
            "http://sentinel.example",
            "--poll-seconds",
            "1",
            "--http-timeout-seconds",
            "3.5",
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        script.main()

    assert exit_info.value.code == 2
    assert captured["timeout"] == 3.5


def _proposal_status(**overrides):
    status = {
        "incident_id": "PD-LIVE-1",
        "status": "waiting_for_approval",
        "current_state": "response_proposal",
        "tool_calls": 24,
        "live_provider_proofs": {
            "datadog": 6,
            "github": 5,
            "pagerduty": 1,
            "slack": 2,
            "kubernetes": 2,
        },
        "live_tool_proofs": _tool_proofs(),
        "diagnosis": "Live evidence points to a bad deploy.",
        "confidence": "high",
        "recommendation": "rollback checkout-service",
        "approval_request_id": "approval-1",
        "approval_slack_notification_request_id": "approval-1",
        "approval_approver_ids": ["pd-user-42"],
        "slack_notified": True,
        "approval_slack_notified": True,
        "rollback_attempted": False,
        "rollback_executed": False,
    }
    status.update(overrides)
    return status


def _approved_completion_status(**overrides):
    status = {
        "incident_id": "PD-LIVE-1",
        "status": "completed",
        "current_state": "post_mortem",
        "tool_calls": 32,
        "live_provider_proofs": {
            "datadog": 7,
            "github": 6,
            "pagerduty": 2,
            "slack": 3,
            "kubernetes": 3,
        },
        "live_tool_proofs": _approved_tool_proofs(),
        "diagnosis": "Live evidence points to a bad deploy.",
        "confidence": "high",
        "approval_request_id": "approval-1",
        "approval_slack_notification_request_id": "approval-1",
        "slack_notified": True,
        "approval_slack_notified": True,
        "rollback_attempted": True,
        "rollback_executed": True,
        "remediation_result": {"status": "executed"},
    }
    status.update(overrides)
    return status


def _load_trigger_script():
    spec = importlib.util.spec_from_file_location(
        "trigger_live_webhook",
        ROOT / "scripts" / "trigger_live_webhook.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _tool_proofs():
    return {
        "observe.fetch_service_logs": 2,
        "observe.get_error_rate_timeseries": 1,
        "observe.fetch_apm_data": 1,
        "repo.get_deploy_history": 1,
        "repo.get_rollback_targets": 1,
        "observe.check_pod_health": 1,
        "comms.page_oncall_engineer": 1,
        "comms.post_to_slack": 2,
    }


def _approved_tool_proofs():
    return {**_tool_proofs(), "infra.rollback_deployment": 1}


class _FakePreflightClient:
    def __init__(
        self,
        *,
        ready: dict,
        connectivity: dict,
        ready_status_code: int = 200,
        connectivity_status_code: int = 200,
    ):
        self.ready = ready
        self.connectivity = connectivity
        self.ready_status_code = ready_status_code
        self.connectivity_status_code = connectivity_status_code
        self.get_urls = []
        self.get_headers = []

    def get(self, url, headers=None):
        self.get_urls.append(url)
        self.get_headers.append(headers or {})
        if url.endswith("/ready/live"):
            if isinstance(self.ready, httpx.HTTPError):
                raise self.ready
            return _Response(self.ready_status_code, self.ready)
        if url.endswith("/live/connectivity"):
            if isinstance(self.connectivity, httpx.HTTPError):
                raise self.connectivity
            return _Response(self.connectivity_status_code, self.connectivity)
        raise AssertionError(f"unexpected GET {url}")


class _Response:
    def __init__(self, status_code: int, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        if isinstance(self._body, BaseException):
            raise self._body
        return self._body

    @property
    def text(self):
        return str(self._body)
