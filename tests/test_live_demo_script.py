import importlib.util
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel.config import SentinelSettings


ROOT = Path(__file__).resolve().parents[1]


def test_http_live_demo_posts_to_deployed_receiver_and_requires_slack_notification():
    demo = _load_demo_script()
    client = _FakeHttpDemoClient(
        ready={"ready": True},
        connectivity={"ready": True, "missing_live_credentials": [], "checks": []},
        status={
            "investigation_id": "inv-remote",
            "incident_id": "PD-REMOTE",
            "status": "waiting_for_approval",
            "current_state": "response_proposal",
            "tool_calls": 24,
            "live_provider_proofs": _provider_proofs(),
            "live_tool_proofs": _tool_proofs(),
            "diagnosis": "Live evidence points to a bad deploy.",
            "confidence": "high",
            "recommendation": "rollback checkout-service to revision:41",
            "approval_request_id": "approval-remote",
            "approval_slack_notification_request_id": "approval-remote",
            "slack_notified": True,
            "approval_slack_notified": True,
            "rollback_attempted": False,
            "rollback_executed": False,
        },
    )
    args = SimpleNamespace(
        base_url="http://sentinel.example",
        incident_id="PD-REMOTE",
        service="checkout-service",
        timeout_seconds=1,
        poll_interval=0,
        api_token="sentinel-api-token",
    )
    settings = replace(
        SentinelSettings.from_env(),
        pagerduty_webhook_secret="pd-secret",
        pagerduty_webhook_subscription_id="PWSUB123",
        api_token="sentinel-api-token",
    )

    summary = demo.run_http_demo(settings, args, client)

    assert summary["mode"] == "http"
    assert summary["requested_incident_id"] == "PD-REMOTE"
    assert summary["incident_id"] == "PD-REMOTE"
    assert summary["tool_calls"] == 24
    assert summary["live_provider_proofs"] == _provider_proofs()
    assert summary["live_tool_proofs"] == _tool_proofs()
    assert summary["status"] == "waiting_for_approval"
    assert summary["approval_request_id"] == "approval-remote"
    assert summary["approval_slack_notification_request_id"] == "approval-remote"
    assert summary["slack_notified"] is True
    assert summary["approval_slack_notified"] is True
    assert summary["rollback_attempted"] is False
    assert summary["rollback_executed"] is False
    assert demo._exit_code(summary) == 0
    assert client.get_urls == [
        "http://sentinel.example/ready/live",
        "http://sentinel.example/live/connectivity",
        "http://sentinel.example/investigations/inv-remote",
    ]
    assert client.get_headers[0] == {"authorization": "Bearer sentinel-api-token"}
    assert client.get_headers[1] == {"authorization": "Bearer sentinel-api-token"}
    assert client.get_headers[2] == {"authorization": "Bearer sentinel-api-token"}
    assert client.post_urls == ["http://sentinel.example/webhooks/pagerduty"]
    assert "x-pagerduty-signature" in client.post_headers[0]
    assert client.post_headers[0]["x-pagerduty-signature"].startswith("v1=")
    assert client.post_headers[0]["x-webhook-subscription"] == "PWSUB123"
    assert json.loads(client.post_bodies[0])["event"]["data"]["id"] == "PD-REMOTE"


def test_http_live_demo_rejects_invalid_receiver_base_url_before_preflight_or_webhook():
    demo = _load_demo_script()
    client = _FakeHttpDemoClient(
        ready={"ready": True},
        connectivity={"ready": True, "missing_live_credentials": [], "checks": []},
        status={},
    )
    args = SimpleNamespace(
        base_url="https://sentinel.example?token=secret",
        incident_id="PD-REMOTE",
        service="checkout-service",
        timeout_seconds=1,
        poll_interval=0,
        api_token="sentinel-api-token",
    )

    summary = demo.run_http_demo(SentinelSettings.from_env(), args, client)

    assert summary["mode"] == "http"
    assert summary["status"] == "receiver_base_url_invalid"
    assert "query string or fragment" in summary["error"]
    assert demo._exit_code(summary) == 2
    assert client.get_urls == []
    assert client.post_urls == []


def test_http_live_demo_stops_before_webhook_when_deployed_receiver_not_ready():
    demo = _load_demo_script()
    client = _FakeHttpDemoClient(
        ready={
            "ready": False,
            "missing_live_credentials": ["SLACK_BOT_TOKEN"],
            "checks": [],
        },
        ready_status_code=503,
        status={},
    )
    args = SimpleNamespace(
        base_url="http://sentinel.example",
        incident_id="PD-REMOTE",
        service="checkout-service",
        timeout_seconds=1,
        poll_interval=0,
        api_token=None,
    )

    summary = demo.run_http_demo(SentinelSettings.from_env(), args, client)

    assert summary["status"] == "not_ready"
    assert summary["missing_live_credentials"] == ["SLACK_BOT_TOKEN"]
    assert demo._exit_code(summary) == 2
    assert client.post_urls == []


def test_http_live_demo_stops_before_webhook_when_connectivity_preflight_fails():
    demo = _load_demo_script()
    client = _FakeHttpDemoClient(
        ready={"ready": True},
        connectivity={
            "ready": False,
            "missing_live_credentials": [],
            "checks": [
                {
                    "name": "datadog.logs",
                    "provider": "datadog",
                    "passed": False,
                    "duration_ms": 7.0,
                    "detail": "provider unavailable",
                    "sample": {},
                }
            ],
        },
        status={},
    )
    args = SimpleNamespace(
        base_url="http://sentinel.example",
        incident_id="PD-REMOTE",
        service="checkout-service",
        timeout_seconds=1,
        poll_interval=0,
        api_token="sentinel-api-token",
    )
    settings = replace(SentinelSettings.from_env(), api_token="sentinel-api-token")

    summary = demo.run_http_demo(settings, args, client)

    assert summary["mode"] == "http"
    assert summary["status"] == "not_ready"
    assert summary["checks"][0]["name"] == "datadog.logs"
    assert demo._exit_code(summary) == 2
    assert client.get_urls == [
        "http://sentinel.example/ready/live",
        "http://sentinel.example/live/connectivity",
    ]
    assert client.get_headers[0] == {"authorization": "Bearer sentinel-api-token"}
    assert client.get_headers[1] == {"authorization": "Bearer sentinel-api-token"}
    assert client.post_urls == []


def test_http_live_demo_reports_connectivity_auth_failure():
    demo = _load_demo_script()
    client = _FakeHttpDemoClient(
        ready={"ready": True},
        connectivity={"detail": "Invalid SENTINEL API token"},
        connectivity_status_code=401,
        status={},
    )
    args = SimpleNamespace(
        base_url="http://sentinel.example",
        incident_id="PD-REMOTE",
        service="checkout-service",
        timeout_seconds=1,
        poll_interval=0,
        api_token=None,
    )

    summary = demo.run_http_demo(SentinelSettings.from_env(), args, client)

    assert summary == {
        "mode": "http",
        "base_url": "http://sentinel.example",
        "status": "connectivity_failed",
        "endpoint": "/live/connectivity",
        "code": 401,
        "body": {"detail": "Invalid SENTINEL API token"},
    }
    assert demo._exit_code(summary) == 2
    assert client.post_urls == []


def test_http_live_demo_stops_before_webhook_when_ready_success_body_is_malformed():
    demo = _load_demo_script()
    client = _FakeHttpDemoClient(
        ready={"status": "ok"},
        status={},
    )
    args = SimpleNamespace(
        base_url="http://sentinel.example",
        incident_id="PD-REMOTE",
        service="checkout-service",
        timeout_seconds=1,
        poll_interval=0,
        api_token="sentinel-api-token",
    )

    summary = demo.run_http_demo(SentinelSettings.from_env(), args, client)

    assert summary == {
        "mode": "http",
        "base_url": "http://sentinel.example",
        "status": "ready_malformed",
        "endpoint": "/ready/live",
        "body": {"status": "ok"},
    }
    assert demo._exit_code(summary) == 2
    assert client.get_urls == ["http://sentinel.example/ready/live"]
    assert client.post_urls == []


def test_http_live_demo_stops_before_webhook_when_connectivity_success_body_is_malformed():
    demo = _load_demo_script()
    client = _FakeHttpDemoClient(
        ready={"ready": True},
        connectivity={"status": "ok"},
        status={},
    )
    args = SimpleNamespace(
        base_url="http://sentinel.example",
        incident_id="PD-REMOTE",
        service="checkout-service",
        timeout_seconds=1,
        poll_interval=0,
        api_token="sentinel-api-token",
    )

    summary = demo.run_http_demo(SentinelSettings.from_env(), args, client)

    assert summary == {
        "mode": "http",
        "base_url": "http://sentinel.example",
        "status": "connectivity_malformed",
        "endpoint": "/live/connectivity",
        "body": {"status": "ok"},
    }
    assert demo._exit_code(summary) == 2
    assert client.get_urls == [
        "http://sentinel.example/ready/live",
        "http://sentinel.example/live/connectivity",
    ]
    assert client.post_urls == []


def test_inprocess_live_demo_reports_missing_credentials_with_preflight_checks(monkeypatch):
    demo = _load_demo_script()
    checks = [
        {
            "name": "sentinel.state_store",
            "provider": "sentinel",
            "passed": True,
            "duration_ms": 1.0,
            "detail": "ok",
            "sample": {"ok": True},
        }
    ]

    monkeypatch.setattr(
        demo,
        "run_live_connectivity_checks",
        lambda _settings, store=None: _FakeConnectivityReport(
            ready=False,
            missing_live_credentials=["DD_API_KEY"],
            checks=checks,
        ),
    )
    args = SimpleNamespace(
        incident_id="PD-LOCAL",
        service="checkout-service",
        timeout_seconds=1,
        poll_interval=0,
        api_token=None,
    )

    summary = demo.run_inprocess_demo(SentinelSettings.from_env(), args)

    assert summary["mode"] == "inprocess"
    assert summary["status"] == "missing_credentials"
    assert summary["missing"] == ["DD_API_KEY"]
    assert summary["checks"] == checks
    assert demo._exit_code(summary) == 2


def test_inprocess_live_demo_stops_before_webhook_when_preflight_not_ready(monkeypatch):
    demo = _load_demo_script()
    checks = [
        {
            "name": "datadog.logs",
            "provider": "datadog",
            "passed": False,
            "duration_ms": 2.0,
            "detail": "provider unavailable",
            "sample": {},
        }
    ]

    monkeypatch.setattr(
        demo,
        "run_live_connectivity_checks",
        lambda _settings, store=None: _FakeConnectivityReport(
            ready=False,
            missing_live_credentials=[],
            checks=checks,
        ),
    )
    args = SimpleNamespace(
        incident_id="PD-LOCAL",
        service="checkout-service",
        timeout_seconds=1,
        poll_interval=0,
        api_token=None,
    )

    summary = demo.run_inprocess_demo(SentinelSettings.from_env(), args)

    assert summary["mode"] == "inprocess"
    assert summary["status"] == "not_ready"
    assert summary["missing_live_credentials"] == []
    assert summary["checks"] == checks
    assert demo._exit_code(summary) == 2


def test_http_live_demo_reports_structured_poll_failure():
    demo = _load_demo_script()
    client = _FakeHttpDemoClient(
        ready={"ready": True},
        status={"detail": "missing auth"},
        status_status_code=401,
    )
    args = SimpleNamespace(
        base_url="http://sentinel.example",
        incident_id="PD-REMOTE",
        service="checkout-service",
        timeout_seconds=1,
        poll_interval=0,
        api_token="sentinel-api-token",
    )
    settings = replace(
        SentinelSettings.from_env(),
        pagerduty_webhook_secret="pd-secret",
        api_token="sentinel-api-token",
    )

    summary = demo.run_http_demo(settings, args, client)

    assert summary["mode"] == "http"
    assert summary["status"] == "poll_failed"
    assert summary["investigation_id"] == "inv-remote"
    assert "poll failed: 401" in summary["error"]
    assert demo._exit_code(summary) == 1


def test_http_live_demo_reports_structured_timeout():
    demo = _load_demo_script()
    client = _FakeHttpDemoClient(
        ready={"ready": True},
        status={
            "investigation_id": "inv-remote",
            "incident_id": "PD-REMOTE",
            "status": "running",
            "current_state": "evidence_collection",
        },
    )
    args = SimpleNamespace(
        base_url="http://sentinel.example",
        incident_id="PD-REMOTE",
        service="checkout-service",
        timeout_seconds=0,
        poll_interval=0,
        api_token="sentinel-api-token",
    )
    settings = replace(
        SentinelSettings.from_env(),
        pagerduty_webhook_secret="pd-secret",
        api_token="sentinel-api-token",
    )

    summary = demo.run_http_demo(settings, args, client)

    assert summary["mode"] == "http"
    assert summary["status"] == "timeout"
    assert summary["investigation_id"] == "inv-remote"
    assert "did not reach proposal state" in summary["error"]
    assert demo._exit_code(summary) == 1


def test_http_live_demo_reports_malformed_poll_payload_as_structured_failure():
    demo = _load_demo_script()
    client = _FakeHttpDemoClient(
        ready={"ready": True},
        status={"investigation_id": "inv-remote"},
    )
    args = SimpleNamespace(
        base_url="http://sentinel.example",
        incident_id="PD-REMOTE",
        service="checkout-service",
        timeout_seconds=1,
        poll_interval=0,
        api_token="sentinel-api-token",
    )
    settings = replace(
        SentinelSettings.from_env(),
        pagerduty_webhook_secret="pd-secret",
        api_token="sentinel-api-token",
    )

    summary = demo.run_http_demo(settings, args, client)

    assert summary["status"] == "poll_failed"
    assert "malformed investigation status" in summary["error"]
    assert demo._exit_code(summary) == 1


def test_live_demo_http_mode_derives_request_timeout_from_short_workflow_timeout(monkeypatch):
    demo = _load_demo_script()
    captured: dict[str, float] = {}

    class CapturingClient:
        def __init__(self, *, timeout):
            captured["timeout"] = timeout

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

    monkeypatch.setattr(demo.httpx, "Client", CapturingClient)
    monkeypatch.setattr(
        demo,
        "run_http_demo",
        lambda _settings, _args, _client: {"mode": "http", "status": "receiver_unreachable"},
    )
    monkeypatch.setattr(
        demo.sys,
        "argv",
        [
            "run_live_sentinel_demo.py",
            "PD-REMOTE",
            "--base-url",
            "http://sentinel.example",
            "--timeout-seconds",
            "1",
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        demo.main()

    assert exit_info.value.code == 2
    assert captured["timeout"] == 1.0


def test_live_demo_http_mode_allows_explicit_request_timeout(monkeypatch):
    demo = _load_demo_script()
    captured: dict[str, float] = {}

    class CapturingClient:
        def __init__(self, *, timeout):
            captured["timeout"] = timeout

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

    monkeypatch.setattr(demo.httpx, "Client", CapturingClient)
    monkeypatch.setattr(
        demo,
        "run_http_demo",
        lambda _settings, _args, _client: {"mode": "http", "status": "receiver_unreachable"},
    )
    monkeypatch.setattr(
        demo.sys,
        "argv",
        [
            "run_live_sentinel_demo.py",
            "PD-REMOTE",
            "--base-url",
            "http://sentinel.example",
            "--timeout-seconds",
            "1",
            "--http-timeout-seconds",
            "3.5",
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        demo.main()

    assert exit_info.value.code == 2
    assert captured["timeout"] == 3.5


def test_live_demo_reports_invalid_env_configuration(monkeypatch, capsys):
    demo = _load_demo_script()
    monkeypatch.setenv("SENTINEL_LIVE_MAX_PAGES", "0")
    monkeypatch.setattr(demo.sys, "argv", ["run_live_sentinel_demo.py", "PD-LOCAL"])

    with pytest.raises(SystemExit) as exit_info:
        demo.main()

    body = json.loads(capsys.readouterr().out)
    assert exit_info.value.code == 2
    assert body["mode"] == "inprocess"
    assert body["status"] == "invalid_config"
    assert "SENTINEL_LIVE_MAX_PAGES" in body["error"]


def test_live_demo_exit_code_requires_waiting_for_approval_boundary():
    demo = _load_demo_script()
    summary = {
        "status": "completed",
        "current_state": "response_proposal",
        "tool_calls": 24,
        "recommendation": "rollback checkout-service",
        "approval_request_id": "approval-1",
        "slack_notified": True,
        "approval_slack_notified": True,
        "rollback_attempted": False,
        "rollback_executed": False,
    }

    assert demo._exit_code(summary) == 1


def test_live_demo_exit_code_requires_approval_request():
    demo = _load_demo_script()
    summary = {
        "status": "waiting_for_approval",
        "current_state": "response_proposal",
        "tool_calls": 24,
        "recommendation": "rollback checkout-service",
        "approval_request_id": None,
        "slack_notified": True,
        "approval_slack_notified": True,
        "rollback_attempted": False,
        "rollback_executed": False,
    }

    assert demo._exit_code(summary) == 1


def test_live_demo_exit_code_rejects_rollback_before_operator_approval():
    demo = _load_demo_script()
    summary = {
        "status": "waiting_for_approval",
        "current_state": "response_proposal",
        "tool_calls": 24,
        "recommendation": "rollback checkout-service",
        "approval_request_id": "approval-1",
        "slack_notified": True,
        "approval_slack_notified": True,
        "rollback_attempted": True,
        "rollback_executed": True,
    }

    assert demo._exit_code(summary) == 1


def test_live_demo_exit_code_requires_matching_incident_id():
    demo = _load_demo_script()
    summary = {
        "requested_incident_id": "PD-REQUESTED",
        "incident_id": "PD-OTHER",
        "status": "waiting_for_approval",
        "current_state": "response_proposal",
        "tool_calls": 24,
        "recommendation": "rollback checkout-service",
        "approval_request_id": "approval-1",
        "slack_notified": True,
        "approval_slack_notified": True,
        "rollback_attempted": False,
        "rollback_executed": False,
    }

    assert demo._exit_code(summary) == 1


def test_live_demo_exit_code_requires_long_horizon_tool_execution():
    demo = _load_demo_script()
    summary = {
        "status": "waiting_for_approval",
        "current_state": "response_proposal",
        "tool_calls": 19,
        "recommendation": "rollback checkout-service",
        "approval_request_id": "approval-1",
        "slack_notified": True,
        "approval_slack_notified": True,
        "rollback_attempted": False,
        "rollback_executed": False,
    }

    assert demo._exit_code(summary) == 1


def test_live_demo_exit_code_requires_all_live_provider_proofs():
    demo = _load_demo_script()
    summary = {
        "status": "waiting_for_approval",
        "current_state": "response_proposal",
        "tool_calls": 24,
        "live_provider_proofs": {
            "datadog": 4,
            "github": 5,
            "pagerduty": 1,
            "slack": 2,
            "kubernetes": 0,
        },
        "live_tool_proofs": _tool_proofs(),
        "diagnosis": "Live evidence points to a bad deploy.",
        "confidence": "high",
        "recommendation": "rollback checkout-service",
        "approval_request_id": "approval-1",
        "approval_slack_notification_request_id": "approval-1",
        "slack_notified": True,
        "approval_slack_notified": True,
        "rollback_attempted": False,
        "rollback_executed": False,
    }

    assert demo._exit_code(summary) == 1


def test_live_demo_exit_code_requires_exact_live_tool_proofs():
    demo = _load_demo_script()
    summary = {
        "status": "waiting_for_approval",
        "current_state": "response_proposal",
        "tool_calls": 24,
        "live_provider_proofs": _provider_proofs(),
        "live_tool_proofs": {**_tool_proofs(), "repo.get_rollback_targets": 0},
        "diagnosis": "Live evidence points to a bad deploy.",
        "confidence": "high",
        "recommendation": "rollback checkout-service",
        "approval_request_id": "approval-1",
        "approval_slack_notification_request_id": "approval-1",
        "slack_notified": True,
        "approval_slack_notified": True,
        "rollback_attempted": False,
        "rollback_executed": False,
    }

    assert demo._exit_code(summary) == 1


def test_live_demo_exit_code_requires_approval_slack_notification():
    demo = _load_demo_script()
    summary = {
        "status": "waiting_for_approval",
        "current_state": "response_proposal",
        "tool_calls": 24,
        "live_provider_proofs": _provider_proofs(),
        "live_tool_proofs": _tool_proofs(),
        "diagnosis": "Live evidence points to a bad deploy.",
        "confidence": "high",
        "recommendation": "rollback checkout-service",
        "approval_request_id": "approval-1",
        "approval_slack_notification_request_id": "approval-1",
        "slack_notified": True,
        "approval_slack_notified": False,
        "rollback_attempted": False,
        "rollback_executed": False,
    }

    assert demo._exit_code(summary) == 1


def test_live_demo_exit_code_requires_current_approval_slack_notification_request():
    demo = _load_demo_script()
    summary = {
        "status": "waiting_for_approval",
        "current_state": "response_proposal",
        "tool_calls": 24,
        "live_provider_proofs": _provider_proofs(),
        "live_tool_proofs": _tool_proofs(),
        "diagnosis": "Live evidence points to a bad deploy.",
        "confidence": "high",
        "recommendation": "rollback checkout-service",
        "approval_request_id": "approval-1",
        "approval_slack_notification_request_id": "approval-1",
        "slack_notified": True,
        "approval_slack_notified": True,
        "rollback_attempted": False,
        "rollback_executed": False,
    }

    assert demo._exit_code({**summary, "approval_slack_notification_request_id": "approval-old"}) == 1
    assert demo._exit_code({**summary, "approval_slack_notification_request_id": None}) == 1
    assert demo._exit_code(summary) == 0


def test_live_demo_exit_code_requires_diagnosis_and_confidence():
    demo = _load_demo_script()
    summary = {
        "status": "waiting_for_approval",
        "current_state": "response_proposal",
        "tool_calls": 24,
        "live_provider_proofs": _provider_proofs(),
        "live_tool_proofs": _tool_proofs(),
        "diagnosis": "Live evidence points to a bad deploy.",
        "confidence": "high",
        "recommendation": "rollback checkout-service",
        "approval_request_id": "approval-1",
        "approval_slack_notification_request_id": "approval-1",
        "slack_notified": True,
        "approval_slack_notified": True,
        "rollback_attempted": False,
        "rollback_executed": False,
    }

    assert demo._exit_code({**summary, "diagnosis": None}) == 1
    assert demo._exit_code({**summary, "confidence": ""}) == 1
    assert demo._exit_code(summary) == 0


def test_live_demo_exit_code_requires_response_proposal_state():
    demo = _load_demo_script()
    summary = {
        "status": "waiting_for_approval",
        "current_state": "diagnosis",
        "tool_calls": 24,
        "recommendation": "rollback checkout-service",
        "approval_request_id": "approval-1",
        "slack_notified": True,
        "approval_slack_notified": True,
        "rollback_attempted": False,
        "rollback_executed": False,
    }

    assert demo._exit_code(summary) == 1


def test_live_demo_exit_code_rejects_failed_rollback_attempt():
    demo = _load_demo_script()
    summary = {
        "status": "waiting_for_approval",
        "current_state": "response_proposal",
        "tool_calls": 24,
        "recommendation": "rollback checkout-service",
        "approval_request_id": "approval-1",
        "slack_notified": True,
        "approval_slack_notified": True,
        "rollback_attempted": True,
        "rollback_executed": False,
    }

    assert demo._exit_code(summary) == 1


def _load_demo_script():
    spec = importlib.util.spec_from_file_location(
        "run_live_sentinel_demo",
        ROOT / "scripts" / "run_live_sentinel_demo.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _provider_proofs():
    return {
        "datadog": 6,
        "github": 5,
        "pagerduty": 1,
        "slack": 2,
        "kubernetes": 2,
    }


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


class _FakeConnectivityReport:
    def __init__(self, *, ready: bool, missing_live_credentials: list[str], checks: list[dict]):
        self.ready = ready
        self.missing_live_credentials = missing_live_credentials
        self.checks = checks

    def model_dump(self, mode: str = "python"):
        return {
            "ready": self.ready,
            "missing_live_credentials": self.missing_live_credentials,
            "checks": self.checks,
        }


class _Response:
    def __init__(self, status_code: int, body: dict):
        self.status_code = status_code
        self._body = body
        self.text = json.dumps(body)

    def json(self):
        return self._body


class _FakeHttpDemoClient:
    def __init__(
        self,
        *,
        ready: dict,
        status: dict,
        connectivity: dict | None = None,
        ready_status_code: int = 200,
        connectivity_status_code: int = 200,
        status_status_code: int = 200,
    ):
        self.ready = ready
        self.connectivity = connectivity if connectivity is not None else {"ready": True, "missing_live_credentials": [], "checks": []}
        self.status = status
        self.ready_status_code = ready_status_code
        self.connectivity_status_code = connectivity_status_code
        self.status_status_code = status_status_code
        self.get_urls: list[str] = []
        self.get_headers: list[dict[str, str]] = []
        self.post_urls: list[str] = []
        self.post_headers: list[dict[str, str]] = []
        self.post_bodies: list[str] = []

    def get(self, url: str, headers: dict[str, str] | None = None):
        self.get_urls.append(url)
        self.get_headers.append(headers or {})
        if url.endswith("/ready/live"):
            return _Response(self.ready_status_code, self.ready)
        if url.endswith("/live/connectivity"):
            return _Response(self.connectivity_status_code, self.connectivity)
        if "/investigations/" in url:
            return _Response(self.status_status_code, self.status)
        raise AssertionError(url)

    def post(self, url: str, *, content: bytes, headers: dict[str, str]):
        self.post_urls.append(url)
        self.post_headers.append(headers)
        self.post_bodies.append(content.decode())
        return _Response(200, {"accepted": True, "investigation_id": "inv-remote"})
