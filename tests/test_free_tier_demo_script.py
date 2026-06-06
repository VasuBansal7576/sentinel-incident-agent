import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import httpx


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_free_tier_sentinel_demo.py"
spec = importlib.util.spec_from_file_location("run_free_tier_sentinel_demo", SCRIPT)
demo = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(demo)


def test_free_tier_demo_payload_targets_generic_webhook():
    payload = demo._generic_payload("FREE-1", "payment-service")

    assert "incident_id" not in payload
    assert payload["receiver"] == "sentinel"
    assert payload["source"] == "alertmanager"
    assert payload["status"] == "firing"
    assert payload["commonLabels"]["service"] == "payment-service"
    assert payload["groupLabels"] == {
        "alertname": "SentinelFreeTierDemo",
        "service": "payment-service",
    }
    assert payload["alerts"][0]["fingerprint"] == "FREE-1"
    assert payload["alerts"][0]["labels"] == {
        "alertname": "SentinelFreeTierDemo",
        "severity": "critical",
        "service": "payment-service",
        "app": "payment-service",
    }


def test_free_tier_demo_detects_paid_provider_env_vars(monkeypatch):
    monkeypatch.setenv("DD_API_KEY", "dd-secret")
    monkeypatch.setenv("DD_CLIENT_SECRET", "dd-oauth-client-secret")
    monkeypatch.setenv("PAGERDUTY_API_KEY", "pd-secret")
    monkeypatch.setenv("PAGERDUTY_WEBHOOK_SECRET", "pd-webhook-secret")
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-secret")
    monkeypatch.setenv("SLACK_CLIENT_SECRET", "slack-oauth-client-secret")
    monkeypatch.setenv("GITHUB_TOKEN", "gh-free-path-still-allowed")

    assert demo._configured_paid_provider_env_vars() == [
        "DD_API_KEY",
        "DD_CLIENT_SECRET",
        "PAGERDUTY_API_KEY",
        "PAGERDUTY_WEBHOOK_SECRET",
        "SLACK_BOT_TOKEN",
        "SLACK_CLIENT_SECRET",
    ]


def test_free_tier_demo_loads_env_file_without_overriding_shell_env(tmp_path):
    env_file = tmp_path / ".env.free"
    env_file.write_text(
        "\n".join(
            [
                "SENTINEL_API_TOKEN=file-token",
                "export SENTINEL_APPROVER_ID='eng-oncall'",
                'DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/123/token"',
                "GITHUB_TOKEN=file-gh-token",
            ]
        )
    )
    env = {"GITHUB_TOKEN": "shell-gh-token"}

    loaded = demo._load_env_file(env_file, environ=env)

    assert loaded == {
        "SENTINEL_API_TOKEN": "file-token",
        "SENTINEL_APPROVER_ID": "eng-oncall",
        "DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/123/token",
    }
    assert env["SENTINEL_API_TOKEN"] == "file-token"
    assert env["SENTINEL_APPROVER_ID"] == "eng-oncall"
    assert env["DISCORD_WEBHOOK_URL"] == "https://discord.com/api/webhooks/123/token"
    assert env["GITHUB_TOKEN"] == "shell-gh-token"


def test_free_tier_demo_env_file_argument_is_preparsed():
    assert demo._env_file_from_argv(["--env-file", "/tmp/demo.env", "FREE-1"]) == "/tmp/demo.env"
    assert demo._env_file_from_argv(["--env-file=/tmp/demo.env", "FREE-1"]) == "/tmp/demo.env"
    assert demo._env_file_from_argv(["FREE-1"]) is None


def test_free_tier_demo_rejects_malformed_env_line(tmp_path):
    env_file = tmp_path / ".env.bad"
    env_file.write_text("not-a-valid-line\n")

    try:
        demo._load_env_file(env_file)
    except ValueError as exc:
        assert ".env.bad:1" in str(exc)
        assert "KEY=VALUE" in str(exc)
    else:
        raise AssertionError("expected malformed .env line to fail")


def test_free_tier_demo_writes_summary_output_with_private_permissions(tmp_path):
    summary_path = tmp_path / "nested" / "free-demo-summary.json"
    summary = {"status": "completed", "tool_calls": 30}

    written = demo._write_summary_output(summary, summary_path)

    assert written == str(summary_path)
    assert json.loads(summary_path.read_text()) == summary
    assert oct(summary_path.stat().st_mode & 0o777) == "0o600"


def test_free_tier_demo_exit_code_marks_paid_provider_env_as_preflight_failure():
    assert demo._exit_code({"status": "paid_provider_credentials_present"}, proposal_only=False) == 2


def test_free_tier_demo_reports_missing_free_provider_config():
    settings = _settings(
        api_token=None,
        prometheus_url=None,
        loki_url=None,
        discord_webhook_url=None,
        approver_id=None,
        github_token=None,
        github_owner=None,
        github_repo=None,
    )

    problem = demo._free_tier_config_problem(settings, SimpleNamespace(skip_kind_bootstrap=True))

    assert problem == {
        "status": "missing_free_tier_config",
        "message": "Free-tier demo requires Prometheus, Loki, GitHub, Discord, generic approver, operator auth, and host kind access before it can prove the end-to-end path.",
        "missing": [
            "SENTINEL_API_TOKEN",
            "PROMETHEUS_URL",
            "LOKI_URL",
            "DISCORD_WEBHOOK_URL",
            "SENTINEL_APPROVER_ID",
            "GITHUB_TOKEN",
            "GITHUB_OWNER",
            "GITHUB_REPO",
        ],
    }
    assert demo._exit_code(problem, proposal_only=False) == 2


def test_free_tier_demo_preflight_accepts_complete_free_config(monkeypatch):
    monkeypatch.delenv("HOST_KUBECONFIG", raising=False)
    settings = _settings()

    assert demo._free_tier_config_problem(settings, SimpleNamespace(skip_kind_bootstrap=True)) is None


def test_free_tier_demo_preflight_rejects_github_write_mode_for_final_free_proof(monkeypatch):
    monkeypatch.delenv("HOST_KUBECONFIG", raising=False)
    settings = _settings(github_write_enabled=True)

    problem = demo._free_tier_config_problem(settings, SimpleNamespace(skip_kind_bootstrap=True))

    assert problem["status"] == "missing_free_tier_config"
    assert problem["missing"] == []
    assert problem["invalid"] == [
        {
            "name": "SENTINEL_GITHUB_WRITE_ENABLED",
            "value": "true",
            "message": (
                "SENTINEL_GITHUB_WRITE_ENABLED must be false for final free-tier demo proof; "
                "the demo uses live GitHub read evidence and kind for remediation."
            ),
        }
    ]


def test_free_tier_demo_preflight_rejects_local_discord_webhook_without_explicit_flag(monkeypatch):
    monkeypatch.delenv("HOST_KUBECONFIG", raising=False)
    settings = _settings(discord_webhook_url="http://127.0.0.1:8765/webhook")

    problem = demo._free_tier_config_problem(
        settings,
        SimpleNamespace(skip_kind_bootstrap=True, allow_local_discord_webhook=False),
    )

    assert problem["status"] == "missing_free_tier_config"
    assert problem["missing"] == []
    assert problem["invalid"] == [
        {
            "name": "DISCORD_WEBHOOK_URL",
            "host": "127.0.0.1",
            "message": (
                "DISCORD_WEBHOOK_URL must point to https://discord.com/api/webhooks/... "
                "for final proof; pass --allow-local-discord-webhook only for local stub testing."
            ),
        }
    ]


def test_free_tier_demo_preflight_allows_local_discord_webhook_for_stub_testing(monkeypatch):
    monkeypatch.delenv("HOST_KUBECONFIG", raising=False)
    settings = _settings(discord_webhook_url="http://127.0.0.1:8765/webhook")

    assert (
        demo._free_tier_config_problem(
            settings,
            SimpleNamespace(skip_kind_bootstrap=True, allow_local_discord_webhook=True),
        )
        is None
    )


def test_free_tier_demo_uses_host_kubeconfig_for_local_kind_bootstrap(monkeypatch, tmp_path):
    host_kubeconfig = tmp_path / "kind-config"
    host_kubeconfig.write_text("apiVersion: v1\n")
    monkeypatch.setenv("HOST_KUBECONFIG", str(host_kubeconfig))
    settings = _settings(kubeconfig="/root/.kube/config")

    assert demo._host_kubeconfig(settings) == str(host_kubeconfig)
    assert demo._free_tier_config_problem(settings, SimpleNamespace(skip_kind_bootstrap=False)) is None


def test_free_tier_demo_reports_missing_host_kubeconfig_path(monkeypatch, tmp_path):
    missing_kubeconfig = tmp_path / "missing-kubeconfig"
    monkeypatch.setenv("HOST_KUBECONFIG", str(missing_kubeconfig))
    settings = _settings(kubeconfig="/root/.kube/config")

    problem = demo._free_tier_config_problem(settings, SimpleNamespace(skip_kind_bootstrap=False))

    assert problem["status"] == "missing_free_tier_config"
    assert problem["missing"] == []
    assert problem["invalid"] == [
        {
            "name": "HOST_KUBECONFIG",
            "value": str(missing_kubeconfig),
            "message": "Host-side kubeconfig path does not exist.",
        }
    ]


def test_free_tier_demo_wraps_kind_bootstrap_failures(monkeypatch):
    args = SimpleNamespace(
        skip_kind_bootstrap=False,
        skip_observability_seed=True,
    )
    bootstrap_failure = {"status": "failed", "stderr": "current-context is not set"}
    monkeypatch.setattr(demo, "_bootstrap_kind_deployment", lambda _settings, _args: bootstrap_failure)

    result = demo.run_demo(_settings(), args, client=None, base_url="http://localhost:8000", operator_headers={})

    assert result == {
        "status": "kind_bootstrap_failed",
        "kind_bootstrap": bootstrap_failure,
    }


def test_free_tier_demo_waits_for_service_demo_info_metric():
    captured = []

    class Client:
        def get(self, url, params=None):
            captured.append((url, params))
            return httpx.Response(
                200,
                json={"status": "success", "data": {"result": [{"metric": {"service": "payment-service"}}]}},
            )

    summary = demo._wait_for_prometheus_metric(Client(), "http://localhost:9090", 'pay"ment\\service', 10)

    assert summary == {
        "status": "ready",
        "query": 'sentinel_demo_info{service="pay\\"ment\\\\service"}',
        "series": 1,
    }
    assert captured == [
        (
            "http://localhost:9090/api/v1/query",
            {"query": 'sentinel_demo_info{service="pay\\"ment\\\\service"}'},
        )
    ]


def test_free_tier_demo_prometheus_label_round_trip_preserves_escape_sequences():
    values = [
        "slash\\svc",
        "slash\\nsvc",
        "line\nsvc",
        'quote"svc',
    ]

    for value in values:
        escaped = demo._prometheus_label_value(value)
        assert demo._prometheus_unescape_label_value(escaped) == value


def test_free_tier_demo_seeds_receiver_metrics_before_prometheus_and_loki(monkeypatch):
    calls = []

    class Client:
        def get(self, url):
            calls.append(("receiver", url))
            return httpx.Response(200, text='sentinel_demo_info{service="payment-service"} 1\n')

    def wait_for_prometheus(_client, _prometheus_url, service, _poll_seconds):
        calls.append(("prometheus", service))
        return {"status": "ready", "query": 'sentinel_demo_info{service="payment-service"}', "series": 1}

    def push_loki(_client, _loki_url, service, incident_id):
        calls.append(("loki", service, incident_id))
        return {"status": "ready", "streams": 1}

    monkeypatch.setattr(demo, "_wait_for_prometheus_metric", wait_for_prometheus)
    monkeypatch.setattr(demo, "_push_loki_demo_logs", push_loki)

    summary = demo._seed_free_observability(
        Client(),
        SimpleNamespace(
            prometheus_url="http://localhost:9090",
            loki_url="http://localhost:3100",
            service="payment-service",
            incident_id="FREE-1",
            poll_seconds=10,
        ),
        "http://localhost:8000",
    )

    assert summary["status"] == "ready"
    assert summary["receiver_metrics"] == {"status": "ready", "service": "payment-service"}
    assert calls == [
        ("receiver", "http://localhost:8000/metrics"),
        ("prometheus", "payment-service"),
        ("loki", "payment-service", "FREE-1"),
    ]


def test_free_tier_demo_reports_missing_receiver_service_metric():
    class Client:
        def get(self, _url):
            return httpx.Response(
                200,
                text=(
                    'sentinel_demo_info{service="other-service"} 1\n'
                    'sentinel_demo_info{service="quote\\"svc"} 1\n'
                    'sentinel_demo_info{service="slash\\\\svc"} 1\n'
                    'sentinel_demo_info{service="slash\\\\nsvc"} 1\n'
                ),
            )

    summary = demo._receiver_metrics_ready(Client(), "http://localhost:8000", "payment-service")

    assert summary == {
        "status": "receiver_metrics_missing_service_series",
        "service": "payment-service",
        "expected": 'sentinel_demo_info{service="payment-service"} 1',
        "available_services": ["other-service", 'quote"svc', "slash\\nsvc", "slash\\svc"],
    }
    assert demo._exit_code(summary, proposal_only=False) == 2


def test_free_tier_demo_exit_code_accepts_completed_free_provider_run():
    summary = {
        "status": "completed",
        "current_state": "post_mortem",
        "requested_incident_id": "FREE-1",
        "requested_service": "payment-service",
        "incident_id": "FREE-1",
        "tool_calls": 30,
        "diagnosis": "Live evidence points to deployment regression.",
        "confidence": "medium",
        "recommendation": "rollback payment-service to revision:2",
        "notification_provider": "discord",
        "discord_notified": True,
        "approval_request_id": "approval-1",
        "approval_slack_notification_request_id": "approval-1",
        "approval_slack_notified": True,
        **_approval_command_fields(),
        "rollback_attempted": True,
        "rollback_executed": True,
        "approval_submitted": True,
        "remediation_result": {"status": "executed"},
        **_generic_webhook_ingress_fields(),
        "live_provider_proofs": {
            "prometheus": 3,
            "loki": 4,
            "github": 3,
            "generic_webhook": 1,
            "discord": 2,
            "kubernetes": 3,
        },
        "live_tool_proofs": {
            "observe.fetch_service_logs": 1,
            "observe.get_error_rate_timeseries": 1,
            "observe.fetch_apm_data": 1,
            "repo.get_deploy_history": 1,
            "repo.get_rollback_targets": 1,
            "observe.check_pod_health": 1,
            "comms.page_oncall_engineer": 1,
            "comms.post_to_slack": 1,
            "infra.rollback_deployment": 1,
        },
    }

    assert demo._exit_code(summary, proposal_only=False) == 0


def test_free_tier_demo_exit_code_rejects_completed_run_before_post_mortem_state():
    summary = _completed_free_summary()
    summary["current_state"] = "remediation"

    assert demo._exit_code(summary, proposal_only=False) == 1


def test_free_tier_demo_exit_code_rejects_completed_run_without_approval_notification_proof():
    summary = _completed_free_summary()

    assert demo._exit_code({**summary, "approval_slack_notified": False}, proposal_only=False) == 1
    assert demo._exit_code({**summary, "approval_slack_notification_request_id": "approval-old"}, proposal_only=False) == 1
    assert demo._exit_code({**summary, "approval_slack_notification_request_id": None}, proposal_only=False) == 1


def test_free_tier_demo_exit_code_rejects_completed_run_without_matching_approval_command_proof():
    summary = _completed_free_summary()

    assert demo._exit_code({**summary, "approval_command_received": False}, proposal_only=False) == 1
    assert demo._exit_code({**summary, "approval_command_request_id": "approval-old"}, proposal_only=False) == 1
    assert demo._exit_code({**summary, "approval_command_approver_id": "random-user"}, proposal_only=False) == 1
    assert demo._exit_code({**summary, "approval_command_decision": "reject"}, proposal_only=False) == 1
    assert demo._exit_code({**summary, "approval_approver_ids": []}, proposal_only=False) == 1


def test_free_tier_demo_exit_code_rejects_completed_run_without_generic_webhook_ingress_proof():
    summary = _completed_free_summary()

    assert demo._exit_code({**summary, "webhook_source": "pagerduty"}, proposal_only=False) == 1
    assert demo._exit_code({**summary, "generic_webhook_received": False}, proposal_only=False) == 1
    assert demo._exit_code({**summary, "webhook_ingress": {"source": "generic_webhook"}}, proposal_only=False) == 1
    missing_alertmanager_keys = _completed_free_summary()
    missing_alertmanager_keys["webhook_ingress"] = {
        "source": "generic_webhook",
        "incident_id": "FREE-1",
        "affected_services": ["payment-service"],
        "payload_keys": ["incident_id", "labels", "service", "source"],
    }
    assert demo._exit_code(missing_alertmanager_keys, proposal_only=False) == 1
    missing_service = _completed_free_summary()
    missing_service["webhook_ingress"] = {
        **missing_service["webhook_ingress"],
        "affected_services": ["other-service"],
    }
    assert demo._exit_code(missing_service, proposal_only=False) == 1


def test_free_tier_demo_exit_code_rejects_mixed_paid_provider_proofs():
    summary = {
        "status": "completed",
        "current_state": "post_mortem",
        "requested_incident_id": "FREE-1",
        "requested_service": "payment-service",
        "incident_id": "FREE-1",
        "tool_calls": 30,
        "diagnosis": "Live evidence points to deployment regression.",
        "confidence": "medium",
        "recommendation": "rollback payment-service to revision:2",
        "notification_provider": "discord",
        "discord_notified": True,
        "approval_request_id": "approval-1",
        "approval_slack_notification_request_id": "approval-1",
        "approval_slack_notified": True,
        **_approval_command_fields(),
        "rollback_attempted": True,
        "rollback_executed": True,
        "approval_submitted": True,
        "remediation_result": {"status": "executed"},
        **_generic_webhook_ingress_fields(),
        "live_provider_proofs": {
            "prometheus": 3,
            "loki": 4,
            "github": 3,
            "generic_webhook": 1,
            "discord": 2,
            "kubernetes": 3,
            "datadog": 1,
        },
        "live_tool_proofs": {
            "observe.fetch_service_logs": 1,
            "observe.get_error_rate_timeseries": 1,
            "observe.fetch_apm_data": 1,
            "repo.get_deploy_history": 1,
            "repo.get_rollback_targets": 1,
            "observe.check_pod_health": 1,
            "comms.page_oncall_engineer": 1,
            "comms.post_to_slack": 1,
            "infra.rollback_deployment": 1,
        },
    }

    assert demo._exit_code(summary, proposal_only=False) == 1


def test_free_tier_demo_proposal_only_rejects_mixed_paid_provider_proofs():
    summary = {
        "status": "waiting_for_approval",
        "current_state": "response_proposal",
        "requested_incident_id": "FREE-1",
        "requested_service": "payment-service",
        "incident_id": "FREE-1",
        "tool_calls": 20,
        "diagnosis": "Live evidence points to deployment regression.",
        "confidence": "medium",
        "recommendation": "rollback payment-service to revision:2",
        "approval_request_id": "approval-1",
        "approval_slack_notification_request_id": "approval-1",
        "approval_slack_notified": True,
        "notification_provider": "discord",
        "discord_notified": True,
        "rollback_attempted": False,
        "rollback_executed": False,
        **_generic_webhook_ingress_fields(),
        "live_provider_proofs": {
            "prometheus": 3,
            "loki": 4,
            "github": 3,
            "generic_webhook": 1,
            "discord": 2,
            "kubernetes": 3,
            "pagerduty": 1,
        },
        "live_tool_proofs": {
            "observe.fetch_service_logs": 1,
            "observe.get_error_rate_timeseries": 1,
            "observe.fetch_apm_data": 1,
            "repo.get_deploy_history": 1,
            "repo.get_rollback_targets": 1,
            "observe.check_pod_health": 1,
            "comms.page_oncall_engineer": 1,
            "comms.post_to_slack": 1,
        },
    }

    assert demo._exit_code(summary, proposal_only=True) == 1


def test_free_tier_demo_exit_code_rejects_paid_provider_proofs_only():
    summary = {
        "status": "completed",
        "current_state": "post_mortem",
        "requested_incident_id": "FREE-1",
        "requested_service": "payment-service",
        "incident_id": "FREE-1",
        "tool_calls": 30,
        "diagnosis": "Live evidence points to deployment regression.",
        "confidence": "medium",
        "recommendation": "rollback payment-service to revision:2",
        "notification_provider": "slack",
        "discord_notified": False,
        "approval_request_id": "approval-1",
        "approval_slack_notification_request_id": "approval-1",
        "approval_slack_notified": True,
        **_approval_command_fields(),
        "rollback_attempted": True,
        "rollback_executed": True,
        "approval_submitted": True,
        "remediation_result": {"status": "executed"},
        **_generic_webhook_ingress_fields(),
        "live_provider_proofs": {
            "datadog": 3,
            "github": 3,
            "pagerduty": 1,
            "slack": 2,
            "kubernetes": 3,
        },
        "live_tool_proofs": {
            "observe.fetch_service_logs": 1,
            "observe.get_error_rate_timeseries": 1,
            "observe.fetch_apm_data": 1,
            "repo.get_deploy_history": 1,
            "repo.get_rollback_targets": 1,
            "observe.check_pod_health": 1,
            "comms.page_oncall_engineer": 1,
            "comms.post_to_slack": 1,
            "infra.rollback_deployment": 1,
        },
    }

    assert demo._exit_code(summary, proposal_only=False) == 1


def _settings(**overrides):
    values = {
        "api_token": "sentinel-token",
        "prometheus_url": "http://prometheus:9090",
        "loki_url": "http://loki:3100",
        "discord_webhook_url": "https://discord.com/api/webhooks/123/token",
        "approver_id": "eng-oncall",
        "github_token": "gh-token",
        "github_owner": "owner",
        "github_repo": "repo",
        "github_write_enabled": False,
        "kubeconfig": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _completed_free_summary():
    return {
        "status": "completed",
        "current_state": "post_mortem",
        "requested_incident_id": "FREE-1",
        "requested_service": "payment-service",
        "incident_id": "FREE-1",
        "tool_calls": 30,
        "diagnosis": "Live evidence points to deployment regression.",
        "confidence": "medium",
        "recommendation": "rollback payment-service to revision:2",
        "notification_provider": "discord",
        "discord_notified": True,
        "approval_request_id": "approval-1",
        "approval_slack_notification_request_id": "approval-1",
        "approval_slack_notified": True,
        **_approval_command_fields(),
        "rollback_attempted": True,
        "rollback_executed": True,
        "approval_submitted": True,
        "remediation_result": {"status": "executed"},
        **_generic_webhook_ingress_fields(),
        "live_provider_proofs": {
            "prometheus": 3,
            "loki": 4,
            "github": 3,
            "generic_webhook": 1,
            "discord": 2,
            "kubernetes": 3,
        },
        "live_tool_proofs": {
            "observe.fetch_service_logs": 1,
            "observe.get_error_rate_timeseries": 1,
            "observe.fetch_apm_data": 1,
            "repo.get_deploy_history": 1,
            "repo.get_rollback_targets": 1,
            "observe.check_pod_health": 1,
            "comms.page_oncall_engineer": 1,
            "comms.post_to_slack": 1,
            "infra.rollback_deployment": 1,
        },
    }


def _generic_webhook_ingress_fields():
    return {
        "webhook_source": "generic_webhook",
        "generic_webhook_received": True,
        "webhook_ingress": {
            "source": "generic_webhook",
            "incident_id": "FREE-1",
            "affected_services": ["payment-service"],
            "payload_keys": [
                "alerts",
                "commonAnnotations",
                "commonLabels",
                "groupKey",
                "groupLabels",
                "receiver",
                "source",
                "status",
            ],
        },
    }


def _approval_command_fields():
    return {
        "approval_approver_ids": ["eng-oncall"],
        "approval_command_received": True,
        "approval_command_request_id": "approval-1",
        "approval_command_approver_id": "eng-oncall",
        "approval_command_decision": "approve",
    }
