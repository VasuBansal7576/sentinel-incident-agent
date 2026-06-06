import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "audit_free_tier_goal.py"
spec = importlib.util.spec_from_file_location("audit_free_tier_goal", SCRIPT)
audit = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(audit)


def test_goal_audit_reports_waiting_for_discord_when_static_checks_pass():
    summary = audit.build_goal_audit(
        _args(),
        readiness_summary={
            "status": "not_ready",
            "free_provider_configured": False,
            "config_problem": {"missing": ["DISCORD_WEBHOOK_URL"]},
            "paid_provider_credentials_present": [],
            "host_prerequisites": {"passed": True},
            "receiver_check": {
                "status": "skipped",
                "reason": "free_provider_config_incomplete",
            },
            "next_commands": {
                "configure_discord": "python3 scripts/configure_discord_webhook.py --test-post",
                "check_receiver": "python3 scripts/check_free_tier_readiness.py --check-receiver",
            },
        },
    )

    assert summary["status"] == "waiting_for_live_credentials"
    assert summary["static_requirements_passed"] is True
    assert summary["readiness"]["missing"] == ["DISCORD_WEBHOOK_URL"]
    assert summary["readiness"]["receiver_check_status"] == "skipped"
    assert summary["readiness"]["receiver_check_reason"] == "free_provider_config_incomplete"
    assert summary["next_actions"][0] == "python3 scripts/configure_discord_webhook.py --test-post"
    assert audit.exit_code(summary) == 2


def test_goal_audit_reports_ready_for_demo_until_completed_demo_summary_is_provided():
    summary = audit.build_goal_audit(
        _args(),
        readiness_summary={
            "status": "ready",
            "free_provider_configured": True,
            "paid_provider_credentials_present": [],
            "host_prerequisites": {"passed": True},
            "next_commands": {
                "run_demo": (
                    "python3 scripts/run_free_tier_sentinel_demo.py FREE-DEMO-001 "
                    "--base-url http://localhost:8000 "
                    "--summary-output .sentinel/free-tier-demo-summary.json"
                ),
                "audit_goal": (
                    "python3 scripts/audit_free_tier_goal.py "
                    "--demo-summary .sentinel/free-tier-demo-summary.json"
                ),
            },
        },
    )

    assert summary["status"] == "ready_for_live_demo"
    assert summary["demo_proof"]["provided"] is False
    assert summary["next_actions"] == [
        "python3 scripts/run_free_tier_sentinel_demo.py FREE-DEMO-001 "
        "--base-url http://localhost:8000 "
        "--summary-output .sentinel/free-tier-demo-summary.json",
        "python3 scripts/audit_free_tier_goal.py "
        "--demo-summary .sentinel/free-tier-demo-summary.json",
    ]
    assert audit.exit_code(summary) == 1


def test_goal_audit_accepts_completed_free_demo_summary():
    summary = audit.build_goal_audit(
        _args(),
        readiness_summary={
            "status": "ready",
            "free_provider_configured": True,
            "paid_provider_credentials_present": [],
            "host_prerequisites": {"passed": True},
        },
        demo_summary=_completed_demo_summary(),
    )

    assert summary["status"] == "complete"
    assert summary["demo_proof"]["passed"] is True
    assert summary["demo_proof"]["current_state"] == "post_mortem"
    assert summary["demo_proof"]["notification_provider"] == "discord"
    assert summary["demo_proof"]["approval_request_id"] == "approval-1"
    assert summary["demo_proof"]["approval_slack_notification_request_id"] == "approval-1"
    assert summary["demo_proof"]["approval_slack_notified"] is True
    assert summary["demo_proof"]["approval_command_received"] is True
    assert summary["demo_proof"]["approval_command_request_id"] == "approval-1"
    assert summary["demo_proof"]["approval_command_approver_id"] == "eng-oncall"
    assert summary["demo_proof"]["approval_command_decision"] == "approve"
    assert summary["demo_proof"]["webhook_source"] == "generic_webhook"
    assert summary["demo_proof"]["generic_webhook_received"] is True
    assert summary["demo_proof"]["webhook_ingress"] == {
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
    }
    assert summary["demo_proof"]["receiver_metrics"] == {"status": "ready", "service": "payment-service"}
    assert audit.exit_code(summary) == 0


def test_goal_audit_rejects_completion_when_paid_provider_env_is_allowed_for_debugging():
    summary = audit.build_goal_audit(
        _args(allow_paid_provider_env=True),
        readiness_summary={
            "status": "ready",
            "free_provider_configured": True,
            "paid_provider_credentials_present": ["SLACK_BOT_TOKEN"],
            "paid_provider_credentials_allowed": True,
            "host_prerequisites": {"passed": True},
            "next_commands": {
                "check_receiver": "python3 scripts/check_free_tier_readiness.py --check-receiver",
            },
        },
        demo_summary=_completed_demo_summary(),
    )

    assert summary["status"] == "paid_provider_env_not_free_proof"
    assert summary["demo_proof"]["passed"] is True
    assert summary["readiness"]["paid_provider_credentials_present"] == ["SLACK_BOT_TOKEN"]
    assert summary["next_actions"][0] == "Unset paid provider credentials before final proof: SLACK_BOT_TOKEN"
    assert audit.exit_code(summary) == 2


def test_goal_audit_rejects_completed_demo_summary_with_paid_provider_proof():
    demo_summary = _completed_demo_summary()
    demo_summary["live_provider_proofs"] = {
        **demo_summary["live_provider_proofs"],
        "datadog": 1,
    }

    summary = audit.build_goal_audit(
        _args(),
        readiness_summary={
            "status": "ready",
            "free_provider_configured": True,
            "paid_provider_credentials_present": [],
            "host_prerequisites": {"passed": True},
        },
        demo_summary=demo_summary,
    )

    assert summary["status"] == "live_demo_failed"
    assert summary["demo_proof"]["passed"] is False
    assert summary["demo_proof"]["current_state"] == "post_mortem"
    assert audit.exit_code(summary) == 1


def test_goal_audit_rejects_completed_demo_summary_before_post_mortem_state():
    demo_summary = _completed_demo_summary()
    demo_summary["current_state"] = "remediation"

    summary = audit.build_goal_audit(
        _args(),
        readiness_summary={
            "status": "ready",
            "free_provider_configured": True,
            "paid_provider_credentials_present": [],
            "host_prerequisites": {"passed": True},
        },
        demo_summary=demo_summary,
    )

    assert summary["status"] == "live_demo_failed"
    assert summary["demo_proof"]["passed"] is False
    assert summary["demo_proof"]["current_state"] == "remediation"
    assert audit.exit_code(summary) == 1


def test_goal_audit_rejects_completed_demo_summary_with_stale_approval_notification():
    demo_summary = _completed_demo_summary()
    demo_summary["approval_slack_notification_request_id"] = "approval-old"

    summary = audit.build_goal_audit(
        _args(),
        readiness_summary={
            "status": "ready",
            "free_provider_configured": True,
            "paid_provider_credentials_present": [],
            "host_prerequisites": {"passed": True},
        },
        demo_summary=demo_summary,
    )

    assert summary["status"] == "live_demo_failed"
    assert summary["demo_proof"]["passed"] is False
    assert summary["demo_proof"]["approval_request_id"] == "approval-1"
    assert summary["demo_proof"]["approval_slack_notification_request_id"] == "approval-old"
    assert audit.exit_code(summary) == 1


def test_goal_audit_rejects_completed_demo_summary_with_stale_approval_command():
    demo_summary = _completed_demo_summary()
    demo_summary["approval_command_request_id"] = "approval-old"

    summary = audit.build_goal_audit(
        _args(),
        readiness_summary={
            "status": "ready",
            "free_provider_configured": True,
            "paid_provider_credentials_present": [],
            "host_prerequisites": {"passed": True},
        },
        demo_summary=demo_summary,
    )

    assert summary["status"] == "live_demo_failed"
    assert summary["demo_proof"]["passed"] is False
    assert summary["demo_proof"]["approval_request_id"] == "approval-1"
    assert summary["demo_proof"]["approval_command_request_id"] == "approval-old"
    assert audit.exit_code(summary) == 1


def test_goal_audit_static_checks_require_dry_run_writes_to_be_empty_evidence(tmp_path, monkeypatch):
    sentinel_dir = tmp_path / "sentinel"
    sentinel_dir.mkdir()
    (sentinel_dir / "models.py").write_text("class ToolResult\nclass ToolCallRecord\n")
    (sentinel_dir / "webapp.py").write_text("class WebhookRunResponse\nresponse_model=WebhookRunResponse\n_investigation_response\n")
    (sentinel_dir / "real_tools.py").write_text("ToolResult(\n_evidence_from_live_result\n")
    monkeypatch.setattr(audit, "PROJECT_ROOT", tmp_path)

    checks = audit._static_requirement_checks()
    contracts = next(check for check in checks if check["id"] == "pydantic_contracts_retained")

    assert contracts["passed"] is False
    assert {
        "file": "sentinel/real_tools.py",
        "needle": "_is_write_skipped_dry_run",
    } in contracts["missing"]


def test_goal_audit_static_checks_require_generic_webhook_ingress_proof(tmp_path, monkeypatch):
    sentinel_dir = tmp_path / "sentinel"
    sentinel_dir.mkdir()
    (sentinel_dir / "webapp.py").write_text(
        "\n".join(
            [
                '@app.post("/webhooks/generic"',
                'source="generic_webhook"',
                '"webhook_source"',
                "_run_live_investigation_safely",
                "response_model=WebhookRunResponse",
            ]
        )
    )
    (sentinel_dir / "live_clients.py").write_text('class GenericAlertClient\n"provider": "generic_webhook"\n')
    monkeypatch.setattr(audit, "PROJECT_ROOT", tmp_path)

    checks = audit._static_requirement_checks()
    generic_webhook = next(check for check in checks if check["id"] == "generic_webhook_alert_source")

    assert generic_webhook["passed"] is False
    assert {
        "file": "sentinel/webapp.py",
        "needle": '"generic_webhook_received"',
    } in generic_webhook["missing"]
    assert {
        "file": "sentinel/webapp.py",
        "needle": "class GenericWebhookRequest",
    } in generic_webhook["missing"]
    assert {
        "file": "sentinel/webapp.py",
        "needle": '_webhook_idempotency_key("generic_webhook"',
    } in generic_webhook["missing"]
    assert {
        "file": "sentinel/webapp.py",
        "needle": "commonLabels",
    } in generic_webhook["missing"]
    assert {
        "file": "sentinel/webapp.py",
        "needle": "_generic_alert_items",
    } in generic_webhook["missing"]


def test_goal_audit_static_checks_require_confirmed_discord_message_proof(tmp_path, monkeypatch):
    sentinel_dir = tmp_path / "sentinel"
    sentinel_dir.mkdir()
    (sentinel_dir / "live_clients.py").write_text(
        "\n".join(
            [
                "class DiscordWebhookClient",
                "def post_to_discord",
                'json={"content": message}',
            ]
        )
    )
    (sentinel_dir / "real_tools.py").write_text(
        "\n".join(
            [
                "def post_to_discord",
                "SLACK_BOT_TOKEN is missing",
                "DISCORD_WEBHOOK_URL",
            ]
        )
    )
    monkeypatch.setattr(audit, "PROJECT_ROOT", tmp_path)

    checks = audit._static_requirement_checks()
    discord = next(check for check in checks if check["id"] == "discord_fallback_notifications")

    assert discord["passed"] is False
    assert {
        "file": "sentinel/live_clients.py",
        "needle": "_require_discord_message_confirmation",
    } in discord["missing"]
    assert {
        "file": "sentinel/real_tools.py",
        "needle": "_count_confirmed_discord_messages",
    } in discord["missing"]


def test_goal_audit_static_checks_require_loki_entry_counting_for_observability_proof(tmp_path, monkeypatch):
    sentinel_dir = tmp_path / "sentinel"
    sentinel_dir.mkdir()
    (sentinel_dir / "live_clients.py").write_text("class PrometheusClient\nclass LokiClient\nclass DatadogClient\n")
    (sentinel_dir / "real_tools.py").write_text(
        "\n".join(
            [
                "router.clients.loki.query_range",
                'return {"provider": "loki"',
                "router.clients.prometheus.query_range",
                'return {"provider": "prometheus"',
                "router.clients.datadog.search_logs",
                "router.clients.datadog.query_metric",
                "_require_datadog_observability_fallback",
            ]
        )
    )
    monkeypatch.setattr(audit, "PROJECT_ROOT", tmp_path)

    checks = audit._static_requirement_checks()
    observability = next(check for check in checks if check["id"] == "prometheus_loki_primary_datadog_fallback")

    assert observability["passed"] is False
    assert {
        "file": "sentinel/real_tools.py",
        "needle": "_count_loki_log_entries",
    } in observability["missing"]
    assert {
        "file": "sentinel/live_clients.py",
        "needle": "def labels",
    } in observability["missing"]
    assert {
        "file": "sentinel/live_clients.py",
        "needle": 'expected_data_shape="list"',
    } in observability["missing"]
    assert {
        "file": "sentinel/live_clients.py",
        "needle": "_require_prometheus_sample_pair",
    } in observability["missing"]


def test_goal_audit_static_checks_require_guarded_datadog_observability_fallback(tmp_path, monkeypatch):
    sentinel_dir = tmp_path / "sentinel"
    sentinel_dir.mkdir()
    (sentinel_dir / "live_clients.py").write_text("class PrometheusClient\nclass LokiClient\nclass DatadogClient\n")
    (sentinel_dir / "real_tools.py").write_text(
        "\n".join(
            [
                "router.clients.loki.query_range",
                'return {"provider": "loki"',
                "_count_loki_log_entries",
                "router.clients.prometheus.query_range",
                'return {"provider": "prometheus"',
                "router.clients.datadog.search_logs",
                "router.clients.datadog.query_metric",
            ]
        )
    )
    monkeypatch.setattr(audit, "PROJECT_ROOT", tmp_path)

    checks = audit._static_requirement_checks()
    observability = next(check for check in checks if check["id"] == "prometheus_loki_primary_datadog_fallback")

    assert observability["passed"] is False
    assert {
        "file": "sentinel/real_tools.py",
        "needle": "_require_datadog_observability_fallback",
    } in observability["missing"]


def test_goal_audit_static_checks_require_demo_memory_metric_alignment(tmp_path, monkeypatch):
    sentinel_dir = tmp_path / "sentinel"
    sentinel_dir.mkdir()
    (sentinel_dir / "live_clients.py").write_text("class PrometheusClient\nclass LokiClient\nclass DatadogClient\n")
    (sentinel_dir / "real_tools.py").write_text(
        "\n".join(
            [
                "router.clients.loki.query_range",
                'return {"provider": "loki"',
                "_count_loki_log_entries",
                "router.clients.prometheus.query_range",
                'return {"provider": "prometheus"',
                "router.clients.datadog.search_logs",
                "router.clients.datadog.query_metric",
                "_require_datadog_observability_fallback",
            ]
        )
    )
    monkeypatch.setattr(audit, "PROJECT_ROOT", tmp_path)

    checks = audit._static_requirement_checks()
    observability = next(check for check in checks if check["id"] == "prometheus_loki_primary_datadog_fallback")

    assert observability["passed"] is False
    assert {
        "file": "sentinel/real_tools.py",
        "needle": "container_memory_working_set_bytes",
    } in observability["missing"]


def test_goal_audit_static_checks_require_prometheus_alerting_and_dashboard_routing(tmp_path, monkeypatch):
    sentinel_dir = tmp_path / "sentinel"
    sentinel_dir.mkdir()
    (sentinel_dir / "live_clients.py").write_text("class PrometheusClient\nclass LokiClient\nclass DatadogClient\n")
    (sentinel_dir / "real_tools.py").write_text(
        "\n".join(
            [
                "router.clients.loki.query_range",
                'return {"provider": "loki"',
                "_count_loki_log_entries",
                "router.clients.prometheus.query_range",
                'return {"provider": "prometheus"',
                "container_memory_working_set_bytes",
                "router.clients.datadog.search_logs",
                "router.clients.datadog.query_metric",
                "_require_datadog_observability_fallback",
            ]
        )
    )
    monkeypatch.setattr(audit, "PROJECT_ROOT", tmp_path)

    checks = audit._static_requirement_checks()
    observability = next(check for check in checks if check["id"] == "prometheus_loki_primary_datadog_fallback")

    assert observability["passed"] is False
    assert {
        "file": "sentinel/real_tools.py",
        "needle": "router.clients.prometheus.alerting_rules",
    } in observability["missing"]
    assert {
        "file": "sentinel/real_tools.py",
        "needle": "router.clients.prometheus.targets",
    } in observability["missing"]
    assert {
        "file": "sentinel/real_tools.py",
        "needle": "router.clients.datadog.list_monitors",
    } in observability["missing"]
    assert {
        "file": "sentinel/real_tools.py",
        "needle": "router.clients.datadog.get_dashboard",
    } in observability["missing"]


def test_goal_audit_static_checks_require_loki_shared_circuit_breaker(tmp_path, monkeypatch):
    sentinel_dir = tmp_path / "sentinel"
    sentinel_dir.mkdir()
    (sentinel_dir / "real_tools.py").write_text("for attempt in range\n_retry_delay_seconds\nToolExecutionError\n")
    (sentinel_dir / "live_clients.py").write_text(
        "\n".join(
            [
                "SharedRateLimiter",
                'shared_circuit_breaker("prometheus")',
                'shared_circuit_breaker("discord")',
                'shared_circuit_breaker("generic_webhook")',
            ]
        )
    )
    (sentinel_dir / "store.py").write_text("audit_events\ntool_calls\nappend_audit_event\n")
    monkeypatch.setattr(audit, "PROJECT_ROOT", tmp_path)

    checks = audit._static_requirement_checks()
    reliability = next(check for check in checks if check["id"] == "shared_reliability_and_audit")

    assert reliability["passed"] is False
    assert {
        "file": "sentinel/live_clients.py",
        "needle": 'shared_circuit_breaker("loki")',
    } in reliability["missing"]


def test_goal_audit_static_checks_require_service_metric_free_demo_proof(tmp_path, monkeypatch):
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    (scripts_dir / "run_free_tier_sentinel_demo.py").write_text(
        "\n".join(
            [
                "MIN_COMPLETED_TOOL_CALLS = 26",
                "REQUIRED_FREE_PROVIDERS = ('prometheus', 'loki', 'github', 'generic_webhook', 'discord', 'kubernetes')",
                '"prometheus"',
                '"loki"',
                '"generic_webhook"',
                "_generic_webhook_ingress_ready",
                '"discord"',
                "PAID_PROVIDER_ENV_VARS = ()",
                "PAID_PROVIDER_PROOF_NAMES = ()",
                "DISCORD_WEBHOOK_HOSTS = frozenset()",
            ]
        )
    )
    monkeypatch.setattr(audit, "PROJECT_ROOT", tmp_path)

    checks = audit._static_requirement_checks()
    free_demo = next(check for check in checks if check["id"] == "free_demo_requires_only_free_providers")

    assert free_demo["passed"] is False
    assert {
        "file": "scripts/run_free_tier_sentinel_demo.py",
        "needle": "sentinel_demo_info",
    } in free_demo["missing"]
    assert {
        "file": "scripts/run_free_tier_sentinel_demo.py",
        "needle": '"commonLabels"',
    } in free_demo["missing"]
    assert {
        "file": "scripts/run_free_tier_sentinel_demo.py",
        "needle": '"fingerprint"',
    } in free_demo["missing"]
    assert {
        "file": "scripts/run_free_tier_sentinel_demo.py",
        "needle": "requested_service",
    } in free_demo["missing"]
    assert {
        "file": "scripts/run_free_tier_sentinel_demo.py",
        "needle": "affected_services",
    } in free_demo["missing"]
    assert {
        "file": "scripts/run_free_tier_sentinel_demo.py",
        "needle": "receiver_metrics_missing_service_series",
    } in free_demo["missing"]
    assert {
        "file": "scripts/run_free_tier_sentinel_demo.py",
        "needle": "DD_CLIENT_SECRET",
    } in free_demo["missing"]
    assert {
        "file": "scripts/run_free_tier_sentinel_demo.py",
        "needle": "PAGERDUTY_WEBHOOK_SECRET",
    } in free_demo["missing"]
    assert {
        "file": "scripts/run_free_tier_sentinel_demo.py",
        "needle": "SLACK_CLIENT_SECRET",
    } in free_demo["missing"]
    assert {
        "file": "scripts/run_free_tier_sentinel_demo.py",
        "needle": "SENTINEL_GITHUB_WRITE_ENABLED",
    } in free_demo["missing"]
    assert {
        "file": "scripts/run_free_tier_sentinel_demo.py",
        "needle": "github_write_enabled",
    } in free_demo["missing"]


def test_goal_audit_static_checks_require_connectivity_service_metric_proof(tmp_path, monkeypatch):
    sentinel_dir = tmp_path / "sentinel"
    sentinel_dir.mkdir()
    (sentinel_dir / "connectivity.py").write_text(
        "\n".join(
            [
                '"prometheus.metrics"',
                "def _prometheus_label_value(value): return value",
            ]
        )
    )
    monkeypatch.setattr(audit, "PROJECT_ROOT", tmp_path)

    checks = audit._static_requirement_checks()
    connectivity = next(check for check in checks if check["id"] == "live_connectivity_free_metric_proof")

    assert connectivity["passed"] is False
    assert {
        "file": "sentinel/connectivity.py",
        "needle": "sentinel_demo_info",
    } in connectivity["missing"]


def test_goal_audit_loads_demo_summary_file(tmp_path):
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(json.dumps(_completed_demo_summary()))

    summary = audit.build_goal_audit(
        _args(demo_summary=str(summary_path)),
        readiness_summary={
            "status": "ready",
            "free_provider_configured": True,
            "paid_provider_credentials_present": [],
            "host_prerequisites": {"passed": True},
        },
    )

    assert summary["status"] == "complete"
    assert summary["demo_proof"]["tool_calls"] == 30


def _args(**overrides):
    values = {
        "demo_summary": None,
        "env_file": ".env",
        "base_url": "http://localhost:8000",
        "timeout_seconds": 20.0,
        "check_receiver": False,
        "skip_host_tool_check": True,
        "skip_kind_bootstrap": True,
        "allow_paid_provider_env": False,
        "allow_local_discord_webhook": False,
        "allow_non_kind_context": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _completed_demo_summary():
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
        "receiver_metrics": {"status": "ready", "service": "payment-service"},
        "approval_request_id": "approval-1",
        "approval_approver_ids": ["eng-oncall"],
        "approval_slack_notification_request_id": "approval-1",
        "approval_slack_notified": True,
        "approval_command_received": True,
        "approval_command_request_id": "approval-1",
        "approval_command_approver_id": "eng-oncall",
        "approval_command_decision": "approve",
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
        "rollback_attempted": True,
        "rollback_executed": True,
        "approval_submitted": True,
        "remediation_result": {"status": "executed"},
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
