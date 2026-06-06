from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(SCRIPT_DIR))

import check_free_tier_readiness as readiness
import run_free_tier_sentinel_demo as free_demo
from sentinel.errors import redact_sensitive_text


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Audit SENTINEL's free-tier implementation and live-demo completion gate."
    )
    parser.add_argument("--env-file", default=os.getenv("SENTINEL_ENV_FILE") or str(PROJECT_ROOT / ".env"))
    parser.add_argument("--base-url", default=os.getenv("SENTINEL_BASE_URL", "http://localhost:8000"))
    parser.add_argument("--timeout-seconds", type=float, default=20.0)
    parser.add_argument("--check-receiver", action="store_true")
    parser.add_argument("--skip-host-tool-check", action="store_true")
    parser.add_argument("--skip-kind-bootstrap", action="store_true")
    parser.add_argument("--allow-paid-provider-env", action="store_true")
    parser.add_argument("--allow-local-discord-webhook", action="store_true")
    parser.add_argument("--allow-non-kind-context", action="store_true")
    parser.add_argument(
        "--demo-summary",
        default=None,
        help="Optional JSON output from run_free_tier_sentinel_demo.py. Required before the audit can report complete.",
    )
    args = parser.parse_args(argv)

    try:
        summary = build_goal_audit(args)
    except Exception as exc:
        summary = {
            "status": "audit_error",
            "error": redact_sensitive_text(exc, max_length=500),
        }
        print(json.dumps(summary, indent=2))
        raise SystemExit(2) from exc

    print(json.dumps(summary, indent=2))
    raise SystemExit(exit_code(summary))


def build_goal_audit(
    args: argparse.Namespace,
    *,
    readiness_summary: dict[str, Any] | None = None,
    demo_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    static_checks = _static_requirement_checks()
    static_passed = all(check["passed"] for check in static_checks)
    if readiness_summary is None:
        readiness_summary = _readiness_summary(args)
    if demo_summary is None and getattr(args, "demo_summary", None):
        demo_summary = _load_demo_summary(Path(args.demo_summary))

    readiness_ready = readiness_summary.get("status") == "ready"
    demo_proof = _demo_proof(demo_summary)
    status = _audit_status(
        static_passed,
        readiness_ready,
        demo_summary,
        demo_proof,
        paid_provider_env_present=bool(readiness_summary.get("paid_provider_credentials_present")),
    )
    return {
        "status": status,
        "static_requirements_passed": static_passed,
        "requirements": static_checks,
        "readiness": _summarize_readiness(readiness_summary),
        "demo_proof": demo_proof,
        "next_actions": _next_actions(status, readiness_summary),
    }


def exit_code(summary: dict[str, Any]) -> int:
    if summary.get("status") == "complete":
        return 0
    if summary.get("status") in {"waiting_for_live_credentials", "paid_provider_env_not_free_proof", "audit_error"}:
        return 2
    return 1


def _readiness_summary(args: argparse.Namespace) -> dict[str, Any]:
    env_file = str(Path(args.env_file).expanduser())
    loaded_env = free_demo._load_env_file(Path(env_file))
    readiness_args = SimpleNamespace(
        env_file=env_file,
        base_url=args.base_url,
        api_token=os.getenv("SENTINEL_API_TOKEN"),
        timeout_seconds=args.timeout_seconds,
        skip_kind_bootstrap=args.skip_kind_bootstrap,
        allow_paid_provider_env=args.allow_paid_provider_env,
        allow_local_discord_webhook=args.allow_local_discord_webhook,
        skip_host_tool_check=args.skip_host_tool_check,
        allow_non_kind_context=args.allow_non_kind_context,
        check_receiver=args.check_receiver,
    )
    return readiness.build_readiness_summary(
        readiness_args,
        env_file=env_file,
        loaded_env=loaded_env,
    )


def _static_requirement_checks() -> list[dict[str, Any]]:
    checks = [
        _check(
            "compose_free_dependencies",
            "Docker Compose includes Postgres, Redis, Prometheus, Loki, and free-provider env wiring.",
            {
                "docker-compose.yml": (
                    "postgres:",
                    "redis:",
                    "prometheus:",
                    "loki:",
                    "PROMETHEUS_URL: ${PROMETHEUS_URL:-http://prometheus:9090}",
                    "LOKI_URL: ${LOKI_URL:-http://loki:3100}",
                    "DISCORD_WEBHOOK_URL: ${DISCORD_WEBHOOK_URL:-}",
                ),
            },
        ),
        _check(
            "prometheus_loki_primary_datadog_fallback",
            "Observe tools use Prometheus and Loki first, with Datadog retained as fallback.",
            {
                "sentinel/live_clients.py": (
                    "class PrometheusClient",
                    "class LokiClient",
                    "class DatadogClient",
                    "def labels",
                    'expected_data_shape="list"',
                    "_require_prometheus_sample_pair",
                ),
                "sentinel/real_tools.py": (
                    "router.clients.loki.query_range",
                    'return {"provider": "loki"',
                    "_count_loki_log_entries",
                    "router.clients.prometheus.query_range",
                    "router.clients.prometheus.alerting_rules",
                    "router.clients.prometheus.targets",
                    'return {"provider": "prometheus"',
                    "container_memory_working_set_bytes",
                    "router.clients.datadog.search_logs",
                    "router.clients.datadog.query_metric",
                    "router.clients.datadog.list_monitors",
                    "router.clients.datadog.get_dashboard",
                    "_require_datadog_observability_fallback",
                ),
            },
        ),
        _check(
            "generic_webhook_alert_source",
            "Generic webhook endpoint accepts HTTP alerts and starts live investigations without PagerDuty.",
            {
                "sentinel/webapp.py": (
                    '@app.post("/webhooks/generic"',
                    "class GenericWebhookRequest",
                    "GenericWebhookRequest.model_validate",
                    "source=\"generic_webhook\"",
                    "_webhook_idempotency_key(\"generic_webhook\"",
                    "_webhook_idempotency_key(source, incident_id)",
                    "alerts",
                    "commonLabels",
                    "groupLabels",
                    "groupKey",
                    "_generic_alert_items",
                    '"webhook_source"',
                    '"generic_webhook_received"',
                    "_run_live_investigation_safely",
                    "response_model=WebhookRunResponse",
                ),
                "sentinel/live_clients.py": ("class GenericAlertClient", "\"provider\": \"generic_webhook\""),
            },
        ),
        _check(
            "pydantic_contracts_retained",
            "Free webhooks and live results keep the existing Pydantic response and tool-result contracts.",
            {
                "sentinel/models.py": ("class ToolResult", "class ToolCallRecord"),
                "sentinel/webapp.py": ("class WebhookRunResponse", "response_model=WebhookRunResponse", "_investigation_response"),
                "sentinel/real_tools.py": ("ToolResult(", "_evidence_from_live_result", "_is_write_skipped_dry_run"),
            },
        ),
        _check(
            "discord_fallback_notifications",
            "Discord webhook notifications are available when Slack is absent.",
            {
                "sentinel/live_clients.py": (
                    "class DiscordWebhookClient",
                    "def post_to_discord",
                    "json={\"content\": message}",
                    "_require_discord_message_confirmation",
                ),
                "sentinel/real_tools.py": (
                    "def post_to_discord",
                    "SLACK_BOT_TOKEN is missing",
                    "DISCORD_WEBHOOK_URL",
                    "_count_confirmed_discord_messages",
                ),
            },
        ),
        _check(
            "shared_reliability_and_audit",
            "Free alternatives use the same live retry, circuit-breaker, rate-limit, typed-error, and audit surfaces.",
            {
                "sentinel/real_tools.py": ("for attempt in range", "_retry_delay_seconds", "ToolExecutionError"),
                "sentinel/live_clients.py": (
                    "SharedRateLimiter",
                    "shared_circuit_breaker(\"prometheus\")",
                    "shared_circuit_breaker(\"loki\")",
                    "shared_circuit_breaker(\"discord\")",
                    "shared_circuit_breaker(\"generic_webhook\")",
                ),
                "sentinel/store.py": ("audit_events", "tool_calls", "append_audit_event"),
            },
        ),
        _check(
            "free_demo_requires_only_free_providers",
            "Free-tier demo refuses paid provider credentials and requires the 26-call free-provider proof set.",
            {
                "scripts/run_free_tier_sentinel_demo.py": (
                    "MIN_COMPLETED_TOOL_CALLS = 26",
                    "REQUIRED_FREE_PROVIDERS",
                    "\"prometheus\"",
                    "\"loki\"",
                    "\"generic_webhook\"",
                    "_generic_webhook_ingress_ready",
                    "\"alerts\"",
                    "\"commonLabels\"",
                    "\"groupLabels\"",
                    "\"groupKey\"",
                    "\"fingerprint\"",
                    "\"discord\"",
                    "sentinel_demo_info",
                    "receiver_metrics_missing_service_series",
                    "PAID_PROVIDER_ENV_VARS",
                    "DD_CLIENT_SECRET",
                    "PAGERDUTY_WEBHOOK_SECRET",
                    "SLACK_CLIENT_SECRET",
                    "PAID_PROVIDER_PROOF_NAMES",
                    "DISCORD_WEBHOOK_HOSTS",
                    "requested_service",
                    "affected_services",
                    "_approval_command_matches",
                    "SENTINEL_GITHUB_WRITE_ENABLED",
                    "github_write_enabled",
                ),
            },
        ),
        _check(
            "live_connectivity_free_metric_proof",
            "Live connectivity preflight proves the same service-labeled Prometheus demo metric as the free demo.",
            {
                "sentinel/connectivity.py": (
                    "\"prometheus.metrics\"",
                    "sentinel_demo_info",
                    "_prometheus_label_value",
                ),
            },
        ),
        _check(
            "premium_integrations_retained",
            "Datadog, PagerDuty, and Slack integrations remain present as premium fallbacks.",
            {
                "sentinel/live_clients.py": ("class DatadogClient", "class PagerDutyClient", "class SlackClient"),
                "sentinel/oauth.py": ("exchange_slack_code", "exchange_datadog_code", "verify_pagerduty_signature"),
                "sentinel/webapp.py": ('@app.post("/webhooks/pagerduty"', "/oauth/slack/install", "/oauth/datadog/install"),
            },
        ),
        _check(
            "live_free_e2e_gate",
            "Opt-in E2E tests exercise the deployed free-provider proposal and approval flows.",
            {
                "tests/test_free_tier_live_e2e.py": (
                    "RUN_FREE_TIER_LIVE_E2E_TESTS",
                    "RUN_FREE_TIER_LIVE_APPROVAL_E2E_TESTS",
                    "_assert_free_provider_proofs",
                    "infra.rollback_deployment",
                ),
            },
        ),
    ]
    return checks


def _check(identifier: str, description: str, file_needles: dict[str, tuple[str, ...]]) -> dict[str, Any]:
    evidence = []
    missing = []
    for relative_path, needles in file_needles.items():
        path = PROJECT_ROOT / relative_path
        try:
            text = path.read_text()
        except OSError as exc:
            missing.append({"file": relative_path, "needle": "<file>", "error": str(exc)})
            continue
        file_missing = [needle for needle in needles if needle not in text]
        if file_missing:
            missing.extend({"file": relative_path, "needle": needle} for needle in file_missing)
        else:
            evidence.append(relative_path)
    return {
        "id": identifier,
        "description": description,
        "passed": not missing,
        "evidence": evidence,
        "missing": missing,
    }


def _load_demo_summary(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def _demo_proof(summary: dict[str, Any] | None) -> dict[str, Any]:
    if summary is None:
        return {
            "provided": False,
            "passed": False,
            "message": "No free-tier demo summary was provided.",
        }
    exit_status = free_demo._exit_code(summary, proposal_only=False)
    return {
        "provided": True,
        "passed": exit_status == 0,
        "status": summary.get("status"),
        "current_state": summary.get("current_state"),
        "tool_calls": summary.get("tool_calls"),
        "notification_provider": summary.get("notification_provider"),
        "discord_notified": summary.get("discord_notified"),
        "approval_request_id": summary.get("approval_request_id"),
        "approval_approver_ids": summary.get("approval_approver_ids"),
        "approval_slack_notification_request_id": summary.get("approval_slack_notification_request_id"),
        "approval_slack_notified": summary.get("approval_slack_notified"),
        "approval_command_received": summary.get("approval_command_received"),
        "approval_command_request_id": summary.get("approval_command_request_id"),
        "approval_command_approver_id": summary.get("approval_command_approver_id"),
        "approval_command_decision": summary.get("approval_command_decision"),
        "webhook_source": summary.get("webhook_source"),
        "generic_webhook_received": summary.get("generic_webhook_received"),
        "webhook_ingress": summary.get("webhook_ingress"),
        "rollback_executed": summary.get("rollback_executed"),
        "approval_submitted": summary.get("approval_submitted"),
        "receiver_metrics": summary.get("receiver_metrics"),
        "live_provider_proofs": summary.get("live_provider_proofs"),
        "live_tool_proofs": summary.get("live_tool_proofs"),
    }


def _audit_status(
    static_passed: bool,
    readiness_ready: bool,
    demo_summary: dict[str, Any] | None,
    demo_proof: dict[str, Any],
    *,
    paid_provider_env_present: bool = False,
) -> str:
    if not static_passed:
        return "implementation_incomplete"
    if not readiness_ready:
        return "waiting_for_live_credentials"
    if paid_provider_env_present:
        return "paid_provider_env_not_free_proof"
    if demo_summary is None:
        return "ready_for_live_demo"
    if demo_proof.get("passed"):
        return "complete"
    return "live_demo_failed"


def _summarize_readiness(summary: dict[str, Any]) -> dict[str, Any]:
    config_problem = summary.get("config_problem") if isinstance(summary.get("config_problem"), dict) else {}
    paid_problem = summary.get("paid_provider_problem") if isinstance(summary.get("paid_provider_problem"), dict) else {}
    receiver = summary.get("receiver") if isinstance(summary.get("receiver"), dict) else None
    body = {
        "status": summary.get("status"),
        "free_provider_configured": summary.get("free_provider_configured"),
        "missing": config_problem.get("missing", []),
        "invalid": config_problem.get("invalid", []),
        "paid_provider_credentials_present": summary.get("paid_provider_credentials_present", []),
        "paid_provider_problem": paid_problem or None,
        "host_prerequisites_passed": (summary.get("host_prerequisites") or {}).get("passed"),
    }
    if receiver is not None:
        body["receiver_status"] = receiver.get("status")
    receiver_check = summary.get("receiver_check") if isinstance(summary.get("receiver_check"), dict) else None
    if receiver_check is not None:
        body["receiver_check_status"] = receiver_check.get("status")
        body["receiver_check_reason"] = receiver_check.get("reason")
    return body


def _next_actions(status: str, readiness_summary: dict[str, Any]) -> list[str]:
    commands = readiness_summary.get("next_commands") if isinstance(readiness_summary.get("next_commands"), dict) else {}
    if status == "waiting_for_live_credentials":
        actions = []
        config_problem = readiness_summary.get("config_problem") if isinstance(readiness_summary.get("config_problem"), dict) else {}
        missing = set(config_problem.get("missing") or [])
        if "DISCORD_WEBHOOK_URL" in missing and commands.get("configure_discord"):
            actions.append(commands["configure_discord"])
        if commands.get("check_receiver"):
            actions.append(commands["check_receiver"])
        return actions
    if status == "paid_provider_env_not_free_proof":
        variables = readiness_summary.get("paid_provider_credentials_present") or []
        names = ", ".join(str(name) for name in variables) or "paid provider credentials"
        actions = [f"Unset paid provider credentials before final proof: {names}"]
        if commands.get("check_receiver"):
            actions.append(commands["check_receiver"])
        return actions
    if status == "ready_for_live_demo":
        actions = [
            commands.get(
                "run_demo",
                "python3 scripts/run_free_tier_sentinel_demo.py FREE-DEMO-001 "
                "--base-url http://localhost:8000 "
                "--summary-output .sentinel/free-tier-demo-summary.json",
            )
        ]
        actions.append(
            commands.get(
                "audit_goal",
                "python3 scripts/audit_free_tier_goal.py "
                "--demo-summary .sentinel/free-tier-demo-summary.json",
            )
        )
        return actions
    if status == "live_demo_failed":
        return ["Review the supplied demo summary and rerun scripts/run_free_tier_sentinel_demo.py after fixing failed provider/tool proofs."]
    if status == "implementation_incomplete":
        return ["Review failed static requirement checks in this audit output."]
    return []


if __name__ == "__main__":
    main()
