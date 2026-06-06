from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import MutableMapping
from urllib.parse import urljoin, urlparse

import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from sentinel.config import SentinelSettings
from sentinel.errors import redact_sensitive_text
from sentinel.live_receiver_preflight import (
    normalize_receiver_base_url,
    operator_auth_headers as _operator_headers,
    receiver_preflight_failure,
    response_body as _body,
    run_http_receiver_check,
)


MIN_PROPOSAL_TOOL_CALLS = 20
MIN_COMPLETED_TOOL_CALLS = 26
REQUIRED_FREE_PROVIDERS = ("prometheus", "loki", "github", "generic_webhook", "discord", "kubernetes")
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
REQUIRED_COMPLETED_TOOL_PROOFS = (
    *REQUIRED_PROPOSAL_TOOL_PROOFS,
    "infra.rollback_deployment",
)
PAID_PROVIDER_ENV_VARS = (
    "DD_API_KEY",
    "DD_APP_KEY",
    "DATADOG_APP_KEY",
    "DD_OAUTH_TOKEN",
    "DD_CLIENT_ID",
    "DATADOG_CLIENT_ID",
    "DD_CLIENT_SECRET",
    "DATADOG_CLIENT_SECRET",
    "PAGERDUTY_API_KEY",
    "PAGERDUTY_REQUESTER_EMAIL",
    "PAGERDUTY_WEBHOOK_SECRET",
    "PAGERDUTY_WEBHOOK_PREVIOUS_SECRET",
    "PAGERDUTY_WEBHOOK_SUBSCRIPTION_ID",
    "SLACK_BOT_TOKEN",
    "SLACK_CHANNEL_ID",
    "SLACK_CLIENT_ID",
    "SLACK_CLIENT_SECRET",
)
PAID_PROVIDER_PROOF_NAMES = ("datadog", "pagerduty", "slack")
REQUIRED_FREE_SETTINGS = (
    ("SENTINEL_API_TOKEN", "api_token"),
    ("PROMETHEUS_URL", "prometheus_url"),
    ("LOKI_URL", "loki_url"),
    ("DISCORD_WEBHOOK_URL", "discord_webhook_url"),
    ("SENTINEL_APPROVER_ID", "approver_id"),
    ("GITHUB_TOKEN", "github_token"),
    ("GITHUB_OWNER", "github_owner"),
    ("GITHUB_REPO", "github_repo"),
)
DISCORD_WEBHOOK_HOSTS = frozenset(
    {
        "discord.com",
        "discordapp.com",
        "canary.discord.com",
        "ptb.discord.com",
    }
)


def main() -> None:
    env_file = _env_file_from_argv(sys.argv[1:]) or os.getenv("SENTINEL_ENV_FILE") or str(PROJECT_ROOT / ".env")
    _load_env_file(Path(env_file))

    parser = argparse.ArgumentParser(
        description="Run SENTINEL end-to-end through free providers: Prometheus, Loki, generic webhook, Discord, GitHub, and kind."
    )
    parser.add_argument("incident_id", nargs="?", default="FREE-TIER-DEMO-INCIDENT")
    parser.add_argument(
        "--env-file",
        default=env_file,
        help="Load environment variables from this file before reading SENTINEL settings. Defaults to .env.",
    )
    parser.add_argument("--service", default=os.getenv("SENTINEL_DEFAULT_SERVICE", "payment-service"))
    parser.add_argument("--base-url", default=os.getenv("SENTINEL_BASE_URL", "http://localhost:8000"))
    parser.add_argument("--prometheus-url", default=os.getenv("PROMETHEUS_SEED_URL") or "http://localhost:9090")
    parser.add_argument("--loki-url", default=os.getenv("LOKI_SEED_URL") or "http://localhost:3100")
    parser.add_argument("--poll-seconds", type=int, default=int(os.getenv("SENTINEL_LIVE_E2E_TIMEOUT_SECONDS", "180")))
    parser.add_argument("--poll-interval", type=float, default=5.0)
    parser.add_argument(
        "--http-timeout-seconds",
        type=float,
        default=None,
        help="Per-request HTTP timeout. Defaults to min(20, --poll-seconds).",
    )
    parser.add_argument("--api-token", default=os.getenv("SENTINEL_API_TOKEN"))
    parser.add_argument("--approver-id", default=os.getenv("SENTINEL_APPROVER_ID"))
    parser.add_argument(
        "--proposal-only",
        action="store_true",
        help="Stop once SENTINEL reaches waiting_for_approval instead of submitting approval.",
    )
    parser.add_argument(
        "--skip-kind-bootstrap",
        action="store_true",
        help="Do not create or patch the demo deployment before the run.",
    )
    parser.add_argument(
        "--allow-non-kind-context",
        action="store_true",
        help="Allow bootstrap against a current kubectl context whose name does not contain 'kind'.",
    )
    parser.add_argument(
        "--skip-observability-seed",
        action="store_true",
        help="Do not push demo log lines to Loki or wait for Prometheus service metrics before preflight.",
    )
    parser.add_argument(
        "--allow-paid-provider-env",
        action="store_true",
        help="Allow Datadog, PagerDuty, or Slack credentials to be present. The default rejects them to prove the free demo path.",
    )
    parser.add_argument(
        "--allow-local-discord-webhook",
        action="store_true",
        help="Allow a non-Discord webhook URL for local stub testing. Do not use this for final live-demo proof.",
    )
    parser.add_argument(
        "--summary-output",
        default=None,
        help="Optional path to write the final JSON summary for audit_free_tier_goal.py --demo-summary.",
    )
    args = parser.parse_args()

    try:
        settings = SentinelSettings.from_env()
        base_url = normalize_receiver_base_url(args.base_url)
    except Exception as exc:
        summary = {"status": "invalid_config", "error": redact_sensitive_text(exc, max_length=500)}
        _emit_summary(summary, args.summary_output)
        raise SystemExit(2) from exc

    paid_vars = _configured_paid_provider_env_vars()
    if paid_vars and not args.allow_paid_provider_env:
        summary = {
            "status": "paid_provider_credentials_present",
            "message": (
                "Free-tier demo refuses to run while Datadog, PagerDuty, or Slack credentials are set. "
                "Unset these variables or pass --allow-paid-provider-env for debugging."
            ),
            "variables": paid_vars,
        }
        _emit_summary(summary, args.summary_output)
        raise SystemExit(2)

    free_config = _free_tier_config_problem(settings, args)
    if free_config is not None:
        _emit_summary(free_config, args.summary_output)
        raise SystemExit(2)

    timeout = _http_timeout_seconds(args.poll_seconds, args.http_timeout_seconds)
    operator_headers = _operator_headers(args.api_token or settings.api_token)
    with httpx.Client(timeout=timeout) as client:
        summary = run_demo(settings, args, client, base_url, operator_headers)
    _emit_summary(summary, args.summary_output)
    raise SystemExit(_exit_code(summary, proposal_only=args.proposal_only))


def run_demo(
    settings: SentinelSettings,
    args: argparse.Namespace,
    client: httpx.Client,
    base_url: str,
    operator_headers: dict[str, str],
) -> dict:
    bootstrap_summary = None
    if not args.skip_kind_bootstrap:
        bootstrap_summary = _bootstrap_kind_deployment(settings, args)
        if bootstrap_summary.get("status") != "ready":
            return {"status": "kind_bootstrap_failed", "kind_bootstrap": bootstrap_summary}

    if not args.skip_observability_seed:
        seed_summary = _seed_free_observability(client, args, base_url)
        if seed_summary.get("status") != "ready":
            return seed_summary

    preflight = _receiver_preflight(client, base_url, operator_headers)
    if preflight is not None:
        if bootstrap_summary:
            preflight["kind_bootstrap"] = bootstrap_summary
        return preflight

    payload = _generic_payload(args.incident_id, args.service)
    response = client.post(f"{base_url}/webhooks/generic", json=payload)
    if response.status_code >= 400:
        return {
            "status": "webhook_failed",
            "code": response.status_code,
            "body": _body(response),
            "kind_bootstrap": bootstrap_summary,
        }

    accepted = response.json()
    investigation_id = accepted["investigation_id"]
    if not investigation_id:
        return {"status": "webhook_not_actionable", "body": accepted}

    approval_submitted = False
    latest: dict | None = None
    deadline = time.monotonic() + args.poll_seconds
    while time.monotonic() < deadline:
        status_response = client.get(f"{base_url}/investigations/{investigation_id}", headers=operator_headers)
        if status_response.status_code >= 400:
            return {
                "status": "poll_failed",
                "code": status_response.status_code,
                "body": _body(status_response),
                "investigation_id": investigation_id,
            }
        latest = status_response.json()
        investigation_status = latest.get("status")
        if investigation_status == "waiting_for_approval":
            if approval_submitted:
                time.sleep(args.poll_interval)
                continue
            if not _proposal_ready(latest, args.incident_id, args.service):
                return {"status": "proposal_not_ready", "body": latest, "kind_bootstrap": bootstrap_summary}
            if args.proposal_only:
                return {
                    "status": "waiting_for_approval",
                    "requested_incident_id": args.incident_id,
                    "requested_service": args.service,
                    "investigation_id": investigation_id,
                    "kind_bootstrap": bootstrap_summary,
                    **latest,
                }
            approver_id = args.approver_id or _approval_approver_id(latest)
            if not approver_id:
                return {"status": "approval_approver_missing", "body": latest}
            approval = {
                "request_id": latest["approval_request_id"],
                "approver_id": approver_id,
                "decision": "approve",
                "idempotency_key": (
                    f"{investigation_id}:approval-command:"
                    f"{latest['approval_request_id']}:{approver_id}:approve"
                ),
            }
            approval_response = client.post(
                f"{base_url}/investigations/{investigation_id}/approval",
                json=approval,
                headers=operator_headers,
            )
            if approval_response.status_code >= 400:
                return {
                    "status": "approval_failed",
                    "code": approval_response.status_code,
                    "body": _body(approval_response),
                    "proposal": latest,
                }
            approval_submitted = True
        elif investigation_status in {"completed", "failed", "insufficient_confidence"}:
            return {
                "status": investigation_status,
                "requested_incident_id": args.incident_id,
                "requested_service": args.service,
                "investigation_id": investigation_id,
                "approval_submitted": approval_submitted,
                "kind_bootstrap": bootstrap_summary,
                **latest,
            }
        time.sleep(args.poll_interval)

    return {
        "status": "timeout",
        "requested_incident_id": args.incident_id,
        "requested_service": args.service,
        "investigation_id": investigation_id,
        "latest": latest,
        "kind_bootstrap": bootstrap_summary,
    }


def _seed_free_observability(client: httpx.Client, args: argparse.Namespace, base_url: str) -> dict:
    receiver_metrics = _receiver_metrics_ready(client, base_url, args.service)
    if receiver_metrics.get("status") != "ready":
        return receiver_metrics
    metrics = _wait_for_prometheus_metric(client, args.prometheus_url, args.service, args.poll_seconds)
    if metrics.get("status") != "ready":
        return metrics
    logs = _push_loki_demo_logs(client, args.loki_url, args.service, args.incident_id)
    if logs.get("status") != "ready":
        return logs
    return {"status": "ready", "receiver_metrics": receiver_metrics, "prometheus": metrics, "loki": logs}


def _receiver_metrics_ready(client: httpx.Client, base_url: str, service: str) -> dict:
    try:
        response = client.get(f"{base_url}/metrics")
    except httpx.HTTPError as exc:
        return {"status": "receiver_metrics_failed", "error": str(exc)}
    if response.status_code >= 400:
        return {"status": "receiver_metrics_failed", "code": response.status_code, "body": _body(response)}
    body = response.text
    expected = f'sentinel_demo_info{{service="{_prometheus_label_value(service)}"}} 1'
    if expected not in body:
        return {
            "status": "receiver_metrics_missing_service_series",
            "service": service,
            "expected": expected,
            "available_services": _receiver_metric_services(body),
        }
    return {"status": "ready", "service": service}


def _receiver_metric_services(metrics_body: str) -> list[str]:
    services = {
        match.group(1)
        for match in re.finditer(r'sentinel_demo_info\{service="((?:\\.|[^"\\])*)"\}\s+', metrics_body)
    }
    return sorted(_prometheus_unescape_label_value(service) for service in services)


def _wait_for_prometheus_metric(
    client: httpx.Client,
    prometheus_url: str,
    service: str,
    timeout_seconds: int,
) -> dict:
    deadline = time.monotonic() + min(timeout_seconds, 60)
    query = f'sentinel_demo_info{{service="{_prometheus_label_value(service)}"}}'
    latest: dict | None = None
    while time.monotonic() < deadline:
        try:
            response = client.get(_join_url(prometheus_url, "/api/v1/query"), params={"query": query})
        except httpx.HTTPError as exc:
            latest = {"error": str(exc)}
            time.sleep(2)
            continue
        latest = _body(response)
        if response.status_code < 400 and isinstance(latest, dict):
            result = ((latest.get("data") or {}).get("result") or [])
            if result:
                return {"status": "ready", "query": query, "series": len(result)}
        time.sleep(2)
    return {"status": "prometheus_not_ready", "query": query, "latest": latest}


def _prometheus_label_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _prometheus_unescape_label_value(value: str) -> str:
    chars: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char != "\\" or index + 1 >= len(value):
            chars.append(char)
            index += 1
            continue
        escaped = value[index + 1]
        if escaped == "n":
            chars.append("\n")
        elif escaped in {'"', "\\"}:
            chars.append(escaped)
        else:
            chars.append(escaped)
        index += 2
    return "".join(chars)


def _push_loki_demo_logs(client: httpx.Client, loki_url: str, service: str, incident_id: str) -> dict:
    now_ns = int(time.time() * 1_000_000_000)
    streams = [
        {
            "stream": {"service": service, "level": "error", "source": "sentinel-free-demo"},
            "values": [
                [str(now_ns - 4_000_000_000), f"incident={incident_id} trace_id=free-demo-1 payment latency spike"],
                [str(now_ns - 3_000_000_000), f"incident={incident_id} db query slow orders.user_id lookup"],
                [str(now_ns - 2_000_000_000), f"incident={incident_id} cdn upstream retries elevated"],
                [str(now_ns - 1_000_000_000), f"incident={incident_id} trace span checkout authorize failed"],
            ],
        }
    ]
    response = client.post(_join_url(loki_url, "/loki/api/v1/push"), json={"streams": streams})
    if response.status_code >= 400:
        return {"status": "loki_push_failed", "code": response.status_code, "body": _body(response)}
    return {"status": "ready", "streams": len(streams)}


def _bootstrap_kind_deployment(settings: SentinelSettings, args: argparse.Namespace) -> dict:
    kubeconfig = _host_kubeconfig(settings)
    namespace = settings.kubernetes_namespace
    base_cmd = ["kubectl"]
    if kubeconfig:
        base_cmd += ["--kubeconfig", kubeconfig]
    context = _run_kubectl([*base_cmd, "config", "current-context"])
    if context["status"] != "ok":
        return context
    context_name = context["stdout"].strip()
    if "kind" not in context_name.lower() and not args.allow_non_kind_context:
        return {
            "status": "unsafe_context",
            "context": context_name,
            "message": "Refusing to bootstrap demo workload outside a kubectl context containing 'kind'.",
        }
    namespace_check = _run_kubectl([*base_cmd, "get", "namespace", namespace])
    if namespace_check["status"] != "ok":
        created = _run_kubectl([*base_cmd, "create", "namespace", namespace])
        if created["status"] != "ok":
            return created

    deployment_check = _run_kubectl([*base_cmd, "get", "deployment", args.service, "-n", namespace])
    if deployment_check["status"] != "ok":
        create = _run_kubectl(
            [
                *base_cmd,
                "create",
                "deployment",
                args.service,
                "-n",
                namespace,
                "--image=registry.k8s.io/pause:3.10",
            ]
        )
        if create["status"] != "ok":
            return create
        rollout = _run_kubectl([*base_cmd, "rollout", "status", f"deployment/{args.service}", "-n", namespace, "--timeout=60s"])
        if rollout["status"] != "ok":
            return rollout

    for revision in ("1", "2"):
        patch = json.dumps(
            {
                "spec": {
                    "template": {
                        "metadata": {
                            "labels": {"app": args.service},
                            "annotations": {
                                "sentinel.dev/demo-revision": revision,
                                "sentinel.dev/demo-seeded-at": datetime.now(UTC).isoformat(),
                            },
                        }
                    }
                }
            }
        )
        patched = _run_kubectl([*base_cmd, "patch", "deployment", args.service, "-n", namespace, "-p", patch])
        if patched["status"] != "ok":
            return patched
        rollout = _run_kubectl([*base_cmd, "rollout", "status", f"deployment/{args.service}", "-n", namespace, "--timeout=60s"])
        if rollout["status"] != "ok":
            return rollout
    return {"status": "ready", "context": context_name, "namespace": namespace, "deployment": args.service}


def _run_kubectl(command: list[str]) -> dict:
    try:
        proc = subprocess.run(command, text=True, capture_output=True, timeout=90, check=False)
    except subprocess.TimeoutExpired as exc:
        return {"status": "timeout", "command": _redacted_command(command), "error": str(exc)}
    if proc.returncode != 0:
        return {
            "status": "failed",
            "command": _redacted_command(command),
            "stdout": proc.stdout.strip(),
            "stderr": redact_sensitive_text(proc.stderr.strip(), max_length=500),
        }
    return {"status": "ok", "stdout": proc.stdout.strip()}


def _receiver_preflight(client: httpx.Client, base_url: str, operator_headers: dict[str, str]) -> dict | None:
    summary = run_http_receiver_check(base_url, client, operator_headers=operator_headers)
    failure = receiver_preflight_failure(summary, include_receiver_context=False)
    if failure and summary.get("status") == "receiver_unreachable":
        failure["base_url"] = summary.get("base_url")
    return failure


def _generic_payload(incident_id: str, service: str) -> dict:
    occurred_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    return {
        "receiver": "sentinel",
        "source": "alertmanager",
        "status": "firing",
        "groupKey": f'{{alertname="SentinelFreeTierDemo", service="{service}"}}',
        "commonLabels": {
            "alertname": "SentinelFreeTierDemo",
            "severity": "critical",
            "service": service,
            "app": service,
        },
        "groupLabels": {
            "alertname": "SentinelFreeTierDemo",
            "service": service,
        },
        "commonAnnotations": {
            "summary": f"{service} latency and error rate regression",
        },
        "alerts": [
            {
                "status": "firing",
                "fingerprint": incident_id,
                "startsAt": occurred_at,
                "labels": {
                    "alertname": "SentinelFreeTierDemo",
                    "severity": "critical",
                    "service": service,
                    "app": service,
                },
                "annotations": {
                    "summary": f"{service} latency and error rate regression",
                    "description": "Free-tier demo alert generated from the Prometheus/Alertmanager payload shape.",
                },
            }
        ],
    }


def _proposal_ready(status: dict, requested_incident_id: str, expected_service: str) -> bool:
    return (
        status.get("incident_id") == requested_incident_id
        and status.get("status") == "waiting_for_approval"
        and status.get("current_state") == "response_proposal"
        and _tool_call_count(status) >= MIN_PROPOSAL_TOOL_CALLS
        and _diagnosis_ready(status)
        and bool(status.get("recommendation"))
        and bool(status.get("approval_request_id"))
        and status.get("notification_provider") == "discord"
        and status.get("discord_notified") is True
        and status.get("approval_slack_notified") is True
        and _approval_notification_matches(status)
        and _generic_webhook_ingress_ready(status, requested_incident_id, expected_service)
        and _live_proofs_ready(status, REQUIRED_PROPOSAL_TOOL_PROOFS)
        and not status.get("rollback_attempted")
        and not status.get("rollback_executed")
    )


def _completed_ready(
    status: dict,
    requested_incident_id: str,
    approval_submitted: bool,
    expected_service: str,
) -> bool:
    remediation = status.get("remediation_result")
    return (
        approval_submitted
        and status.get("incident_id") == requested_incident_id
        and status.get("status") == "completed"
        and status.get("current_state") == "post_mortem"
        and _tool_call_count(status) >= MIN_COMPLETED_TOOL_CALLS
        and _diagnosis_ready(status)
        and bool(status.get("recommendation"))
        and status.get("notification_provider") == "discord"
        and status.get("discord_notified") is True
        and status.get("approval_slack_notified") is True
        and _approval_notification_matches(status)
        and _approval_command_matches(status)
        and _generic_webhook_ingress_ready(status, requested_incident_id, expected_service)
        and status.get("rollback_attempted") is True
        and status.get("rollback_executed") is True
        and isinstance(remediation, dict)
        and remediation.get("status") == "executed"
        and _live_proofs_ready(status, REQUIRED_COMPLETED_TOOL_PROOFS)
    )


def _live_proofs_ready(status: dict, required_tools: tuple[str, ...]) -> bool:
    provider_proofs = status.get("live_provider_proofs")
    tool_proofs = status.get("live_tool_proofs")
    if not isinstance(provider_proofs, dict) or not isinstance(tool_proofs, dict):
        return False
    if any(_positive_count(provider_proofs.get(provider)) for provider in PAID_PROVIDER_PROOF_NAMES):
        return False
    return all(_positive_count(provider_proofs.get(provider)) for provider in REQUIRED_FREE_PROVIDERS) and all(
        _positive_count(tool_proofs.get(tool_name)) for tool_name in required_tools
    )


def _generic_webhook_ingress_ready(status: dict, requested_incident_id: str, expected_service: str) -> bool:
    ingress = status.get("webhook_ingress")
    payload_keys = ingress.get("payload_keys") if isinstance(ingress, dict) else None
    affected_services = ingress.get("affected_services") if isinstance(ingress, dict) else None
    grouped_alert_keys = {"alerts", "commonLabels", "groupKey", "groupLabels"}
    service = expected_service.strip() if isinstance(expected_service, str) else ""
    return (
        bool(service)
        and status.get("webhook_source") == "generic_webhook"
        and status.get("generic_webhook_received") is True
        and isinstance(ingress, dict)
        and ingress.get("source") == "generic_webhook"
        and ingress.get("incident_id") == requested_incident_id
        and isinstance(affected_services, list)
        and service in {item for item in affected_services if isinstance(item, str)}
        and isinstance(payload_keys, list)
        and grouped_alert_keys.issubset({key for key in payload_keys if isinstance(key, str)})
    )


def _diagnosis_ready(status: dict) -> bool:
    diagnosis = status.get("diagnosis")
    confidence = status.get("confidence")
    return isinstance(diagnosis, str) and bool(diagnosis.strip()) and isinstance(confidence, str) and bool(confidence.strip())


def _approval_notification_matches(status: dict) -> bool:
    request_id = status.get("approval_request_id")
    notification_request_id = status.get("approval_slack_notification_request_id")
    return isinstance(request_id, str) and bool(request_id.strip()) and notification_request_id == request_id


def _approval_command_matches(status: dict) -> bool:
    request_id = status.get("approval_request_id")
    command_request_id = status.get("approval_command_request_id")
    command_approver_id = status.get("approval_command_approver_id")
    approvers = status.get("approval_approver_ids")
    if (
        status.get("approval_command_received") is not True
        or status.get("approval_command_decision") != "approve"
        or not isinstance(request_id, str)
        or not request_id.strip()
        or command_request_id != request_id
        or not isinstance(command_approver_id, str)
        or not command_approver_id.strip()
        or not isinstance(approvers, list)
    ):
        return False
    authorized_approvers = {
        approver.strip()
        for approver in approvers
        if isinstance(approver, str) and approver.strip()
    }
    return command_approver_id.strip() in authorized_approvers


def _approval_approver_id(status: dict) -> str | None:
    approvers = status.get("approval_approver_ids")
    if not isinstance(approvers, list):
        return None
    for approver in approvers:
        if isinstance(approver, str) and approver.strip():
            return approver.strip()
    return None


def _tool_call_count(status: dict) -> int:
    try:
        return int(status.get("tool_calls") or 0)
    except (TypeError, ValueError):
        return 0


def _positive_count(value) -> bool:
    try:
        return int(value) > 0
    except (TypeError, ValueError):
        return False


def _exit_code(summary: dict, *, proposal_only: bool) -> int:
    if summary.get("status") in {
        "invalid_config",
        "missing_free_tier_config",
        "paid_provider_credentials_present",
        "kind_bootstrap_failed",
        "prometheus_not_ready",
        "loki_push_failed",
        "receiver_metrics_failed",
        "receiver_metrics_missing_service_series",
        "ready_failed",
        "ready_malformed",
        "connectivity_failed",
        "connectivity_malformed",
        "receiver_unreachable",
        "receiver_base_url_invalid",
    }:
        return 2
    requested_incident_id = summary.get("requested_incident_id")
    requested_service = summary.get("requested_service")
    if requested_incident_id and summary.get("incident_id") != requested_incident_id:
        return 1
    if proposal_only:
        return 0 if _proposal_ready(summary, requested_incident_id or "", requested_service or "") else 1
    return (
        0
        if _completed_ready(
            summary,
            requested_incident_id or "",
            bool(summary.get("approval_submitted")),
            requested_service or "",
        )
        else 1
    )


def _configured_paid_provider_env_vars() -> list[str]:
    configured = []
    for name in PAID_PROVIDER_ENV_VARS:
        value = os.getenv(name)
        if isinstance(value, str) and value.strip():
            configured.append(name)
    return configured


def _free_tier_config_problem(settings: SentinelSettings, args: argparse.Namespace) -> dict | None:
    missing = [
        env_name
        for env_name, attr in REQUIRED_FREE_SETTINGS
        if not getattr(settings, attr)
    ]
    invalid = []
    discord_problem = _discord_webhook_problem(settings.discord_webhook_url, args)
    if discord_problem is not None and "DISCORD_WEBHOOK_URL" not in missing:
        invalid.append(discord_problem)
    if getattr(settings, "github_write_enabled", False):
        invalid.append(
            {
                "name": "SENTINEL_GITHUB_WRITE_ENABLED",
                "value": "true",
                "message": (
                    "SENTINEL_GITHUB_WRITE_ENABLED must be false for final free-tier demo proof; "
                    "the demo uses live GitHub read evidence and kind for remediation."
                ),
            }
        )
    if not args.skip_kind_bootstrap:
        kubeconfig = _host_kubeconfig(settings)
        if kubeconfig and not Path(kubeconfig).exists():
            invalid.append(
                {
                    "name": "HOST_KUBECONFIG",
                    "value": kubeconfig,
                    "message": "Host-side kubeconfig path does not exist.",
                }
            )
    if not missing and not invalid:
        return None
    body = {
        "status": "missing_free_tier_config",
        "message": "Free-tier demo requires Prometheus, Loki, GitHub, Discord, generic approver, operator auth, and host kind access before it can prove the end-to-end path.",
        "missing": missing,
    }
    if invalid:
        body["invalid"] = invalid
    return body


def _discord_webhook_problem(webhook_url: str | None, args: argparse.Namespace) -> dict | None:
    if getattr(args, "allow_local_discord_webhook", False):
        return None
    if not webhook_url:
        return None
    try:
        parsed = urlparse(webhook_url)
    except ValueError:
        return {
            "name": "DISCORD_WEBHOOK_URL",
            "message": "DISCORD_WEBHOOK_URL must be a real Discord webhook URL for final free-tier demo proof.",
        }
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or host not in DISCORD_WEBHOOK_HOSTS or not parsed.path.startswith("/api/webhooks/"):
        return {
            "name": "DISCORD_WEBHOOK_URL",
            "host": host or None,
            "message": (
                "DISCORD_WEBHOOK_URL must point to https://discord.com/api/webhooks/... "
                "for final proof; pass --allow-local-discord-webhook only for local stub testing."
            ),
        }
    return None


def _host_kubeconfig(settings: SentinelSettings) -> str | None:
    host_value = _optional_env("HOST_KUBECONFIG")
    if host_value:
        return str(Path(host_value).expanduser())
    kubeconfig = settings.kubeconfig.strip() if isinstance(settings.kubeconfig, str) else None
    if kubeconfig and kubeconfig != "/root/.kube/config":
        return str(Path(kubeconfig).expanduser())
    return None


def _optional_env(name: str) -> str | None:
    value = os.getenv(name)
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _emit_summary(summary: dict, output_path: str | None) -> None:
    if output_path:
        _write_summary_output(summary, Path(output_path).expanduser())
    print(json.dumps(summary, indent=2))


def _write_summary_output(summary: dict, output_path: Path) -> str:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(summary, indent=2) + "\n"
    temporary = output_path.with_name(f"{output_path.name}.tmp")
    temporary.write_text(body)
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    temporary.replace(output_path)
    try:
        os.chmod(output_path, 0o600)
    except OSError:
        pass
    return str(output_path)


def _env_file_from_argv(argv: list[str]) -> str | None:
    for index, item in enumerate(argv):
        if item == "--env-file" and index + 1 < len(argv):
            return argv[index + 1]
        if item.startswith("--env-file="):
            return item.partition("=")[2]
    return None


def _load_env_file(path: Path, environ: MutableMapping[str, str] | None = None) -> dict[str, str]:
    if not path.exists():
        return {}
    target = environ if environ is not None else os.environ
    loaded: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text().splitlines(), start=1):
        parsed = _parse_env_line(raw_line, line_number=line_number, path=path)
        if parsed is None:
            continue
        key, value = parsed
        if key in target:
            continue
        target[key] = value
        loaded[key] = value
    return loaded


def _parse_env_line(raw_line: str, *, line_number: int, path: Path) -> tuple[str, str] | None:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("export "):
        line = line[len("export "):].strip()
    if "=" not in line:
        raise ValueError(f"{path}:{line_number} must be KEY=VALUE")
    key, value = line.split("=", 1)
    key = key.strip()
    if not key or not key.replace("_", "").isalnum() or key[0].isdigit():
        raise ValueError(f"{path}:{line_number} has invalid environment variable name")
    return key, _clean_env_value(value)


def _clean_env_value(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _join_url(base_url: str, path: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def _redacted_command(command: list[str]) -> list[str]:
    redacted: list[str] = []
    skip_next = False
    for part in command:
        if skip_next:
            redacted.append("<redacted>")
            skip_next = False
            continue
        redacted.append(part)
        if part == "--kubeconfig":
            skip_next = True
    return redacted


def _http_timeout_seconds(workflow_timeout_seconds: int | float, explicit_timeout_seconds: float | None) -> float:
    if explicit_timeout_seconds is not None:
        return max(0.1, float(explicit_timeout_seconds))
    return max(0.1, min(20.0, float(workflow_timeout_seconds)))


if __name__ == "__main__":
    main()
