from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import shlex
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASE_URL = "http://localhost:8000"
GROQ_RESPONSES_ENDPOINT = "https://api.groq.com/openai/v1/responses"
DEFAULT_GROQ_MODEL = "llama-3.3-70b-versatile"
LOCAL_POSTGRES_DATABASE_URL = "postgresql://sentinel:change-me@postgres:5432/sentinel"
SQLITE_CHECKPOINT_DATABASE_URL = "sqlite:////data/sentinel-live-checkpoint.sqlite3"
MIN_TOOL_CALLS = 20


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Prompt for real credentials, run SENTINEL through the live receiver, "
            "capture a full log, restart at the approval checkpoint, and verify "
            "Groq/model/subagent/tool-call evidence."
        )
    )
    parser.add_argument("--base-url", default=os.getenv("SENTINEL_BASE_URL", DEFAULT_BASE_URL))
    parser.add_argument("--payload-file", help="JSON webhook payload to POST to /webhooks/generic.")
    parser.add_argument("--poll-seconds", type=int, default=420)
    parser.add_argument("--poll-interval", type=float, default=5.0)
    parser.add_argument("--skip-preflight", action="store_true", help="Skip non-secret local Docker/config checks.")
    parser.add_argument("--skip-compose", action="store_true", help="Use an already running receiver.")
    parser.add_argument("--compose-project", default="sentinel-live")
    parser.add_argument("--log-path", default=None)
    parser.add_argument("--host-prometheus-url", default=os.getenv("SENTINEL_HOST_PROMETHEUS_URL", "http://localhost:9090"))
    parser.add_argument("--slow-query-row-count", type=int, default=180_000)
    parser.add_argument("--slow-query-load-seconds", type=int, default=25)
    parser.add_argument("--slow-query-min-requests", type=int, default=12)
    parser.add_argument("--slow-query-alert-wait-seconds", type=int, default=45)
    parser.add_argument(
        "--checkpoint-backend",
        choices=("sqlite", "postgres"),
        default="sqlite",
        help=(
            "Store backend used for the restart proof. Defaults to sqlite to satisfy "
            "the video checkpoint requirement; use postgres for the production-style Docker default."
        ),
    )
    args = parser.parse_args()

    run_id = int(time.time())
    sentinel_dir = PROJECT_ROOT / ".sentinel"
    sentinel_dir.mkdir(exist_ok=True)
    log_path = Path(args.log_path) if args.log_path else sentinel_dir / f"live-run-{run_id}.log"
    env_file = sentinel_dir / f"live-run-{run_id}.env"

    with _LiveLog(log_path) as log:
        _run_non_secret_preflight(args, log)
        env, credential_meta = _collect_credentials(args.checkpoint_backend)
        env["SENTINEL_MODEL_ENDPOINT"] = GROQ_RESPONSES_ENDPOINT
        env.setdefault("SENTINEL_MODEL", DEFAULT_GROQ_MODEL)
        env.setdefault("SENTINEL_ENV", "production")
        env.setdefault("SENTINEL_GITHUB_WRITE_ENABLED", "false")
        env.setdefault("SENTINEL_SERVICE_ALIASES", "{}")

        _write_env_file(env_file, env)
        log.section("credential_prompts_complete")
        log.json(
            {
                "env_file": str(env_file),
                "redacted_env": _redacted_env_summary(env),
                "credential_prompt_meta": credential_meta,
            }
        )
        if not args.skip_compose:
            _run_compose(["up", "-d", "--build", "postgres", "redis", "prometheus", "loki", "sentinel"], env_file, args, log)
        _wait_receiver_ready(args.base_url, env["SENTINEL_API_TOKEN"], args.poll_seconds, log)

        payload = _load_or_prompt_payload(args, log)
        incident_id = _payload_incident_id(payload)
        if not incident_id:
            raise SystemExit("The live payload must include incident_id, alert_id, id, or fingerprint.")
        log.section("posting_real_generic_webhook")
        log.json({"incident_id": incident_id, "payload": payload})

        operator_headers = {"Authorization": f"Bearer {env['SENTINEL_API_TOKEN']}"}
        checkpoint_recovered = False
        approval_submitted = False
        with httpx.Client(timeout=30.0) as client:
            accepted = _post_webhook(client, args.base_url, payload, log)
            investigation_id = accepted["investigation_id"]
            latest = _poll_until(
                client,
                args.base_url,
                investigation_id,
                operator_headers,
                args.poll_seconds,
                args.poll_interval,
                log,
                stop_status="waiting_for_approval",
            )
            if latest.get("status") != "waiting_for_approval":
                _finalize_failure(log, latest, checkpoint_recovered=False)
                raise SystemExit(1)

            before_restart_calls = int(latest.get("tool_calls") or 0)
            before_restart_process = _receiver_process(latest)
            log.section("checkpoint_restart")
            log.json(
                {
                    "message": "Hard-killing the receiver after approval checkpoint, then restarting and polling the same investigation.",
                    "investigation_id": investigation_id,
                    "status_before_restart": latest.get("status"),
                    "tool_calls_before_restart": before_restart_calls,
                    "receiver_process_before_restart": before_restart_process,
                    "checkpoint_backend": args.checkpoint_backend,
                    "store_note": (
                        "This proves durable checkpoint resume at the approval boundary "
                        f"for the {args.checkpoint_backend} store."
                    ),
                }
            )
            if args.skip_compose:
                input("Kill and restart the receiver process now, then press Enter to continue polling the same investigation...")
            else:
                _run_compose(["kill", "-s", "SIGKILL", "sentinel"], env_file, args, log)
                _run_compose(["up", "-d", "sentinel"], env_file, args, log)
            _wait_receiver_ready(args.base_url, env["SENTINEL_API_TOKEN"], args.poll_seconds, log)
            after_restart = _get_status(client, args.base_url, investigation_id, operator_headers)
            after_restart_process = _receiver_process(after_restart)
            checkpoint_process_restarted = _receiver_process_changed(
                before_restart_process,
                after_restart_process,
            )
            log.section("checkpoint_recovered_status")
            log.json(
                {
                    "receiver_process_before_restart": before_restart_process,
                    "receiver_process_after_restart": after_restart_process,
                    "checkpoint_process_restarted": checkpoint_process_restarted,
                    "status": after_restart,
                }
            )
            checkpoint_recovered = (
                after_restart.get("investigation_id") == investigation_id
                and after_restart.get("status") == "waiting_for_approval"
                and int(after_restart.get("tool_calls") or 0) >= before_restart_calls
                and checkpoint_process_restarted
            )
            if not checkpoint_recovered:
                _finalize_failure(log, after_restart, checkpoint_recovered=False)
                raise SystemExit(1)

            approval = _approval_payload(after_restart)
            log.section("approval_prompt")
            log.json(
                {
                    "approval_request_id": approval["request_id"],
                    "approver_id": approval["approver_id"],
                    "recommendation": after_restart.get("recommendation"),
                }
            )
            confirmation = input("Type APPROVE to submit the real structured approval command: ").strip()
            if confirmation != "APPROVE":
                log.json({"status": "approval_aborted_by_user"})
                raise SystemExit(1)
            approval_response = client.post(
                f"{args.base_url.rstrip('/')}/investigations/{investigation_id}/approval",
                headers=operator_headers,
                json=approval,
            )
            log.section("approval_submitted")
            log.json({"code": approval_response.status_code, "body": _response_body(approval_response)})
            approval_response.raise_for_status()
            approval_submitted = True

            completed = _poll_until(
                client,
                args.base_url,
                investigation_id,
                operator_headers,
                args.poll_seconds,
                args.poll_interval,
                log,
                terminal=True,
            )
            summary = _verification_summary(
                completed,
                checkpoint_recovered=checkpoint_recovered,
                checkpoint_process_restarted=checkpoint_process_restarted,
                approval_submitted=approval_submitted,
                checkpoint_backend=args.checkpoint_backend,
            )
            log.section("verification_summary")
            log.json(summary)
            if not summary["passed"]:
                raise SystemExit(1)

    print(f"Live run log: {log_path}")


def _run_non_secret_preflight(args: argparse.Namespace, log: "_LiveLog") -> None:
    if args.skip_preflight:
        log.section("local_preflight")
        log.json({"status": "skipped", "reason": "--skip-preflight"})
        return
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    from scripts.preflight_credentialed_live_e2e import run_preflight

    summary = run_preflight(
        project_root=PROJECT_ROOT,
        compose_project=args.compose_project,
        check_compose=not args.skip_compose,
    )
    log.section("local_preflight")
    log.json(summary)
    if not summary["passed"]:
        raise SystemExit("Local preflight failed before credential prompts; fix errors or pass --skip-preflight.")


def _collect_credentials(checkpoint_backend: str) -> tuple[dict[str, str], dict[str, Any]]:
    print("SENTINEL real live E2E credential prompts")
    print("Secrets are not echoed. Press Enter on optional prompts to leave them unset.")
    env: dict[str, str] = {}
    env["GROQ_API_KEY"] = _prompt_secret("GROQ_API_KEY", required=True)
    env["GITHUB_TOKEN"] = _prompt_secret("GITHUB_TOKEN", required=True)
    env["GITHUB_OWNER"] = _prompt_text("GITHUB_OWNER", required=True, default=os.getenv("GITHUB_OWNER"))
    env["GITHUB_REPO"] = _prompt_text("GITHUB_REPO", required=True, default=os.getenv("GITHUB_REPO"))
    env["DISCORD_WEBHOOK_URL"] = _prompt_secret("DISCORD_WEBHOOK_URL", required=True)
    generated_token = secrets.token_urlsafe(32)
    env["SENTINEL_API_TOKEN"] = _prompt_secret("SENTINEL_API_TOKEN", required=True, default=generated_token)
    prompted_database_url = _prompt_text(
        "DATABASE_URL",
        required=True,
        default=os.getenv("DATABASE_URL") or LOCAL_POSTGRES_DATABASE_URL,
    )
    credential_meta: dict[str, Any] = {
        "database_url_prompted": True,
        "database_url_default": LOCAL_POSTGRES_DATABASE_URL,
        "checkpoint_backend": checkpoint_backend,
    }
    if checkpoint_backend == "sqlite":
        sqlite_checkpoint_url = _prompt_text(
            "SQLITE_CHECKPOINT_DATABASE_URL",
            required=True,
            default=os.getenv("SQLITE_CHECKPOINT_DATABASE_URL") or SQLITE_CHECKPOINT_DATABASE_URL,
        )
        env["DATABASE_URL"] = sqlite_checkpoint_url
        credential_meta["effective_database_url_prompt"] = "SQLITE_CHECKPOINT_DATABASE_URL"
        credential_meta["database_url_prompt_value_used_for_receiver"] = False
    else:
        env["DATABASE_URL"] = prompted_database_url
        credential_meta["effective_database_url_prompt"] = "DATABASE_URL"
        credential_meta["database_url_prompt_value_used_for_receiver"] = True
    env["REDIS_URL"] = _prompt_text(
        "REDIS_URL",
        required=True,
        default=os.getenv("REDIS_URL") or "redis://redis:6379/0",
    )
    env["PROMETHEUS_URL"] = _prompt_text("PROMETHEUS_URL", required=True, default=os.getenv("PROMETHEUS_URL") or "http://prometheus:9090")
    env["LOKI_URL"] = _prompt_text("LOKI_URL", required=True, default=os.getenv("LOKI_URL") or "http://loki:3100")
    env["SENTINEL_APPROVER_ID"] = _prompt_text(
        "SENTINEL_APPROVER_ID",
        required=True,
        default=os.getenv("SENTINEL_APPROVER_ID") or os.getenv("USER") or "eng-oncall",
    )
    env["SENTINEL_DEFAULT_SERVICE"] = _prompt_text(
        "SENTINEL_DEFAULT_SERVICE",
        required=True,
        default=os.getenv("SENTINEL_DEFAULT_SERVICE") or "payment-service",
    )
    host_kubeconfig = _prompt_text(
        "HOST/CONTAINER_KUBECONFIG",
        required=False,
        default=os.getenv("CONTAINER_KUBECONFIG") or str(Path.home() / ".kube" / "config"),
    )
    if host_kubeconfig:
        env["CONTAINER_KUBECONFIG"] = host_kubeconfig
        env["KUBECONFIG"] = "/root/.kube/config"
    env["KUBERNETES_NAMESPACE"] = _prompt_text(
        "KUBERNETES_NAMESPACE",
        required=True,
        default=os.getenv("KUBERNETES_NAMESPACE") or "default",
    )
    env["SENTINEL_MODEL"] = _prompt_text("SENTINEL_MODEL", required=True, default=os.getenv("SENTINEL_MODEL") or DEFAULT_GROQ_MODEL)
    for name in (
        "DD_API_KEY",
        "DD_APP_KEY",
        "DD_OAUTH_TOKEN",
        "PAGERDUTY_API_KEY",
        "PAGERDUTY_WEBHOOK_SECRET",
        "PAGERDUTY_WEBHOOK_SUBSCRIPTION_ID",
        "SLACK_BOT_TOKEN",
        "SLACK_CHANNEL_ID",
    ):
        value = _prompt_secret(name, required=False, default=os.getenv(name))
        if value:
            env[name] = value
    return env, credential_meta


def _prompt_text(name: str, *, required: bool, default: str | None = None) -> str:
    suffix = f" [{_display_default(default)}]" if default else ""
    while True:
        value = input(f"{name}{suffix}: ").strip()
        if not value and default:
            value = default
        if value or not required:
            return value
        print(f"{name} is required.")


def _prompt_secret(name: str, *, required: bool, default: str | None = None) -> str:
    suffix = " [set]" if default else ""
    while True:
        value = getpass.getpass(f"{name}{suffix}: ").strip()
        if not value and default:
            value = default
        if value or not required:
            return value
        print(f"{name} is required.")


def _display_default(value: str | None) -> str:
    if not value:
        return ""
    if len(value) > 80:
        return value[:77] + "..."
    return value


def _write_env_file(path: Path, env: dict[str, str]) -> None:
    lines = [f"{key}={_quote_env(value)}" for key, value in sorted(env.items()) if value]
    path.write_text("\n".join(lines) + "\n")
    path.chmod(0o600)


def _quote_env(value: str) -> str:
    if not value:
        return ""
    if any(char.isspace() for char in value) or value[0] in {"'", '"'}:
        return json.dumps(value)
    return value


def _load_or_prompt_payload(args: argparse.Namespace, log: "_LiveLog") -> dict[str, Any]:
    if args.payload_file:
        payload = json.loads(Path(args.payload_file).read_text())
        if not isinstance(payload, dict):
            raise SystemExit("Webhook payload file must contain a JSON object.")
        return payload
    print("Paste a real generic webhook JSON payload, then press Enter on a blank line.")
    print(
        "Or press Enter immediately to trigger the local real /slow-query workload, "
        "wait for Prometheus evidence, and build the webhook payload from that run."
    )
    lines: list[str] = []
    while True:
        line = input()
        if not line:
            break
        lines.append(line)
    if lines:
        payload = json.loads("\n".join(lines))
        if not isinstance(payload, dict):
            raise SystemExit("Webhook payload must be a JSON object.")
        return payload
    return _build_real_slow_query_payload(args, log)


def _build_real_slow_query_payload(args: argparse.Namespace, log: "_LiveLog") -> dict[str, Any]:
    print("Building a real local /slow-query incident payload.")
    print("This resets the live SQLite workload, sends real HTTP requests, and waits for Prometheus to scrape it.")
    incident_id = _prompt_text("REAL_INCIDENT_ID", required=True, default=f"LIVE-SLOW-{int(time.time())}")
    services = _prompt_services()
    evidence_note = _prompt_text(
        "REAL_EVIDENCE_NOTE",
        required=True,
        default="local /slow-query traffic produced Prometheus and Loki evidence",
    )
    workload = _prepare_slow_query_workload(args, log)
    occurred_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    return _generic_slow_query_payload(
        incident_id=incident_id,
        services=services,
        occurred_at=occurred_at,
        evidence_note=evidence_note,
        workload=workload,
    )


def _prompt_services() -> list[str]:
    services_raw = _prompt_text(
        "AFFECTED_SERVICES comma-separated, must include 2+ for subagent proof",
        required=True,
        default="payment-service,checkout-service",
    )
    services = [item.strip() for item in services_raw.split(",") if item.strip()]
    if len(services) < 2:
        raise SystemExit("The credentialed video run requires 2+ affected services so the subagent path is real.")
    return services


def _prepare_slow_query_workload(args: argparse.Namespace, log: "_LiveLog") -> dict[str, Any]:
    base_url = args.base_url.rstrip("/")
    prometheus_url = args.host_prometheus_url.rstrip("/")
    durations: list[float] = []
    errors = 0
    with httpx.Client(timeout=30.0) as client:
        reset = client.post(
            f"{base_url}/slow-query/reset",
            params={"row_count": args.slow_query_row_count},
        )
        reset_body = _response_body(reset)
        log.section("slow_query_reset")
        log.json({"code": reset.status_code, "body": reset_body})
        reset.raise_for_status()

        deadline = time.monotonic() + args.slow_query_load_seconds
        request_count = 0
        while time.monotonic() < deadline or request_count < args.slow_query_min_requests:
            try:
                response = client.get(f"{base_url}/slow-query")
                body = _response_body(response)
                if response.status_code >= 400:
                    errors += 1
                elif isinstance(body, dict):
                    duration = body.get("duration_ms")
                    if isinstance(duration, (int, float)):
                        durations.append(float(duration))
                response.raise_for_status()
            except Exception:
                errors += 1
            request_count += 1
            time.sleep(0.08)

    prometheus_sample = _wait_for_prometheus_sample(
        prometheus_url,
        service="payment-service",
        timeout_seconds=max(20, args.slow_query_alert_wait_seconds),
    )
    prometheus_alert = _wait_for_prometheus_alert(
        prometheus_url,
        timeout_seconds=args.slow_query_alert_wait_seconds,
    )
    workload = {
        "requests": request_count,
        "errors": errors,
        "max_duration_ms": max(durations) if durations else None,
        "last_duration_ms": durations[-1] if durations else None,
        "prometheus_sample": prometheus_sample,
        "prometheus_alert": prometheus_alert,
    }
    log.section("slow_query_workload_proof")
    log.json(workload)
    if not durations:
        raise RuntimeError("The live /slow-query workload produced no successful request durations.")
    if not isinstance(prometheus_sample.get("value_seconds"), (int, float)) or prometheus_sample["value_seconds"] <= 0:
        raise RuntimeError("Prometheus did not return a positive live /slow-query sample.")
    return workload


def _wait_for_prometheus_sample(prometheus_url: str, *, service: str, timeout_seconds: int) -> dict[str, Any]:
    query = f'sentinel_slow_query_last_duration_seconds{{service="{service}"}}'
    deadline = time.monotonic() + timeout_seconds
    latest: dict[str, Any] = {}
    while time.monotonic() < deadline:
        latest = _prometheus_query(prometheus_url, query)
        value = _latest_prometheus_sample(latest)
        if value is not None and value > 0:
            return {"query": query, "value_seconds": value, "response": latest}
        time.sleep(2)
    return {"query": query, "value_seconds": None, "response": latest}


def _wait_for_prometheus_alert(prometheus_url: str, *, timeout_seconds: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    latest: dict[str, Any] = {}
    while time.monotonic() < deadline:
        try:
            response = httpx.get(f"{prometheus_url}/api/v1/alerts", timeout=10.0)
            response.raise_for_status()
            latest = response.json()
        except Exception as exc:
            latest = {"error": str(exc)}
        for alert in latest.get("data", {}).get("alerts", []) if isinstance(latest.get("data"), dict) else []:
            labels = alert.get("labels") if isinstance(alert, dict) else {}
            if (
                isinstance(labels, dict)
                and labels.get("alertname") == "SentinelSlowQueryLatency"
                and alert.get("state") in {"firing", "pending"}
            ):
                return {"found": True, "alert": alert, "response": latest}
        time.sleep(2)
    return {"found": False, "response": latest}


def _prometheus_query(prometheus_url: str, query: str) -> dict[str, Any]:
    response = httpx.get(
        f"{prometheus_url}/api/v1/query",
        params={"query": query},
        timeout=10.0,
    )
    response.raise_for_status()
    body = response.json()
    if not isinstance(body, dict):
        raise RuntimeError("Prometheus query did not return a JSON object.")
    return body


def _latest_prometheus_sample(response: dict[str, Any]) -> float | None:
    data = response.get("data")
    result = data.get("result") if isinstance(data, dict) else None
    if not isinstance(result, list):
        return None
    latest: tuple[float, float] | None = None
    for item in result:
        if not isinstance(item, dict):
            continue
        value = item.get("value")
        if not isinstance(value, list) or len(value) < 2:
            continue
        try:
            timestamp = float(value[0])
            sample = float(value[1])
        except (TypeError, ValueError):
            continue
        if latest is None or timestamp >= latest[0]:
            latest = (timestamp, sample)
    return latest[1] if latest else None


def _generic_slow_query_payload(
    *,
    incident_id: str,
    services: list[str],
    occurred_at: str,
    evidence_note: str,
    workload: dict[str, Any],
) -> dict[str, Any]:
    alert = workload.get("prometheus_alert", {}).get("alert")
    labels = dict(alert.get("labels") or {}) if isinstance(alert, dict) else {}
    labels.setdefault("alertname", "SentinelSlowQueryLatency")
    labels.setdefault("severity", "critical")
    labels.setdefault("service", services[0])
    labels.setdefault("route", "/slow-query")
    annotations = dict(alert.get("annotations") or {}) if isinstance(alert, dict) else {}
    annotations.setdefault("summary", f"{services[0]} /slow-query latency spike from missing SQLite index")
    annotations.setdefault("description", evidence_note)
    return {
        "receiver": "sentinel",
        "source": "prometheus_manual_generic_webhook",
        "status": "firing",
        "incident_id": incident_id,
        "affected_services": services,
        "groupKey": f'{{alertname="SentinelSlowQueryLatency", service="{services[0]}"}}',
        "groupLabels": {"alertname": "SentinelSlowQueryLatency", "service": services[0]},
        "commonLabels": labels,
        "commonAnnotations": annotations,
        "live_workload_proof": {
            "requests": workload.get("requests"),
            "errors": workload.get("errors"),
            "max_duration_ms": workload.get("max_duration_ms"),
            "last_duration_ms": workload.get("last_duration_ms"),
            "prometheus_value_seconds": workload.get("prometheus_sample", {}).get("value_seconds"),
            "prometheus_alert_found": workload.get("prometheus_alert", {}).get("found"),
        },
        "alerts": [
            {
                "status": "firing",
                "fingerprint": incident_id,
                "startsAt": occurred_at,
                "labels": {**labels, "service": service},
                "annotations": annotations,
            }
            for service in services
        ],
    }


def _post_webhook(client: httpx.Client, base_url: str, payload: dict[str, Any], log: "_LiveLog") -> dict[str, Any]:
    response = client.post(f"{base_url.rstrip('/')}/webhooks/generic", json=payload)
    body = _response_body(response)
    log.json({"webhook_response_code": response.status_code, "webhook_response": body})
    response.raise_for_status()
    if not isinstance(body, dict) or not body.get("investigation_id"):
        raise RuntimeError(f"Webhook did not create an investigation: {body}")
    return body


def _poll_until(
    client: httpx.Client,
    base_url: str,
    investigation_id: str,
    headers: dict[str, str],
    timeout_seconds: int,
    poll_interval: float,
    log: "_LiveLog",
    *,
    stop_status: str | None = None,
    terminal: bool = False,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    latest: dict[str, Any] = {}
    while time.monotonic() < deadline:
        latest = _get_status(client, base_url, investigation_id, headers)
        log.section(f"status_{latest.get('status', 'unknown')}")
        log.json(latest)
        if stop_status and latest.get("status") == stop_status:
            return latest
        if terminal and latest.get("status") in {"completed", "failed", "insufficient_confidence"}:
            return latest
        if latest.get("status") in {"failed", "insufficient_confidence"}:
            return latest
        time.sleep(poll_interval)
    latest["poll_timeout"] = True
    return latest


def _get_status(client: httpx.Client, base_url: str, investigation_id: str, headers: dict[str, str]) -> dict[str, Any]:
    response = client.get(f"{base_url.rstrip('/')}/investigations/{investigation_id}", headers=headers)
    response.raise_for_status()
    body = response.json()
    if not isinstance(body, dict):
        raise RuntimeError("Investigation status was not a JSON object.")
    return body


def _approval_payload(status: dict[str, Any]) -> dict[str, str]:
    request_id = status.get("approval_request_id")
    approvers = status.get("approval_approver_ids")
    approver_id = None
    if isinstance(approvers, list):
        approver_id = next((item for item in approvers if isinstance(item, str) and item.strip()), None)
    if not isinstance(request_id, str) or not request_id.strip() or not approver_id:
        raise RuntimeError("Status does not contain an approval request and approver.")
    investigation_id = status["investigation_id"]
    return {
        "request_id": request_id,
        "approver_id": approver_id,
        "decision": "approve",
        "idempotency_key": f"{investigation_id}:credentialed-live-approval:{request_id}:{approver_id}",
    }


def _verification_summary(
    status: dict[str, Any],
    *,
    checkpoint_recovered: bool,
    checkpoint_process_restarted: bool,
    approval_submitted: bool,
    checkpoint_backend: str,
) -> dict[str, Any]:
    model_plans = status.get("model_tool_plans") if isinstance(status.get("model_tool_plans"), list) else []
    service_reports = status.get("service_reports") if isinstance(status.get("service_reports"), list) else []
    tool_call_records = status.get("tool_call_records") if isinstance(status.get("tool_call_records"), list) else []
    state_transitions = status.get("state_transitions") if isinstance(status.get("state_transitions"), list) else []
    evidence_records = status.get("evidence_records") if isinstance(status.get("evidence_records"), list) else []
    tool_calls = int(status.get("tool_calls") or 0)
    recorded_tool_names = [
        str(record.get("tool_name"))
        for record in tool_call_records
        if isinstance(record, dict) and record.get("tool_name")
    ]
    successful_tool_names = {
        str(record.get("tool_name"))
        for record in tool_call_records
        if isinstance(record, dict) and record.get("tool_name") and record.get("success") is True
    }
    has_groq_model = any(
        isinstance(plan, dict) and plan.get("source") == "model" and plan.get("provider") == "groq"
        for plan in model_plans
    )
    has_model_reasoning = any(
        isinstance(plan, dict)
        and plan.get("source") == "model"
        and plan.get("provider") == "groq"
        and bool(str(plan.get("model_rationale") or "").strip())
        for plan in model_plans
    )
    has_full_tool_call_records = (
        len(tool_call_records) >= tool_calls >= MIN_TOOL_CALLS
        and all(
            isinstance(record, dict)
            and record.get("tool_name")
            and record.get("state")
            and record.get("success") is not None
            and bool(str(record.get("reasoning_trace") or "").strip())
            for record in tool_call_records
        )
    )
    transition_states = {
        str((event.get("payload") or {}).get("state"))
        for event in state_transitions
        if isinstance(event, dict) and isinstance(event.get("payload"), dict)
    }
    has_state_transition_records = {
        "received",
        "triage",
        "evidence_collection",
        "response_proposal",
        "remediation",
        "post_mortem",
    }.issubset(transition_states)
    has_live_evidence_records = any(
        isinstance(record, dict) and str(record.get("provenance") or "").startswith("live::")
        for record in evidence_records
    )
    has_subagent = "infra.spawn_service_investigator" in recorded_tool_names and (
        bool(service_reports) or any(
            isinstance(step, dict) and "subagent" in str(step.get("action", "")).lower()
            for step in status.get("plan_steps", [])
            if isinstance(step, dict)
        )
    )
    has_discord_message = bool(status.get("discord_notified")) and bool(
        str(status.get("last_discord_message") or "").strip()
    )
    remediation_tool_executed = bool(
        {"infra.rollback_deployment", "infra.add_database_index"} & successful_tool_names
    )
    remediation = status.get("remediation_result")
    remediation_executed = (
        isinstance(remediation, dict)
        and remediation.get("status") == "executed"
        and remediation_tool_executed
    )
    has_subagent_plan_step = bool(service_reports) or any(
        isinstance(step, dict) and "subagent" in str(step.get("action", "")).lower()
        for step in status.get("plan_steps", [])
        if isinstance(step, dict)
    )
    passed = (
        status.get("status") == "completed"
        and approval_submitted
        and checkpoint_recovered
        and checkpoint_process_restarted
        and checkpoint_backend == "sqlite"
        and tool_calls >= MIN_TOOL_CALLS
        and has_full_tool_call_records
        and has_state_transition_records
        and has_groq_model
        and has_model_reasoning
        and has_subagent
        and has_subagent_plan_step
        and has_live_evidence_records
        and has_discord_message
        and remediation_executed
    )
    return {
        "passed": passed,
        "status": status.get("status"),
        "tool_calls": tool_calls,
        "tool_call_records": len(tool_call_records),
        "has_full_tool_call_records": has_full_tool_call_records,
        "has_state_transition_records": has_state_transition_records,
        "has_groq_model_plan": has_groq_model,
        "has_model_reasoning": has_model_reasoning,
        "has_subagent": has_subagent,
        "has_live_evidence_records": has_live_evidence_records,
        "checkpoint_backend": checkpoint_backend,
        "checkpoint_recovered": checkpoint_recovered,
        "checkpoint_process_restarted": checkpoint_process_restarted,
        "approval_submitted": approval_submitted,
        "discord_notified": bool(status.get("discord_notified")),
        "has_discord_message": has_discord_message,
        "remediation_status": remediation.get("status") if isinstance(remediation, dict) else None,
        "remediation_tool_executed": remediation_tool_executed,
        "model_tool_plans": model_plans,
        "service_reports": service_reports,
        "last_discord_message": status.get("last_discord_message"),
    }


def _finalize_failure(log: "_LiveLog", status: dict[str, Any], *, checkpoint_recovered: bool) -> None:
    log.section("verification_failed")
    log.json(
        _verification_summary(
            status,
            checkpoint_recovered=checkpoint_recovered,
            checkpoint_process_restarted=False,
            approval_submitted=False,
            checkpoint_backend="unknown",
        )
    )


def _wait_receiver_ready(base_url: str, api_token: str, timeout_seconds: int, log: "_LiveLog") -> None:
    deadline = time.monotonic() + timeout_seconds
    headers = {"Authorization": f"Bearer {api_token}"}
    latest: Any = None
    with httpx.Client(timeout=10.0) as client:
        while time.monotonic() < deadline:
            try:
                response = client.get(f"{base_url.rstrip('/')}/ready/live", headers=headers)
                latest = _response_body(response)
                if response.status_code == 200 and isinstance(latest, dict) and latest.get("ready") is True:
                    log.section("receiver_ready")
                    log.json(latest)
                    return
            except httpx.HTTPError as exc:
                latest = {"error": str(exc)}
            time.sleep(3)
    log.section("receiver_not_ready")
    log.json(latest if isinstance(latest, dict) else {"latest": latest})
    raise RuntimeError("Receiver did not become ready.")


def _run_compose(command: list[str], env_file: Path, args: argparse.Namespace, log: "_LiveLog") -> None:
    full = ["docker", "compose", "--env-file", str(env_file), "-p", args.compose_project, *command]
    log.section("command")
    log.json({"cmd": _redacted_command(full)})
    proc = subprocess.run(full, cwd=PROJECT_ROOT, text=True, capture_output=True, check=False)
    log.json(
        {
            "returncode": proc.returncode,
            "stdout": proc.stdout[-4000:],
            "stderr": proc.stderr[-4000:],
        }
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed: {_redacted_command(full)}")


def _response_body(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return response.text


def _receiver_process(status: dict[str, Any]) -> dict[str, Any]:
    process = status.get("receiver_process")
    return process if isinstance(process, dict) else {}


def _receiver_process_changed(before: dict[str, Any], after: dict[str, Any]) -> bool:
    before_started = before.get("started_at")
    after_started = after.get("started_at")
    if isinstance(before_started, str) and isinstance(after_started, str):
        return bool(before_started and after_started and before_started != after_started)
    before_pid = before.get("pid")
    after_pid = after.get("pid")
    return before_pid is not None and after_pid is not None and before_pid != after_pid


def _payload_incident_id(payload: dict[str, Any]) -> str | None:
    for key in ("incident_id", "alert_id", "id", "fingerprint"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    alerts = payload.get("alerts")
    if isinstance(alerts, list):
        for item in alerts:
            if isinstance(item, dict):
                value = item.get("fingerprint") or item.get("id")
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return None


def _redacted_env_summary(env: dict[str, str]) -> dict[str, str]:
    secret_names = ("KEY", "TOKEN", "SECRET", "WEBHOOK", "PASSWORD")
    secret_keys = {"DATABASE_URL", "REDIS_URL"}
    summary = {}
    for key, value in sorted(env.items()):
        summary[key] = "[set]" if (key in secret_keys or any(marker in key for marker in secret_names)) and value else value
    return summary


def _redacted_command(command: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


class _LiveLog:
    def __init__(self, path: Path):
        self.path = path
        self.handle = None

    def __enter__(self) -> "_LiveLog":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("a")
        self.section("live_run_started")
        self.json({"started_at": datetime.now(UTC).isoformat(), "log_path": str(self.path)})
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc:
            self.section("live_run_exception")
            self.json({"error": str(exc)})
        self.section("live_run_finished")
        self.json({"finished_at": datetime.now(UTC).isoformat()})
        assert self.handle is not None
        self.handle.close()

    def section(self, name: str) -> None:
        assert self.handle is not None
        line = f"\n=== {datetime.now(UTC).isoformat()} {name} ===\n"
        self.handle.write(line)
        self.handle.flush()
        print(line, end="")

    def json(self, payload: Any) -> None:
        assert self.handle is not None
        text = json.dumps(payload, indent=2, sort_keys=True, default=str)
        self.handle.write(text + "\n")
        self.handle.flush()
        print(text)


if __name__ == "__main__":
    main()
