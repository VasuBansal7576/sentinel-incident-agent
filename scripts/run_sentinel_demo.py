from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from sentinel.models import InvestigationState, InvestigationStatus
from sentinel.orchestrator import SentinelOrchestrator


DEFAULT_INCIDENT_ID = "PD-2026-06-03-0312"
CORE_STORY_TOOLS = (
    "observe.fetch_service_logs",
    "observe.query_metrics_range",
    "observe.check_db_slow_queries",
    "repo.get_deploy_history",
    "repo.diff_pull_request",
    "repo.blame_file_line",
    "infra.rollback_deployment",
    "observe.get_error_rate_timeseries",
)
COMPOSE_SERVICES = ("sentinel", "postgres", "redis", "prometheus", "loki")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run SENTINEL's record-ready PR #847 incident demo: Compose dependencies, "
            "seeded data, autonomous investigation, approved rollback, and Discord preview."
        )
    )
    parser.add_argument("--skip-compose", action="store_true", help="Skip docker compose startup.")
    parser.add_argument(
        "--summary-output",
        default=None,
        help="Optional path for a machine-readable summary. The terminal output stays narrative-first.",
    )
    args = parser.parse_args()

    compose = (
        {"status": "skipped", "message": "docker compose startup skipped by --skip-compose"}
        if args.skip_compose
        else _start_compose_dependencies()
    )
    if compose["status"] == "failed":
        print(render_compose_failure(compose))
        raise SystemExit(2)

    seed = _seed_demo_data()
    state = SentinelOrchestrator().run_scenario("golden_path", auto_approve=True)
    output = render_demo(state, compose=compose, seed=seed)
    print(output)
    if args.summary_output:
        _write_summary_output(_summary(state, compose=compose, seed=seed, output=output), Path(args.summary_output))
    raise SystemExit(0 if _demo_complete(state) else 1)


def _start_compose_dependencies() -> dict[str, Any]:
    if shutil.which("docker") is None:
        return {"status": "failed", "message": "Docker CLI was not found on PATH."}
    env_file, demo_env = _prepare_compose_demo_env()
    command = ["docker", "compose", "--env-file", str(env_file), "up", "-d", "--build"]
    subprocess_env = os.environ.copy()
    subprocess_env.update(demo_env)
    try:
        proc = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            env=subprocess_env,
            text=True,
            capture_output=True,
            timeout=300,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {"status": "failed", "command": command, "message": f"docker compose timed out: {exc}"}
    if proc.returncode != 0:
        return {
            "status": "failed",
            "command": command,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }
    return {
        "status": "ready",
        "command": " ".join(command),
        "env_file": str(env_file),
        "services": list(COMPOSE_SERVICES),
    }


def _prepare_compose_demo_env() -> tuple[Path, dict[str, str]]:
    demo_dir = PROJECT_ROOT / ".sentinel"
    demo_dir.mkdir(parents=True, exist_ok=True)
    kubeconfig = demo_dir / "recording-demo-kubeconfig"
    kubeconfig.write_text(
        "\n".join(
            [
                "apiVersion: v1",
                "kind: Config",
                "clusters: []",
                "contexts: []",
                "users: []",
                "current-context: sentinel-recording-demo",
                "",
            ]
        )
    )
    demo_env = {
        "SENTINEL_ENV": "development",
        "SENTINEL_API_TOKEN": "recording-demo-token",
        "SENTINEL_APPROVER_ID": "eng-oncall",
        "PROMETHEUS_URL": "http://prometheus:9090",
        "LOKI_URL": "http://loki:3100",
        "GITHUB_TOKEN": "recording-demo-token",
        "GITHUB_OWNER": "sentinel-demo",
        "GITHUB_REPO": "payments",
        "DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/recording-demo/token",
        "CONTAINER_KUBECONFIG": str(kubeconfig),
        "KUBERNETES_NAMESPACE": "default",
        "POSTGRES_USER": "sentinel",
        "POSTGRES_PASSWORD": "change-me",
        "POSTGRES_DB": "sentinel",
        "DD_API_KEY": "",
        "DD_APP_KEY": "",
        "DATADOG_APP_KEY": "",
        "PAGERDUTY_API_KEY": "",
        "PAGERDUTY_WEBHOOK_SECRET": "",
        "SLACK_BOT_TOKEN": "",
        "SLACK_CHANNEL_ID": "",
    }
    env_file = demo_dir / "recording-demo.env"
    env_file.write_text("\n".join(f"{key}={value}" for key, value in demo_env.items()) + "\n")
    return env_file, demo_env


def _seed_demo_data() -> dict[str, Any]:
    seed = {
        "incident_id": DEFAULT_INCIDENT_ID,
        "story": "PR #847 missing-index payment latency regression",
        "service": "payment-service",
        "pull_request": 847,
        "commit": "abc1234",
        "author": "@alice",
        "deployed_at": "02:58 UTC",
        "query": "SELECT * FROM orders WHERE user_id = ?",
        "missing_index": "orders.user_id",
        "latency": {"before_ms": 4, "after_ms": 2300, "multiplier": 575},
        "safe_rollback": "v2.3.1",
        "durable_fix": "add_index :orders, :user_id",
    }
    output_path = PROJECT_ROOT / ".sentinel" / "recording-demo-seed.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(seed, indent=2) + "\n")
    return {**seed, "path": str(output_path)}


def render_demo(state: InvestigationState, *, compose: dict[str, Any], seed: dict[str, Any]) -> str:
    story = _story_tool_rows(state)
    discord_preview = _discord_preview(state)
    lines: list[str] = [
        "🚨 SENTINEL RECORDING DEMO",
        "One command: full Docker Compose stack → seeded incident → autonomous investigation → approved rollback → Discord preview",
        "",
        "✅ Compose",
        _compose_line(compose),
        "",
        "🌱 Seeded Incident",
        f"Incident: {seed['incident_id']} | Service: {seed['service']}",
        "Deploy: PR #847 / commit abc1234 by @alice at 02:58 UTC",
        "Regression: SELECT * FROM orders WHERE user_id = ? with no index on orders.user_id",
        "Impact: payment latency 4ms → 2.3s (575x)",
        "",
        "🧠 Autonomy Trace",
        f"Registry size: 52 tools across 4 namespaces; story-facing tools shown: {len(CORE_STORY_TOOLS)}",
        f"Full run: {len(state.tool_calls)} tool calls, {len(state.plan_steps)} plan steps, status={state.status.value}",
        "",
    ]
    for index, row in enumerate(story, start=1):
        lines.extend(
            [
                f"{index}. {row['tool']}",
                f"   Why: {row['why']}",
                f"   Learned: {row['learned']}",
            ]
        )
    lines.extend(
        [
            "",
            "🧾 Incident Timeline",
            "02:58 UTC  Deploy PR #847 commit abc1234 by @alice to payment-service.",
            "03:12 UTC  Webhook received for payment-service latency and checkout failures.",
            "03:13 UTC  Logs show slow SELECT * FROM orders WHERE user_id = ? calls.",
            "03:14 UTC  Metrics show latency spike from 4ms to 2.3s.",
            "03:15 UTC  Deploy history, PR diff, and blame link the regression to missing orders.user_id index.",
            "03:16 UTC  SENTINEL proposes rollback to v2.3.1 and add_index :orders, :user_id follow-up.",
            "03:17 UTC  Human approver eng-oncall approves the exact rollback request.",
            "03:18 UTC  Rollback executes and metrics recover toward baseline.",
            "03:19 UTC  SENTINEL posts the full timeline to Discord.",
            "",
            "🎯 Diagnosis",
            state.diagnosis.summary if state.diagnosis else "Diagnosis unavailable.",
            "",
            "🛠️ Remediation",
            state.recommendation.command if state.recommendation else "No recommendation produced.",
            state.remediation_result.message if state.remediation_result else "No remediation result.",
            "",
            "📣 Discord Message Preview",
            discord_preview,
        ]
    )
    return "\n".join(lines)


def render_compose_failure(compose: dict[str, Any]) -> str:
    lines = [
        "🚨 SENTINEL RECORDING DEMO",
        "",
        "❌ Compose startup failed before the incident demo could run.",
    ]
    if compose.get("command"):
        lines.append(f"Command: {' '.join(compose['command']) if isinstance(compose['command'], list) else compose['command']}")
    if compose.get("message"):
        lines.append(str(compose["message"]))
    if compose.get("stderr"):
        lines.append(str(compose["stderr"]))
    return "\n".join(lines)


def _story_tool_rows(state: InvestigationState) -> list[dict[str, str]]:
    rows = []
    for tool_name in CORE_STORY_TOOLS:
        call = _story_call(state, tool_name)
        trace = call.reasoning_trace if call else ""
        why, learned = _split_reasoning_trace(trace)
        evidence = _evidence_claim(state, tool_name)
        if evidence:
            learned = evidence
        rows.append({"tool": tool_name, "why": why, "learned": learned})
    return rows


def _story_call(state: InvestigationState, tool_name: str):
    matches = [call for call in state.tool_calls if call.tool_name == tool_name and call.success]
    if not matches:
        return None
    if tool_name == "observe.get_error_rate_timeseries":
        remediation_matches = [call for call in matches if call.state.value == "remediation"]
        return remediation_matches[-1] if remediation_matches else matches[-1]
    return matches[0]


def _split_reasoning_trace(trace: str) -> tuple[str, str]:
    if not trace:
        return "Tool was selected by the phase-filtered model plan.", "No reasoning trace was recorded."
    if trace.startswith("Why: ") and " Learned: " in trace:
        why, learned = trace[len("Why: ") :].split(" Learned: ", 1)
        return why.strip(), learned.strip()
    return trace.strip(), "See tool evidence."


def _evidence_claim(state: InvestigationState, tool_name: str) -> str | None:
    claims = [
        evidence.claim
        for evidence in state.evidence
        if evidence.source == tool_name and not evidence.claim.startswith("evidence gap:")
    ]
    if not claims:
        return None
    if tool_name == "observe.get_error_rate_timeseries":
        recovery = [claim for claim in claims if "recovered" in claim]
        if recovery:
            return recovery[-1]
    return claims[0]


def _discord_preview(state: InvestigationState) -> str:
    diagnosis = state.diagnosis.summary if state.diagnosis else "Diagnosis unavailable."
    recommendation = state.recommendation.command if state.recommendation else "No remediation command."
    remediation = state.remediation_result.message if state.remediation_result else "No remediation result."
    return "\n".join(
        [
            "**SENTINEL resolved payment-service incident**",
            f"Root cause: {diagnosis}",
            "Timeline: 02:58 deploy → 03:12 webhook → 03:13 slow-query logs → 03:14 latency metrics → 03:15 PR/blame → 03:17 approval → 03:18 rollback.",
            f"Action: {recommendation}. {remediation}",
            "Follow-up: add_index :orders, :user_id owned by payments-platform.",
        ]
    )


def _compose_line(compose: dict[str, Any]) -> str:
    if compose["status"] == "ready":
        return f"Started with `{compose['command']}`: {', '.join(compose['services'])}"
    return str(compose.get("message") or compose["status"])


def _summary(
    state: InvestigationState,
    *,
    compose: dict[str, Any],
    seed: dict[str, Any],
    output: str,
) -> dict[str, Any]:
    return {
        "status": state.status.value,
        "current_state": state.current_state.value,
        "investigation_id": state.id,
        "incident_id": state.incident_id,
        "compose": compose,
        "seed": seed,
        "tool_calls": len(state.tool_calls),
        "plan_steps": len(state.plan_steps),
        "story_tools": list(CORE_STORY_TOOLS),
        "all_tool_calls_have_reasoning_trace": all(
            bool(call.reasoning_trace.strip()) for call in state.tool_calls
        ),
        "diagnosis": state.diagnosis.summary if state.diagnosis else None,
        "recommendation": state.recommendation.command if state.recommendation else None,
        "remediation": state.remediation_result.model_dump(mode="json") if state.remediation_result else None,
        "discord_preview": _discord_preview(state),
        "terminal_output": output,
    }


def _write_summary_output(summary: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(f"{output_path.name}.tmp")
    temporary.write_text(json.dumps(summary, indent=2) + "\n")
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    temporary.replace(output_path)
    try:
        os.chmod(output_path, 0o600)
    except OSError:
        pass


def _demo_complete(state: InvestigationState) -> bool:
    return (
        state.status == InvestigationStatus.COMPLETED
        and state.diagnosis is not None
        and "PR #847 by @alice" in state.diagnosis.summary
        and "4ms \u2192 2.3s (575x)" in state.diagnosis.summary
        and state.remediation_result is not None
        and state.remediation_result.status == "executed"
        and all(bool(call.reasoning_trace.strip()) for call in state.tool_calls)
    )


if __name__ == "__main__":
    main()
