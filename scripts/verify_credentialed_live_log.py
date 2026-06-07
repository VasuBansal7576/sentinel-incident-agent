from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.run_credentialed_live_e2e import (  # noqa: E402
    LOCAL_POSTGRES_DATABASE_URL,
    MIN_TOOL_CALLS,
    _receiver_process_changed,
    _verification_summary,
)


SECTION_RE = re.compile(r"^===\s+\S+\s+(.+?)\s+===$")
REQUIRED_PROMPT_KEYS = {
    "GROQ_API_KEY",
    "GITHUB_TOKEN",
    "DISCORD_WEBHOOK_URL",
    "SENTINEL_API_TOKEN",
    "DATABASE_URL",
    "REDIS_URL",
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify that a credentialed SENTINEL live-run log satisfies the video-proof gates."
    )
    parser.add_argument("log_path", type=Path)
    args = parser.parse_args()

    summary = verify_log(args.log_path)
    print(json.dumps(summary, indent=2, sort_keys=True))
    raise SystemExit(0 if summary["passed"] else 1)


def verify_log(path: Path) -> dict[str, Any]:
    entries = parse_log(path)
    credential_payload = _last_payload(entries, "credential_prompts_complete") or {}
    checkpoint_restart = _last_payload(entries, "checkpoint_restart") or {}
    checkpoint_status_payload = _last_payload(entries, "checkpoint_recovered_status") or {}
    approval_submitted = _last_payload(entries, "approval_submitted") or {}
    final_status = _last_status(entries)
    logged_summary = _last_payload(entries, "verification_summary") or {}
    webhook_payload = _last_payload(entries, "posting_real_generic_webhook") or {}

    checkpoint_status = checkpoint_status_payload.get("status")
    if not isinstance(checkpoint_status, dict):
        checkpoint_status = {}
    checkpoint_process_restarted = _checkpoint_process_restarted(checkpoint_status_payload)
    checkpoint_recovered = (
        bool(checkpoint_process_restarted)
        and checkpoint_status.get("investigation_id") == checkpoint_restart.get("investigation_id")
        and checkpoint_status.get("status") == "waiting_for_approval"
        and int(checkpoint_status.get("tool_calls") or 0) >= int(checkpoint_restart.get("tool_calls_before_restart") or 0)
    )
    approval_ok = approval_submitted.get("code") in {200, 201, 202}
    checkpoint_backend = str(checkpoint_restart.get("checkpoint_backend") or "unknown")
    reconstructed = _verification_summary(
        final_status,
        checkpoint_recovered=checkpoint_recovered,
        checkpoint_process_restarted=bool(checkpoint_process_restarted),
        approval_submitted=approval_ok,
        checkpoint_backend=checkpoint_backend,
    )
    credential_check = _credential_prompt_check(credential_payload)
    webhook_check = {
        "posted": bool(webhook_payload.get("incident_id")),
        "incident_id": webhook_payload.get("incident_id"),
        "affected_services": _affected_services(webhook_payload.get("payload")),
        "workload_proof": _workload_proof(webhook_payload.get("payload")),
    }
    generated_slow_query_payload = _payload_source(webhook_payload.get("payload")) == "prometheus_manual_generic_webhook"
    logged_summary_passed = logged_summary.get("passed") is True
    passed = (
        credential_check["passed"]
        and webhook_check["posted"]
        and len(webhook_check["affected_services"]) >= 2
        and (not generated_slow_query_payload or webhook_check["workload_proof"]["passed"])
        and checkpoint_recovered
        and approval_ok
        and reconstructed["passed"]
        and logged_summary_passed
    )
    return {
        "passed": passed,
        "log_path": str(path),
        "credential_prompts": credential_check,
        "webhook": webhook_check,
        "checkpoint_recovered": checkpoint_recovered,
        "checkpoint_process_restarted": bool(checkpoint_process_restarted),
        "checkpoint_backend": checkpoint_backend,
        "approval_submitted": approval_ok,
        "logged_verification_summary_passed": logged_summary_passed,
        "tool_calls": reconstructed["tool_calls"],
        "minimum_tool_calls": MIN_TOOL_CALLS,
        "has_groq_model_plan": reconstructed["has_groq_model_plan"],
        "has_model_reasoning": reconstructed["has_model_reasoning"],
        "has_subagent": reconstructed["has_subagent"],
        "has_live_evidence_records": reconstructed["has_live_evidence_records"],
        "discord_notified": reconstructed["discord_notified"],
        "has_discord_message": reconstructed["has_discord_message"],
        "remediation_status": reconstructed["remediation_status"],
        "remediation_tool_executed": reconstructed["remediation_tool_executed"],
        "reconstructed_verification": reconstructed,
    }


def parse_log(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(path)
    entries: list[dict[str, Any]] = []
    current_section: str | None = None
    buffer: list[str] = []
    for line in path.read_text().splitlines():
        match = SECTION_RE.match(line.strip())
        if match:
            _flush_section(entries, current_section, "\n".join(buffer))
            current_section = match.group(1)
            buffer = []
        elif current_section is not None:
            buffer.append(line)
    _flush_section(entries, current_section, "\n".join(buffer))
    return entries


def _flush_section(entries: list[dict[str, Any]], section: str | None, text: str) -> None:
    if not section:
        return
    decoder = json.JSONDecoder()
    index = 0
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            break
        try:
            payload, end = decoder.raw_decode(text, index)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Could not parse JSON in section {section!r}: {exc}") from exc
        entries.append({"section": section, "payload": payload})
        index = end


def _last_payload(entries: list[dict[str, Any]], section: str) -> dict[str, Any] | None:
    for entry in reversed(entries):
        if entry["section"] == section and isinstance(entry["payload"], dict):
            return entry["payload"]
    return None


def _last_status(entries: list[dict[str, Any]]) -> dict[str, Any]:
    for entry in reversed(entries):
        if str(entry["section"]).startswith("status_") and isinstance(entry["payload"], dict):
            return entry["payload"]
    return {}


def _credential_prompt_check(payload: dict[str, Any]) -> dict[str, Any]:
    redacted_env = payload.get("redacted_env") if isinstance(payload.get("redacted_env"), dict) else {}
    credential_meta = (
        payload.get("credential_prompt_meta")
        if isinstance(payload.get("credential_prompt_meta"), dict)
        else {}
    )
    present = sorted(key for key in REQUIRED_PROMPT_KEYS if redacted_env.get(key))
    missing = sorted(REQUIRED_PROMPT_KEYS - set(present))
    postgres_default_ok = credential_meta.get("database_url_default") == LOCAL_POSTGRES_DATABASE_URL
    sqlite_checkpoint_ok = (
        credential_meta.get("checkpoint_backend") == "sqlite"
        and credential_meta.get("effective_database_url_prompt") == "SQLITE_CHECKPOINT_DATABASE_URL"
    )
    return {
        "passed": not missing and postgres_default_ok and sqlite_checkpoint_ok,
        "present": present,
        "missing": missing,
        "postgres_database_default": postgres_default_ok,
        "sqlite_checkpoint_prompt": sqlite_checkpoint_ok,
    }


def _checkpoint_process_restarted(payload: dict[str, Any]) -> bool:
    before = payload.get("receiver_process_before_restart")
    after = payload.get("receiver_process_after_restart")
    explicit = payload.get("checkpoint_process_restarted") is True
    if isinstance(before, dict) and isinstance(after, dict):
        return explicit and _receiver_process_changed(before, after)
    return explicit


def _affected_services(payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        return []
    values = payload.get("affected_services") or payload.get("services")
    if isinstance(values, list):
        return [item for item in values if isinstance(item, str) and item.strip()]
    value = payload.get("affected_service") or payload.get("service")
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _payload_source(payload: Any) -> str | None:
    if not isinstance(payload, dict):
        return None
    source = payload.get("source")
    return source.strip() if isinstance(source, str) and source.strip() else None


def _workload_proof(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {"passed": False, "reason": "missing payload"}
    proof = payload.get("live_workload_proof")
    if not isinstance(proof, dict):
        return {"passed": False, "reason": "missing live_workload_proof"}
    requests = proof.get("requests")
    errors = proof.get("errors")
    sample = proof.get("prometheus_value_seconds")
    passed = (
        isinstance(requests, int)
        and requests > 0
        and isinstance(errors, int)
        and errors >= 0
        and isinstance(sample, (int, float))
        and sample > 0
    )
    return {
        "passed": passed,
        "requests": requests,
        "errors": errors,
        "prometheus_value_seconds": sample,
        "prometheus_alert_found": proof.get("prometheus_alert_found"),
    }


if __name__ == "__main__":
    main()
