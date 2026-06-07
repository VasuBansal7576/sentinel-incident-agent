import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_credentialed_live_log.py"
spec = importlib.util.spec_from_file_location("verify_credentialed_live_log", SCRIPT)
verify = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(verify)


def test_verify_credentialed_live_log_accepts_full_real_run_proof(tmp_path):
    log_path = tmp_path / "live-run.log"
    log_path.write_text(_live_log_text())

    summary = verify.verify_log(log_path)

    assert summary["passed"] is True
    assert summary["tool_calls"] == 20
    assert summary["checkpoint_process_restarted"] is True
    assert summary["has_groq_model_plan"] is True
    assert summary["has_subagent"] is True
    assert summary["discord_notified"] is True


def test_verify_credentialed_live_log_follows_terminal_transcript_structured_pointer(tmp_path):
    structured = tmp_path / "live-run.structured.log"
    terminal = tmp_path / "live-run.log"
    structured.write_text(_live_log_text())
    terminal.write_text(
        "\n".join(
            [
                "SENTINEL credentialed live E2E recording",
                f"terminal_log: {terminal}",
                f"structured_log: {structured}",
                "Secrets are entered in the Python prompts; getpass values are not echoed.",
            ]
        )
    )

    summary = verify.verify_log(terminal)

    assert summary["passed"] is True
    assert summary["log_path"] == str(terminal)
    assert summary["structured_log_path"] == str(structured)


def test_verify_credentialed_live_log_rejects_thin_summary_without_process_restart(tmp_path):
    log_path = tmp_path / "live-run.log"
    log_path.write_text(
        _live_log_text(
            checkpoint_process_restarted=False,
            before_process={"pid": 10, "started_at": "2026-06-07T07:00:00+00:00"},
            after_process={"pid": 10, "started_at": "2026-06-07T07:00:00+00:00"},
        )
    )

    summary = verify.verify_log(log_path)

    assert summary["passed"] is False
    assert summary["checkpoint_process_restarted"] is False


def test_verify_credentialed_live_log_rejects_single_service_payload(tmp_path):
    log_path = tmp_path / "live-run.log"
    log_path.write_text(_live_log_text(affected_services=["checkout-service"]))

    summary = verify.verify_log(log_path)

    assert summary["passed"] is False
    assert summary["webhook"]["affected_services"] == ["checkout-service"]


def test_verify_credentialed_live_log_rejects_generated_payload_without_workload_proof(tmp_path):
    log_path = tmp_path / "live-run.log"
    log_path.write_text(_live_log_text(generated_payload=True, include_workload_proof=False))

    summary = verify.verify_log(log_path)

    assert summary["passed"] is False
    assert summary["webhook"]["workload_proof"]["passed"] is False


def test_verify_credentialed_live_log_rejects_missing_workload_log_for_generated_payload(tmp_path):
    log_path = tmp_path / "live-run.log"
    log_path.write_text(
        _live_log_text(
            generated_payload=True,
            include_workload_proof=True,
            include_workload_log=False,
        )
    )

    summary = verify.verify_log(log_path)

    assert summary["passed"] is False
    assert summary["webhook"]["workload_log"]["passed"] is False


def _live_log_text(
    *,
    checkpoint_process_restarted: bool = True,
    before_process: dict | None = None,
    after_process: dict | None = None,
    affected_services: list[str] | None = None,
    generated_payload: bool = False,
    include_workload_proof: bool = True,
    include_workload_log: bool = True,
) -> str:
    before_process = before_process or {"pid": 10, "started_at": "2026-06-07T07:00:00+00:00"}
    after_process = after_process or {"pid": 20, "started_at": "2026-06-07T07:01:00+00:00"}
    affected_services = affected_services or ["checkout-service", "payment-service"]
    completed = _completed_status(affected_services=affected_services)
    sections = [
        (
            "live_run_started",
            {"started_at": "2026-06-07T07:00:00+00:00", "log_path": ".sentinel/live-run.log"},
        ),
        (
            "credential_prompts_complete",
            {
                "redacted_env": {
                    "GROQ_API_KEY": "[set]",
                    "GITHUB_TOKEN": "[set]",
                    "DISCORD_WEBHOOK_URL": "[set]",
                    "SENTINEL_API_TOKEN": "[set]",
                    "DATABASE_URL": "[set]",
                    "REDIS_URL": "[set]",
                },
                "credential_prompt_meta": {
                    "database_url_default": verify.LOCAL_POSTGRES_DATABASE_URL,
                    "checkpoint_backend": "sqlite",
                    "effective_database_url_prompt": "SQLITE_CHECKPOINT_DATABASE_URL",
                },
            },
        ),
        (
            "posting_real_generic_webhook",
            {
                "incident_id": "LIVE-1",
                "payload": _webhook_payload(
                    affected_services,
                    generated=generated_payload,
                    include_workload_proof=include_workload_proof,
                ),
            },
        ),
        (
            "status_waiting_for_approval",
            {
                "receiver_process": before_process,
                "investigation_id": "inv-live",
                "status": "waiting_for_approval",
                "tool_calls": 20,
            },
        ),
        (
            "checkpoint_restart",
            {
                "investigation_id": "inv-live",
                "tool_calls_before_restart": 20,
                "checkpoint_backend": "sqlite",
                "receiver_process_before_restart": before_process,
            },
        ),
        (
            "checkpoint_recovered_status",
            {
                "receiver_process_before_restart": before_process,
                "receiver_process_after_restart": after_process,
                "checkpoint_process_restarted": checkpoint_process_restarted,
                "status": {
                    "investigation_id": "inv-live",
                    "status": "waiting_for_approval",
                    "tool_calls": 20,
                },
            },
        ),
        ("approval_submitted", {"code": 200, "body": {"accepted": True}}),
        ("status_completed", completed),
        ("verification_summary", {"passed": True}),
    ]
    if generated_payload and include_workload_log:
        sections.insert(
            3,
            (
                "slow_query_workload_proof",
                {
                    "requests": 12,
                    "errors": 0,
                    "prometheus_sample": {"value_seconds": 0.132},
                },
            ),
        )
    return "".join(_section(name, payload) for name, payload in sections)


def _webhook_payload(
    affected_services: list[str],
    *,
    generated: bool,
    include_workload_proof: bool,
) -> dict:
    payload = {
        "incident_id": "LIVE-1",
        "affected_services": affected_services,
    }
    if generated:
        payload["source"] = "prometheus_manual_generic_webhook"
    if include_workload_proof:
        payload["live_workload_proof"] = {
            "requests": 12,
            "errors": 0,
            "prometheus_value_seconds": 0.132,
            "prometheus_alert_found": True,
        }
    return payload


def _section(name: str, payload: dict) -> str:
    return f"=== 2026-06-07T07:00:00+00:00 {name} ===\n{json.dumps(payload, indent=2)}\n"


def _completed_status(*, affected_services: list[str]) -> dict:
    return {
        "receiver_process": {"pid": 20, "started_at": "2026-06-07T07:01:00+00:00"},
        "investigation_id": "inv-live",
        "incident_id": "LIVE-1",
        "status": "completed",
        "tool_calls": 20,
        "tool_call_records": _tool_call_records(20),
        "state_transitions": [
            {"payload": {"state": "received"}},
            {"payload": {"state": "triage"}},
            {"payload": {"state": "evidence_collection"}},
            {"payload": {"state": "response_proposal"}},
            {"payload": {"state": "remediation"}},
            {"payload": {"state": "post_mortem"}},
        ],
        "model_tool_plans": [
            {
                "source": "model",
                "provider": "groq",
                "model_rationale": "Use live metrics, logs, repo history, and rollout readiness.",
                "selected_tools": ["observe.query_metrics_range"],
            }
        ],
        "evidence_records": [
            {
                "source": "observe.query_metrics_range",
                "provenance": "live::observe.query_metrics_range",
                "claim": "real provider evidence",
            }
        ],
        "live_provider_proofs": {
            "prometheus": 8,
            "loki": 3,
            "github": 2,
            "generic_webhook": 1,
            "discord": 3,
            "sqlite": 1,
        },
        "live_tool_proofs": {
            "observe.fetch_service_logs": 1,
            "observe.query_metrics_range": 2,
            "observe.check_db_slow_queries": 1,
            "repo.get_recent_commits": 2,
            "comms.page_oncall_engineer": 1,
            "comms.post_to_slack": 2,
            "infra.add_database_index": 1,
        },
        "service_reports": [
            {
                "service_name": service,
                "summary": "subagent report",
            }
            for service in affected_services
        ],
        "plan_steps": [{"action": "Spawn checkout-service Service Investigator"}],
        "discord_notified": True,
        "last_discord_message": "SENTINEL posted the real incident timeline.",
        "remediation_result": {"status": "executed"},
    }


def _tool_call_records(count: int) -> list[dict]:
    names = [
        "comms.create_incident_channel",
        "comms.post_to_slack",
        "comms.page_oncall_engineer",
        "observe.query_metrics_range",
        "observe.fetch_service_logs",
        "repo.get_deploy_history",
        "infra.spawn_service_investigator",
        "observe.get_error_rate_timeseries",
        "repo.diff_pull_request",
        "repo.fetch_pr_metadata",
        "repo.get_rollback_targets",
        "infra.rollback_deployment",
    ]
    while len(names) < count:
        names.append("observe.check_uptime_history")
    return [
        {
            "tool_name": name,
            "state": "triage",
            "success": True,
            "reasoning_trace": f"recorded live reasoning for {name}",
        }
        for name in names[:count]
    ]
