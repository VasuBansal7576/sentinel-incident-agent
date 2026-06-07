import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_credentialed_live_e2e.py"
spec = importlib.util.spec_from_file_location("run_credentialed_live_e2e", SCRIPT)
live_e2e = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(live_e2e)


def test_credentialed_live_verifier_requires_twenty_tools_groq_reasoning_and_sqlite_checkpoint():
    summary = live_e2e._verification_summary(
        _completed_status(tool_calls=20),
        checkpoint_recovered=True,
        checkpoint_process_restarted=True,
        approval_submitted=True,
        checkpoint_backend="sqlite",
    )

    assert summary["passed"] is True
    assert summary["tool_calls"] == 20
    assert summary["tool_call_records"] == 20
    assert summary["has_full_tool_call_records"] is True
    assert summary["has_state_transition_records"] is True
    assert summary["has_groq_model_plan"] is True
    assert summary["has_model_reasoning"] is True
    assert summary["has_subagent"] is True
    assert summary["has_live_evidence_records"] is True
    assert summary["has_discord_message"] is True
    assert summary["remediation_tool_executed"] is True
    assert summary["checkpoint_backend"] == "sqlite"
    assert summary["checkpoint_process_restarted"] is True


def test_credentialed_live_verifier_rejects_thirteen_tool_trace():
    summary = live_e2e._verification_summary(
        _completed_status(tool_calls=13),
        checkpoint_recovered=True,
        checkpoint_process_restarted=True,
        approval_submitted=True,
        checkpoint_backend="sqlite",
    )

    assert summary["passed"] is False
    assert summary["tool_calls"] == 13


def test_credentialed_live_verifier_rejects_model_plan_without_reasoning():
    summary = live_e2e._verification_summary(
        _completed_status(tool_calls=20, rationale=""),
        checkpoint_recovered=True,
        checkpoint_process_restarted=True,
        approval_submitted=True,
        checkpoint_backend="sqlite",
    )

    assert summary["passed"] is False
    assert summary["has_groq_model_plan"] is True
    assert summary["has_model_reasoning"] is False


def test_credentialed_live_verifier_rejects_summary_without_detailed_records():
    status = _completed_status(tool_calls=20)
    status.pop("tool_call_records")

    summary = live_e2e._verification_summary(
        status,
        checkpoint_recovered=True,
        checkpoint_process_restarted=True,
        approval_submitted=True,
        checkpoint_backend="sqlite",
    )

    assert summary["passed"] is False
    assert summary["has_full_tool_call_records"] is False


def test_credentialed_live_verifier_rejects_missing_subagent_spawn_tool():
    status = _completed_status(tool_calls=20)
    for record in status["tool_call_records"]:
        if record["tool_name"] == "infra.spawn_service_investigator":
            record["tool_name"] = "observe.fetch_service_logs"

    summary = live_e2e._verification_summary(
        status,
        checkpoint_recovered=True,
        checkpoint_process_restarted=True,
        approval_submitted=True,
        checkpoint_backend="sqlite",
    )

    assert summary["passed"] is False
    assert summary["has_subagent"] is False


def test_credentialed_live_verifier_rejects_checkpoint_without_process_restart():
    summary = live_e2e._verification_summary(
        _completed_status(tool_calls=20),
        checkpoint_recovered=True,
        checkpoint_process_restarted=False,
        approval_submitted=True,
        checkpoint_backend="sqlite",
    )

    assert summary["passed"] is False
    assert summary["checkpoint_process_restarted"] is False


def test_credentialed_live_verifier_rejects_non_sqlite_checkpoint_for_video_proof():
    summary = live_e2e._verification_summary(
        _completed_status(tool_calls=20),
        checkpoint_recovered=True,
        checkpoint_process_restarted=True,
        approval_submitted=True,
        checkpoint_backend="postgres",
    )

    assert summary["passed"] is False
    assert summary["checkpoint_backend"] == "postgres"


def test_credentialed_live_verifier_rejects_missing_github_provider_proof():
    status = _completed_status(tool_calls=20)
    status["live_provider_proofs"]["github"] = 0

    summary = live_e2e._verification_summary(
        status,
        checkpoint_recovered=True,
        checkpoint_process_restarted=True,
        approval_submitted=True,
        checkpoint_backend="sqlite",
    )

    assert summary["passed"] is False
    assert summary["has_required_live_provider_proofs"] is False
    assert summary["required_live_provider_proofs"]["github"] == 0


def test_credentialed_live_runner_keeps_postgres_database_prompt_and_sqlite_checkpoint_default():
    assert (
        live_e2e.LOCAL_POSTGRES_DATABASE_URL
        == "postgresql://sentinel:change-me@postgres:5432/sentinel"
    )
    assert live_e2e.SQLITE_CHECKPOINT_DATABASE_URL == "sqlite:////data/sentinel-live-checkpoint.sqlite3"


def test_credentialed_live_runner_reads_optional_integrations_from_env_without_prompt(monkeypatch):
    monkeypatch.setenv("DD_API_KEY", "dd-api-key")
    prompted_secrets: list[str] = []

    def fake_prompt_secret(
        name: str,
        *,
        required: bool,
        default: str | None = None,
        accept_default: bool = False,
    ) -> str:
        prompted_secrets.append(name)
        if name == "GROQ_API_KEY":
            return "groq-key"
        if name == "GITHUB_TOKEN":
            return "github-token"
        if name == "DISCORD_WEBHOOK_URL":
            return "discord-webhook"
        if name == "SENTINEL_API_TOKEN":
            return default or "sentinel-token"
        raise AssertionError(f"unexpected secret prompt: {name}")

    def fake_prompt_text(
        name: str,
        *,
        required: bool,
        default: str | None = None,
        accept_default: bool = False,
    ) -> str:
        return default or {
            "GITHUB_OWNER": "owner",
            "GITHUB_REPO": "repo",
            "DATABASE_URL": live_e2e.LOCAL_POSTGRES_DATABASE_URL,
            "SQLITE_CHECKPOINT_DATABASE_URL": live_e2e.SQLITE_CHECKPOINT_DATABASE_URL,
            "REDIS_URL": "redis://redis:6379/0",
            "PROMETHEUS_URL": "http://prometheus:9090",
            "LOKI_URL": "http://loki:3100",
            "SENTINEL_APPROVER_ID": "vasu-local-approver",
            "SENTINEL_DEFAULT_SERVICE": "payment-service",
            "HOST/CONTAINER_KUBECONFIG": "",
            "KUBERNETES_NAMESPACE": "default",
            "SENTINEL_MODEL": live_e2e.DEFAULT_GROQ_MODEL,
        }[name]

    monkeypatch.setattr(live_e2e, "_prompt_secret", fake_prompt_secret)
    monkeypatch.setattr(live_e2e, "_prompt_text", fake_prompt_text)

    env, meta = live_e2e._collect_credentials("sqlite")

    assert env["DD_API_KEY"] == "dd-api-key"
    assert "DD_API_KEY" not in prompted_secrets
    assert prompted_secrets == [
        "GROQ_API_KEY",
        "GITHUB_TOKEN",
        "DISCORD_WEBHOOK_URL",
        "SENTINEL_API_TOKEN",
    ]
    assert meta["optional_integrations_prompted"] is False
    assert meta["optional_integrations_present"] == ["DD_API_KEY"]


def test_credentialed_live_runner_accepts_env_defaults_without_prompt(monkeypatch):
    for name, value in {
        "GROQ_API_KEY": "groq-key",
        "GITHUB_TOKEN": "github-token",
        "GITHUB_OWNER": "owner",
        "GITHUB_REPO": "repo",
        "DISCORD_WEBHOOK_URL": "discord-webhook",
    }.items():
        monkeypatch.setenv(name, value)

    def fail_prompt(*args, **kwargs):
        raise AssertionError("accept_defaults should not prompt when env/defaults are available")

    monkeypatch.setattr(live_e2e, "input", fail_prompt, raising=False)
    monkeypatch.setattr(live_e2e.getpass, "getpass", fail_prompt)

    env, meta = live_e2e._collect_credentials("sqlite", accept_defaults=True)

    assert env["GROQ_API_KEY"] == "groq-key"
    assert env["GITHUB_OWNER"] == "owner"
    assert env["GITHUB_REPO"] == "repo"
    assert env["DISCORD_WEBHOOK_URL"] == "discord-webhook"
    assert env["DATABASE_URL"] == live_e2e.SQLITE_CHECKPOINT_DATABASE_URL
    assert meta["optional_integrations_prompted"] is False


def test_credentialed_live_runner_detects_receiver_process_identity_change():
    assert live_e2e._receiver_process_changed(
        {"started_at": "2026-06-07T07:00:00Z", "pid": 1},
        {"started_at": "2026-06-07T07:01:00Z", "pid": 1},
    )
    assert live_e2e._receiver_process_changed({"pid": 101}, {"pid": 202})
    assert not live_e2e._receiver_process_changed(
        {"started_at": "2026-06-07T07:00:00Z", "pid": 1},
        {"started_at": "2026-06-07T07:00:00Z", "pid": 1},
    )


def test_credentialed_live_runner_builds_slow_query_payload_with_workload_proof():
    payload = live_e2e._generic_slow_query_payload(
        incident_id="LIVE-SLOW-1",
        services=["payment-service", "checkout-service"],
        occurred_at="2026-06-07T08:00:00Z",
        evidence_note="real slow-query traffic generated this alert",
        workload={
            "requests": 12,
            "errors": 0,
            "max_duration_ms": 145.0,
            "last_duration_ms": 132.0,
            "prometheus_sample": {"value_seconds": 0.132},
            "prometheus_alert": {"found": True},
        },
    )

    assert payload["source"] == "prometheus_manual_generic_webhook"
    assert payload["commonLabels"]["alertname"] == "SentinelSlowQueryLatency"
    assert payload["affected_services"] == ["payment-service", "checkout-service"]
    assert payload["live_workload_proof"]["requests"] == 12
    assert payload["live_workload_proof"]["prometheus_value_seconds"] == 0.132
    assert len(payload["alerts"]) == 2


def test_credentialed_live_runner_reads_latest_prometheus_sample():
    response = {
        "data": {
            "result": [
                {"value": [1710000000, "0.12"]},
                {"value": [1710000001, "0.34"]},
            ]
        }
    }

    assert live_e2e._latest_prometheus_sample(response) == 0.34


def _completed_status(*, tool_calls: int, rationale: str = "Groq selected metrics, logs, and repo tools.") -> dict:
    model_plan = {
        "source": "model",
        "provider": "groq",
        "selected_tools": ["observe.query_metrics_range"],
    }
    if rationale is not None:
        model_plan["model_rationale"] = rationale
    return {
        "status": "completed",
        "tool_calls": tool_calls,
        "tool_call_records": _tool_call_records(tool_calls),
        "state_transitions": [
            {"payload": {"state": "received"}},
            {"payload": {"state": "triage"}},
            {"payload": {"state": "evidence_collection"}},
            {"payload": {"state": "response_proposal"}},
            {"payload": {"state": "remediation"}},
            {"payload": {"state": "post_mortem"}},
        ],
        "model_tool_plans": [model_plan],
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
        "service_reports": [{"service": "checkout-service", "summary": "subagent report"}],
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
