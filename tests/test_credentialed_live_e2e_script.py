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
        approval_submitted=True,
        checkpoint_backend="sqlite",
    )

    assert summary["passed"] is True
    assert summary["tool_calls"] == 20
    assert summary["has_groq_model_plan"] is True
    assert summary["has_model_reasoning"] is True
    assert summary["has_subagent"] is True
    assert summary["checkpoint_backend"] == "sqlite"


def test_credentialed_live_verifier_rejects_thirteen_tool_trace():
    summary = live_e2e._verification_summary(
        _completed_status(tool_calls=13),
        checkpoint_recovered=True,
        approval_submitted=True,
        checkpoint_backend="sqlite",
    )

    assert summary["passed"] is False
    assert summary["tool_calls"] == 13


def test_credentialed_live_verifier_rejects_model_plan_without_reasoning():
    summary = live_e2e._verification_summary(
        _completed_status(tool_calls=20, rationale=""),
        checkpoint_recovered=True,
        approval_submitted=True,
        checkpoint_backend="sqlite",
    )

    assert summary["passed"] is False
    assert summary["has_groq_model_plan"] is True
    assert summary["has_model_reasoning"] is False


def test_credentialed_live_verifier_rejects_non_sqlite_checkpoint_for_video_proof():
    summary = live_e2e._verification_summary(
        _completed_status(tool_calls=20),
        checkpoint_recovered=True,
        approval_submitted=True,
        checkpoint_backend="postgres",
    )

    assert summary["passed"] is False
    assert summary["checkpoint_backend"] == "postgres"


def test_credentialed_live_runner_keeps_postgres_database_prompt_and_sqlite_checkpoint_default():
    assert (
        live_e2e.LOCAL_POSTGRES_DATABASE_URL
        == "postgresql://sentinel:change-me@postgres:5432/sentinel"
    )
    assert live_e2e.SQLITE_CHECKPOINT_DATABASE_URL == "sqlite:////data/sentinel-live-checkpoint.sqlite3"


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
        "model_tool_plans": [model_plan],
        "service_reports": [{"service": "checkout-service", "summary": "subagent report"}],
        "discord_notified": True,
        "remediation_result": {"status": "executed"},
    }
