import importlib.util
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_free_tier_readiness.py"
spec = importlib.util.spec_from_file_location("check_free_tier_readiness", SCRIPT)
readiness = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(readiness)


def test_free_tier_readiness_reports_missing_config(monkeypatch):
    _clear_free_env(monkeypatch)
    args = SimpleNamespace(
        skip_kind_bootstrap=True,
        allow_paid_provider_env=False,
        skip_host_tool_check=True,
        check_receiver=False,
    )

    summary = readiness.build_readiness_summary(
        args,
        env_file=".env",
        loaded_env={},
    )

    assert summary["status"] == "not_ready"
    assert summary["free_provider_configured"] is False
    assert "SENTINEL_API_TOKEN" in summary["config_problem"]["missing"]
    assert readiness.exit_code(summary) == 2


def test_free_tier_readiness_explains_skipped_receiver_check_when_config_is_missing(monkeypatch):
    _clear_free_env(monkeypatch)
    args = SimpleNamespace(
        skip_kind_bootstrap=True,
        allow_paid_provider_env=False,
        skip_host_tool_check=True,
        check_receiver=True,
    )

    summary = readiness.build_readiness_summary(
        args,
        env_file=".env",
        loaded_env={},
    )

    assert summary["status"] == "not_ready"
    assert "receiver" not in summary
    assert summary["receiver_check"]["status"] == "skipped"
    assert summary["receiver_check"]["reason"] == "free_provider_config_incomplete"
    assert "SENTINEL_API_TOKEN" in summary["receiver_check"]["missing"]


def test_free_tier_readiness_accepts_complete_free_config(monkeypatch):
    _set_complete_free_env(monkeypatch)
    args = SimpleNamespace(
        skip_kind_bootstrap=True,
        allow_paid_provider_env=False,
        skip_host_tool_check=True,
        check_receiver=False,
    )

    summary = readiness.build_readiness_summary(
        args,
        env_file=".env.free",
        loaded_env={"SENTINEL_API_TOKEN": "sentinel-token"},
    )

    assert summary["status"] == "ready"
    assert summary["free_provider_configured"] is True
    assert summary["paid_provider_credentials_present"] == []
    assert "configure_discord" in summary["next_commands"]
    assert summary["next_commands"]["configure_discord"] == (
        "python3 scripts/configure_discord_webhook.py --test-post"
    )
    assert "run_demo" in summary["next_commands"]
    assert "--summary-output .sentinel/free-tier-demo-summary.json" in summary["next_commands"]["run_demo"]
    assert summary["next_commands"]["audit_goal"] == (
        "python3 scripts/audit_free_tier_goal.py --demo-summary .sentinel/free-tier-demo-summary.json"
    )
    assert readiness.exit_code(summary) == 0


def test_free_tier_readiness_rejects_paid_provider_env(monkeypatch):
    _set_complete_free_env(monkeypatch)
    monkeypatch.setenv("DD_CLIENT_SECRET", "dd-oauth-client-secret")
    args = SimpleNamespace(
        skip_kind_bootstrap=True,
        allow_paid_provider_env=False,
        skip_host_tool_check=True,
        check_receiver=False,
    )

    summary = readiness.build_readiness_summary(
        args,
        env_file=".env.free",
        loaded_env={},
    )

    assert summary["status"] == "not_ready"
    assert summary["paid_provider_problem"]["variables"] == ["DD_CLIENT_SECRET"]
    assert readiness.exit_code(summary) == 2


def test_free_tier_readiness_rejects_github_write_mode_for_final_proof(monkeypatch):
    _set_complete_free_env(monkeypatch)
    monkeypatch.setenv("SENTINEL_GITHUB_WRITE_ENABLED", "true")
    args = SimpleNamespace(
        skip_kind_bootstrap=True,
        allow_paid_provider_env=False,
        allow_local_discord_webhook=False,
        skip_host_tool_check=True,
        check_receiver=False,
    )

    summary = readiness.build_readiness_summary(
        args,
        env_file=".env.free",
        loaded_env={},
    )

    assert summary["status"] == "not_ready"
    assert summary["config_problem"]["invalid"] == [
        {
            "name": "SENTINEL_GITHUB_WRITE_ENABLED",
            "value": "true",
            "message": (
                "SENTINEL_GITHUB_WRITE_ENABLED must be false for final free-tier demo proof; "
                "the demo uses live GitHub read evidence and kind for remediation."
            ),
        }
    ]
    assert readiness.exit_code(summary) == 2


def test_free_tier_readiness_can_allow_paid_provider_env_for_debugging(monkeypatch):
    _set_complete_free_env(monkeypatch)
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-secret")
    args = SimpleNamespace(
        skip_kind_bootstrap=True,
        allow_paid_provider_env=True,
        skip_host_tool_check=True,
        check_receiver=False,
    )

    summary = readiness.build_readiness_summary(
        args,
        env_file=".env.free",
        loaded_env={},
    )

    assert summary["status"] == "ready"
    assert summary["paid_provider_credentials_present"] == ["SLACK_BOT_TOKEN"]


def test_free_tier_readiness_rejects_local_discord_webhook_without_explicit_flag(monkeypatch):
    _set_complete_free_env(monkeypatch)
    monkeypatch.setenv("DISCORD_WEBHOOK_URL", "http://127.0.0.1:8765/webhook")
    args = SimpleNamespace(
        skip_kind_bootstrap=True,
        allow_paid_provider_env=False,
        allow_local_discord_webhook=False,
        skip_host_tool_check=True,
        check_receiver=False,
    )

    summary = readiness.build_readiness_summary(
        args,
        env_file=".env.free",
        loaded_env={},
    )

    assert summary["status"] == "not_ready"
    assert summary["config_problem"]["invalid"][0]["name"] == "DISCORD_WEBHOOK_URL"
    assert summary["config_problem"]["invalid"][0]["host"] == "127.0.0.1"
    assert readiness.exit_code(summary) == 2


def test_free_tier_readiness_allows_local_discord_webhook_for_stub_testing(monkeypatch):
    _set_complete_free_env(monkeypatch)
    monkeypatch.setenv("DISCORD_WEBHOOK_URL", "http://127.0.0.1:8765/webhook")
    args = SimpleNamespace(
        skip_kind_bootstrap=True,
        allow_paid_provider_env=False,
        allow_local_discord_webhook=True,
        skip_host_tool_check=True,
        check_receiver=False,
    )

    summary = readiness.build_readiness_summary(
        args,
        env_file=".env.free",
        loaded_env={},
    )

    assert summary["status"] == "ready"


def test_free_tier_readiness_receiver_failure_uses_preflight_exit_code(monkeypatch):
    _set_complete_free_env(monkeypatch)
    args = SimpleNamespace(
        skip_kind_bootstrap=True,
        allow_paid_provider_env=False,
        skip_host_tool_check=True,
        check_receiver=True,
        api_token="sentinel-token",
        base_url="http://localhost:8000",
        timeout_seconds=1.0,
    )
    monkeypatch.setattr(
        readiness,
        "_receiver_summary",
        lambda _settings, _args: {"status": "receiver_unreachable", "error": "connection refused"},
    )

    summary = readiness.build_readiness_summary(
        args,
        env_file=".env.free",
        loaded_env={},
    )

    assert summary["status"] == "not_ready"
    assert summary["receiver"]["status"] == "receiver_unreachable"
    assert readiness.exit_code(summary) == 2


def test_free_tier_readiness_reports_missing_kind_binary(monkeypatch):
    _set_complete_free_env(monkeypatch)
    args = SimpleNamespace(
        skip_kind_bootstrap=True,
        allow_paid_provider_env=False,
        skip_host_tool_check=False,
        allow_non_kind_context=False,
        check_receiver=False,
    )
    monkeypatch.setattr(
        readiness.shutil,
        "which",
        lambda name: None if name == "kind" else f"/usr/local/bin/{name}",
    )
    monkeypatch.setattr(
        readiness,
        "_command_check",
        lambda _command, name: {"name": name, "passed": True, "detail": "ok"},
    )

    summary = readiness.build_readiness_summary(
        args,
        env_file=".env.free",
        loaded_env={},
    )

    assert summary["status"] == "not_ready"
    failed = [
        check
        for check in summary["host_prerequisites"]["checks"]
        if check["name"] == "kind.binary"
    ]
    assert failed == [
        {
            "name": "kind.binary",
            "passed": False,
            "path": None,
            "detail": "kind is not installed or not on PATH",
        }
    ]


def _set_complete_free_env(monkeypatch):
    _clear_free_env(monkeypatch)
    for name in readiness.free_demo.PAID_PROVIDER_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SENTINEL_API_TOKEN", "sentinel-token")
    monkeypatch.setenv("PROMETHEUS_URL", "http://prometheus:9090")
    monkeypatch.setenv("LOKI_URL", "http://loki:3100")
    monkeypatch.setenv("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/123/token")
    monkeypatch.setenv("SENTINEL_APPROVER_ID", "eng-oncall")
    monkeypatch.setenv("GITHUB_TOKEN", "gh-token")
    monkeypatch.setenv("GITHUB_OWNER", "owner")
    monkeypatch.setenv("GITHUB_REPO", "repo")


def _clear_free_env(monkeypatch):
    for name, _attr in readiness.free_demo.REQUIRED_FREE_SETTINGS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("HOST_KUBECONFIG", raising=False)
    monkeypatch.delenv("SENTINEL_GITHUB_WRITE_ENABLED", raising=False)
