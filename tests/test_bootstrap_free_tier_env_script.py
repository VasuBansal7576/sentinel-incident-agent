import importlib.util
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bootstrap_free_tier_env.py"
spec = importlib.util.spec_from_file_location("bootstrap_free_tier_env", SCRIPT)
bootstrap = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bootstrap)


def test_bootstrap_free_tier_env_dry_run_generates_local_values(tmp_path):
    output = tmp_path / ".env"
    args = SimpleNamespace(
        template=str(ROOT / ".env.example"),
        output=str(output),
        force=False,
        dry_run=True,
        github_token="",
        github_owner="VasuBansal7576",
        github_repo="demo-repo",
        discord_webhook_url="",
        approver_id="vasu",
        api_token="generated-token",
        host_kubeconfig="~/.kube/config",
        container_kubeconfig=".sentinel/kubeconfig.container",
    )

    summary = bootstrap.bootstrap_env(args)

    assert summary["status"] == "would_create"
    assert output.exists() is False
    assert summary["missing_user_values"] == ["GITHUB_TOKEN", "DISCORD_WEBHOOK_URL"]
    assert summary["generated_values"] == ["SENTINEL_API_TOKEN"]


def test_bootstrap_free_tier_env_writes_env_from_template(tmp_path):
    output = tmp_path / ".env.free"
    args = SimpleNamespace(
        template=str(ROOT / ".env.example"),
        output=str(output),
        force=False,
        dry_run=False,
        github_token="gh-token",
        github_owner="owner",
        github_repo="repo",
        discord_webhook_url="https://discord.example/webhook",
        approver_id="eng-oncall",
        api_token="generated-token",
        host_kubeconfig="~/.kube/config",
        container_kubeconfig=".sentinel/kubeconfig.container",
    )

    summary = bootstrap.bootstrap_env(args)
    content = output.read_text()

    assert summary["status"] == "created"
    assert summary["missing_user_values"] == []
    assert "SENTINEL_API_TOKEN=generated-token" in content
    assert "SENTINEL_APPROVER_ID=eng-oncall" in content
    assert "GITHUB_TOKEN=gh-token" in content
    assert "SENTINEL_GITHUB_WRITE_ENABLED=false" in content
    assert "DISCORD_WEBHOOK_URL=https://discord.example/webhook" in content
    assert "HOST_KUBECONFIG=~/.kube/config" in content
    assert "CONTAINER_KUBECONFIG=.sentinel/kubeconfig.container" in content
    assert "DD_API_KEY=" in content
    assert "DD_CLIENT_SECRET=" in content
    assert "PAGERDUTY_API_KEY=" in content
    assert "PAGERDUTY_WEBHOOK_SECRET=" in content
    assert "SLACK_BOT_TOKEN=" in content
    assert "SLACK_CLIENT_SECRET=" in content


def test_bootstrap_free_tier_env_can_read_github_token_from_gh_cli(tmp_path, monkeypatch):
    output = tmp_path / ".env.free"
    monkeypatch.setattr(bootstrap, "_read_gh_cli_token", lambda: ("gh-cli-token", None))
    args = SimpleNamespace(
        template=str(ROOT / ".env.example"),
        output=str(output),
        force=False,
        dry_run=False,
        github_token="",
        github_token_from_gh_cli=True,
        github_owner="owner",
        github_repo="repo",
        discord_webhook_url="https://discord.example/webhook",
        approver_id="eng-oncall",
        api_token="generated-token",
        host_kubeconfig="~/.kube/config",
        container_kubeconfig=".sentinel/kubeconfig.container",
    )

    summary = bootstrap.bootstrap_env(args)
    content = output.read_text()

    assert summary["status"] == "created"
    assert summary["github_token_source"] == "gh_cli"
    assert summary["missing_user_values"] == []
    assert "GITHUB_TOKEN=gh-cli-token" in content


def test_bootstrap_free_tier_env_reports_gh_cli_token_problem(tmp_path, monkeypatch):
    output = tmp_path / ".env.free"
    problem = {"status": "github_cli_token_failed", "message": "Run gh auth login first."}
    monkeypatch.setattr(bootstrap, "_read_gh_cli_token", lambda: ("", problem))
    args = SimpleNamespace(
        template=str(ROOT / ".env.example"),
        output=str(output),
        force=False,
        dry_run=False,
        github_token="",
        github_token_from_gh_cli=True,
        github_owner="owner",
        github_repo="repo",
        discord_webhook_url="https://discord.example/webhook",
        approver_id="eng-oncall",
        api_token="generated-token",
        host_kubeconfig="~/.kube/config",
        container_kubeconfig=".sentinel/kubeconfig.container",
    )

    summary = bootstrap.bootstrap_env(args)

    assert summary == problem
    assert output.exists() is False


def test_bootstrap_free_tier_env_refuses_to_overwrite_without_force(tmp_path):
    output = tmp_path / ".env"
    output.write_text("existing=true\n")
    args = SimpleNamespace(
        template=str(ROOT / ".env.example"),
        output=str(output),
        force=False,
        dry_run=False,
        github_token="gh-token",
        github_owner="owner",
        github_repo="repo",
        discord_webhook_url="https://discord.example/webhook",
        approver_id="eng-oncall",
        api_token="generated-token",
        host_kubeconfig="~/.kube/config",
        container_kubeconfig=".sentinel/kubeconfig.container",
    )

    summary = bootstrap.bootstrap_env(args)

    assert summary["status"] == "output_exists"
    assert output.read_text() == "existing=true\n"
