import importlib.util
from pathlib import Path
from types import SimpleNamespace

import httpx


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "configure_discord_webhook.py"
spec = importlib.util.spec_from_file_location("configure_discord_webhook", SCRIPT)
configure = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(configure)


REAL_WEBHOOK = "https://discord.com/api/webhooks/123456/secret-token"


def test_configure_discord_webhook_rejects_local_url_without_explicit_flag(tmp_path):
    env_file = tmp_path / ".env"
    args = _args(env_file, allow_local_discord_webhook=False)

    summary = configure.configure_discord_webhook(
        args,
        webhook_url="http://127.0.0.1:8765/webhook",
    )

    assert summary["status"] == "invalid_discord_webhook_url"
    assert summary["problem"]["name"] == "DISCORD_WEBHOOK_URL"
    assert summary["problem"]["host"] == "127.0.0.1"
    assert env_file.exists() is False
    assert configure.exit_code(summary) == 2


def test_configure_discord_webhook_accepts_local_url_only_for_stub_testing(tmp_path):
    env_file = tmp_path / ".env"
    args = _args(env_file, allow_local_discord_webhook=True, dry_run=True)

    summary = configure.configure_discord_webhook(
        args,
        webhook_url="http://127.0.0.1:8765/webhook",
    )

    assert summary["status"] == "would_update"
    assert summary["webhook"] == {
        "scheme": "http",
        "host": "127.0.0.1",
        "path": "<redacted>",
    }
    assert env_file.exists() is False


def test_configure_discord_webhook_updates_env_without_printing_secret(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("GITHUB_OWNER=owner\nDISCORD_WEBHOOK_URL=\n")
    args = _args(env_file)

    summary = configure.configure_discord_webhook(args, webhook_url=REAL_WEBHOOK)

    assert summary["status"] == "updated"
    assert summary["webhook"] == {
        "scheme": "https",
        "host": "discord.com",
        "path": "/api/webhooks/<redacted>",
    }
    assert "secret-token" not in str(summary)
    assert "GITHUB_OWNER=owner" in env_file.read_text()
    assert f"DISCORD_WEBHOOK_URL={REAL_WEBHOOK}" in env_file.read_text()
    assert oct(env_file.stat().st_mode & 0o777) == "0o600"
    assert summary["mode"] == "0o600"


def test_configure_discord_webhook_test_post_succeeds_before_write(tmp_path):
    env_file = tmp_path / ".env"
    requested_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        return httpx.Response(204)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    args = _args(env_file, test_post=True)

    summary = configure.configure_discord_webhook(args, webhook_url=REAL_WEBHOOK, client=client)

    assert summary["status"] == "updated"
    assert summary["test"] == {"status": "ok"}
    assert requested_urls == [REAL_WEBHOOK]
    assert f"DISCORD_WEBHOOK_URL={REAL_WEBHOOK}" in env_file.read_text()


def test_configure_discord_webhook_does_not_write_when_test_post_fails(tmp_path):
    env_file = tmp_path / ".env"
    client = httpx.Client(transport=httpx.MockTransport(lambda _request: httpx.Response(404, text="nope")))
    args = _args(env_file, test_post=True)

    summary = configure.configure_discord_webhook(args, webhook_url=REAL_WEBHOOK, client=client)

    assert summary["status"] == "webhook_test_failed"
    assert summary["test"]["status"] == "http_error"
    assert summary["test"]["code"] == 404
    assert env_file.exists() is False
    assert configure.exit_code(summary) == 2


def _args(env_file, **overrides):
    values = {
        "env_file": str(env_file),
        "allow_local_discord_webhook": False,
        "test_post": False,
        "dry_run": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)
