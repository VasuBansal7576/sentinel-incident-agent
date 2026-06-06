from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(SCRIPT_DIR))

import run_free_tier_sentinel_demo as free_demo
from sentinel.errors import redact_sensitive_text

KEY = "DISCORD_WEBHOOK_URL"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Validate and save a Discord webhook URL for SENTINEL's free-tier demo."
    )
    parser.add_argument("--env-file", default=os.getenv("SENTINEL_ENV_FILE") or str(PROJECT_ROOT / ".env"))
    parser.add_argument(
        "--webhook-url",
        default="",
        help="Discord webhook URL. Prefer --from-stdin or the hidden prompt to avoid shell history.",
    )
    parser.add_argument(
        "--from-stdin",
        action="store_true",
        help="Read the webhook URL from stdin instead of a command-line argument.",
    )
    parser.add_argument(
        "--allow-local-discord-webhook",
        action="store_true",
        help="Allow a non-Discord webhook URL for local stub testing only.",
    )
    parser.add_argument(
        "--test-post",
        action="store_true",
        help="Send a small validation message before writing the env file.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Validate without writing .env.")
    args = parser.parse_args(argv)

    webhook_url = _webhook_url_from_args(args)
    with httpx.Client(timeout=20.0) as client:
        summary = configure_discord_webhook(args, webhook_url=webhook_url, client=client)
    print(json.dumps(summary, indent=2))
    raise SystemExit(exit_code(summary))


def configure_discord_webhook(
    args: argparse.Namespace,
    *,
    webhook_url: str,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    env_file = Path(args.env_file).expanduser()
    webhook_url = webhook_url.strip()
    if not webhook_url:
        return {
            "status": "missing_webhook_url",
            "env_file": str(env_file),
            "message": "Provide a Discord webhook URL via hidden prompt, --from-stdin, or --webhook-url.",
        }
    if "\n" in webhook_url or "\r" in webhook_url:
        return {
            "status": "invalid_discord_webhook_url",
            "env_file": str(env_file),
            "problem": {
                "name": KEY,
                "message": "Discord webhook URL must be a single line.",
            },
        }

    problem = free_demo._discord_webhook_problem(webhook_url, args)
    if problem is not None:
        return {
            "status": "invalid_discord_webhook_url",
            "env_file": str(env_file),
            "problem": problem,
        }

    preview = _webhook_preview(webhook_url)
    if getattr(args, "test_post", False):
        test_result = _test_webhook(webhook_url, client=client)
        if test_result.get("status") != "ok":
            return {
                "status": "webhook_test_failed",
                "env_file": str(env_file),
                "webhook": preview,
                "test": test_result,
            }

    if getattr(args, "dry_run", False):
        return {
            "status": "would_update",
            "env_file": str(env_file),
            "key": KEY,
            "webhook": preview,
            "test": {"status": "skipped"} if not getattr(args, "test_post", False) else {"status": "ok"},
        }

    _update_env_file_secure(env_file, KEY, webhook_url)
    return {
        "status": "updated",
        "env_file": str(env_file),
        "key": KEY,
        "webhook": preview,
        "mode": _file_mode(env_file),
        "test": {"status": "skipped"} if not getattr(args, "test_post", False) else {"status": "ok"},
        "next_command": "python3 scripts/check_free_tier_readiness.py --check-receiver",
    }


def exit_code(summary: dict[str, Any]) -> int:
    return 0 if summary.get("status") in {"updated", "would_update"} else 2


def _webhook_url_from_args(args: argparse.Namespace) -> str:
    if args.from_stdin:
        return sys.stdin.readline().strip()
    if args.webhook_url:
        return args.webhook_url.strip()
    return getpass.getpass("Discord webhook URL: ").strip()


def _test_webhook(webhook_url: str, *, client: httpx.Client | None = None) -> dict[str, Any]:
    close_client = client is None
    client = client or httpx.Client(timeout=20.0)
    try:
        try:
            response = client.post(webhook_url, json={"content": "SENTINEL Discord webhook validation"})
        except httpx.HTTPError as exc:
            return {
                "status": "transport_error",
                "error": redact_sensitive_text(exc, max_length=500),
            }
        if response.status_code >= 400:
            return {
                "status": "http_error",
                "code": response.status_code,
                "body": redact_sensitive_text(response.text, max_length=500),
            }
        return {"status": "ok", "code": response.status_code}
    finally:
        if close_client:
            client.close()


def _update_env_file_secure(path: Path, key: str, value: str) -> None:
    lines = path.read_text().splitlines() if path.exists() else []
    rendered: list[str] = []
    updated = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#") or "=" not in line:
            rendered.append(line)
            continue
        current_key, _sep, _current_value = line.partition("=")
        if current_key.strip() == key:
            rendered.append(f"{key}={value}")
            updated = True
        else:
            rendered.append(line)
    if not updated:
        rendered.append(f"{key}={value}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(rendered) + "\n")
    path.chmod(0o600)


def _webhook_preview(webhook_url: str) -> dict[str, str | None]:
    parsed = urlparse(webhook_url)
    return {
        "scheme": parsed.scheme or None,
        "host": parsed.hostname,
        "path": "/api/webhooks/<redacted>" if parsed.path.startswith("/api/webhooks/") else "<redacted>",
    }


def _file_mode(path: Path) -> str:
    return oct(path.stat().st_mode & 0o777)


if __name__ == "__main__":
    main()
