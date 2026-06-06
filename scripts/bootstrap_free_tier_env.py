from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))


PAID_PROVIDER_KEYS = {
    "DD_API_KEY",
    "DD_APP_KEY",
    "DATADOG_APP_KEY",
    "DD_OAUTH_TOKEN",
    "DD_CLIENT_ID",
    "DATADOG_CLIENT_ID",
    "DD_CLIENT_SECRET",
    "DATADOG_CLIENT_SECRET",
    "PAGERDUTY_API_KEY",
    "PAGERDUTY_REQUESTER_EMAIL",
    "PAGERDUTY_WEBHOOK_SECRET",
    "PAGERDUTY_WEBHOOK_PREVIOUS_SECRET",
    "PAGERDUTY_WEBHOOK_SUBSCRIPTION_ID",
    "SLACK_BOT_TOKEN",
    "SLACK_CHANNEL_ID",
    "SLACK_CLIENT_ID",
    "SLACK_CLIENT_SECRET",
}
USER_SUPPLIED_KEYS = ("GITHUB_TOKEN", "GITHUB_OWNER", "GITHUB_REPO", "DISCORD_WEBHOOK_URL")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Create a local .env skeleton for the free-tier SENTINEL demo."
    )
    parser.add_argument("--output", default=str(PROJECT_ROOT / ".env"))
    parser.add_argument("--template", default=str(PROJECT_ROOT / ".env.example"))
    parser.add_argument("--force", action="store_true", help="Overwrite an existing output file.")
    parser.add_argument("--dry-run", action="store_true", help="Print the planned result without writing.")
    parser.add_argument("--github-token", default=os.getenv("GITHUB_TOKEN", ""))
    parser.add_argument(
        "--github-token-from-gh-cli",
        action="store_true",
        help="Read GITHUB_TOKEN from the authenticated GitHub CLI without printing it.",
    )
    parser.add_argument("--github-owner", default=os.getenv("GITHUB_OWNER", ""))
    parser.add_argument("--github-repo", default=os.getenv("GITHUB_REPO", ""))
    parser.add_argument("--discord-webhook-url", default=os.getenv("DISCORD_WEBHOOK_URL", ""))
    parser.add_argument("--approver-id", default=os.getenv("SENTINEL_APPROVER_ID") or os.getenv("USER") or "local-approver")
    parser.add_argument("--api-token", default=os.getenv("SENTINEL_API_TOKEN") or secrets.token_hex(32))
    parser.add_argument("--host-kubeconfig", default=os.getenv("HOST_KUBECONFIG") or "~/.kube/config")
    parser.add_argument(
        "--container-kubeconfig",
        default=os.getenv("CONTAINER_KUBECONFIG") or str(PROJECT_ROOT / ".sentinel" / "kubeconfig.container"),
    )
    args = parser.parse_args(argv)

    summary = bootstrap_env(args)
    print(json.dumps(summary, indent=2))
    raise SystemExit(0 if summary["status"] in {"created", "would_create"} else 2)


def bootstrap_env(args: argparse.Namespace) -> dict:
    template = Path(args.template)
    output = Path(args.output)
    if not template.exists():
        return {"status": "template_missing", "template": str(template)}
    if output.exists() and not args.force and not args.dry_run:
        return {
            "status": "output_exists",
            "output": str(output),
            "message": "Refusing to overwrite existing env file without --force.",
        }

    github_token, github_token_source, github_token_problem = _github_token_value(args)
    if github_token_problem is not None:
        return github_token_problem

    values = _free_tier_values(args, output, github_token=github_token)
    content = _render_env(template.read_text(), values)
    missing_user_values = [key for key in USER_SUPPLIED_KEYS if not values.get(key)]
    if not args.dry_run:
        output.write_text(content)
    return {
        "status": "would_create" if args.dry_run else "created",
        "output": str(output),
        "template": str(template),
        "missing_user_values": missing_user_values,
        "generated_values": ["SENTINEL_API_TOKEN"],
        "github_token_source": github_token_source,
        "next_command": f"python3 scripts/check_free_tier_readiness.py --env-file {output}",
    }


def _free_tier_values(args: argparse.Namespace, output: Path, *, github_token: str | None = None) -> dict[str, str]:
    values = {
        "PROMETHEUS_URL": "http://prometheus:9090",
        "LOKI_URL": "http://loki:3100",
        "GITHUB_TOKEN": (github_token if github_token is not None else args.github_token).strip(),
        "GITHUB_OWNER": args.github_owner.strip(),
        "GITHUB_REPO": args.github_repo.strip(),
        "SENTINEL_GITHUB_WRITE_ENABLED": "false",
        "DISCORD_WEBHOOK_URL": args.discord_webhook_url.strip(),
        "SENTINEL_API_TOKEN": args.api_token.strip(),
        "SENTINEL_APPROVER_ID": args.approver_id.strip(),
        "HOST_KUBECONFIG": args.host_kubeconfig.strip() or "~/.kube/config",
        "CONTAINER_KUBECONFIG": args.container_kubeconfig.strip(),
        "KUBECONFIG": "/root/.kube/config",
        "SENTINEL_ENV_FILE": str(output),
    }
    for key in PAID_PROVIDER_KEYS:
        values[key] = ""
    return values


def _github_token_value(args: argparse.Namespace) -> tuple[str, str, dict | None]:
    explicit = getattr(args, "github_token", "").strip()
    if explicit:
        return explicit, "argument_or_env", None
    if not bool(getattr(args, "github_token_from_gh_cli", False)):
        return "", "missing", None

    token, problem = _read_gh_cli_token()
    if problem is not None:
        return "", "gh_cli", problem
    return token, "gh_cli", None


def _read_gh_cli_token() -> tuple[str, dict | None]:
    gh = shutil.which("gh")
    if not gh:
        return "", {
            "status": "github_cli_unavailable",
            "message": "Cannot read GITHUB_TOKEN from GitHub CLI because gh is not installed or not on PATH.",
        }
    try:
        proc = subprocess.run(
            [gh, "auth", "token"],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except Exception as exc:
        return "", {
            "status": "github_cli_token_failed",
            "message": "GitHub CLI token lookup failed.",
            "error": str(exc),
        }
    token = proc.stdout.strip()
    if proc.returncode != 0 or not token:
        return "", {
            "status": "github_cli_token_failed",
            "message": "GitHub CLI did not return a token. Run `gh auth login` first or pass --github-token.",
            "stderr": proc.stderr.strip(),
        }
    return token, None


def _render_env(template: str, values: dict[str, str]) -> str:
    rendered: list[str] = []
    seen: set[str] = set()
    for raw_line in template.splitlines():
        key, sep, _value = raw_line.partition("=")
        normalized_key = key.strip()
        if sep and normalized_key in values:
            rendered.append(f"{normalized_key}={_quote_env_value(values[normalized_key])}")
            seen.add(normalized_key)
        else:
            rendered.append(raw_line)
    for key in sorted(set(values) - seen):
        rendered.append(f"{key}={_quote_env_value(values[key])}")
    rendered.append("")
    return "\n".join(rendered)


def _quote_env_value(value: str) -> str:
    if not value:
        return ""
    if any(char.isspace() for char in value) or value[0] in {"'", '"'}:
        return json.dumps(value)
    return value


if __name__ == "__main__":
    main()
