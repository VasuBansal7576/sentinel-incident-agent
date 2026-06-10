from __future__ import annotations

import argparse
import os
import secrets
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class EnvEntry:
    key: str
    default: str
    prompt: str
    secret: bool = False


ENV_GROUPS: tuple[tuple[str, tuple[EnvEntry, ...]], ...] = (
    (
        "REQUIRED",
        (
            EnvEntry("SENTINEL_PROFILE", "free-local", "Provider profile"),
            EnvEntry("SENTINEL_ENV", "development", "Runtime environment"),
            EnvEntry("SENTINEL_API_TOKEN", "", "Operator API token", secret=True),
            EnvEntry("SENTINEL_APPROVER_ID", "eng-oncall", "Default remediation approver id"),
            EnvEntry("SENTINEL_DEFAULT_SERVICE", "payment-service", "Default service name"),
            EnvEntry("SENTINEL_MCP_ENABLED", "false", "Enable MCP HTTP endpoint"),
            EnvEntry("SENTINEL_HOST_PORT", "8000", "SENTINEL host port"),
            EnvEntry("POSTGRES_USER", "sentinel", "Postgres user"),
            EnvEntry("POSTGRES_PASSWORD", "change-me", "Postgres password", secret=True),
            EnvEntry("POSTGRES_DB", "sentinel", "Postgres database"),
            EnvEntry("POSTGRES_HOST_PORT", "5432", "Postgres host port"),
            EnvEntry("REDIS_HOST_PORT", "6379", "Redis host port"),
            EnvEntry("DATABASE_URL", "postgresql://sentinel:change-me@postgres:5432/sentinel", "Database URL"),
            EnvEntry("REDIS_URL", "redis://redis:6379/0", "Redis URL"),
            EnvEntry("CONTAINER_KUBECONFIG", ".sentinel/kubeconfig.container", "Container kubeconfig path"),
            EnvEntry("KUBERNETES_NAMESPACE", "default", "Kubernetes namespace"),
        ),
    ),
    (
        "FREE_TIER",
        (
            EnvEntry("PROMETHEUS_URL", "http://prometheus:9090", "Prometheus URL"),
            EnvEntry("LOKI_URL", "http://loki:3100", "Loki URL"),
            EnvEntry("PROMETHEUS_HOST_PORT", "9090", "Prometheus host port"),
            EnvEntry("LOKI_HOST_PORT", "3100", "Loki host port"),
            EnvEntry("DISCORD_WEBHOOK_URL", "", "Discord webhook URL"),
            EnvEntry("SENTINEL_BASE_URL", "http://localhost:8000", "Local receiver base URL"),
            EnvEntry("SENTINEL_LIVE_RECEIVER_URL", "http://localhost:8000", "Live receiver URL"),
            EnvEntry("SENTINEL_GITHUB_WRITE_ENABLED", "false", "Enable GitHub writes"),
        ),
    ),
    (
        "OPTIONAL_ENTERPRISE",
        (
            EnvEntry("DD_API_KEY", "", "Datadog API key", secret=True),
            EnvEntry("DD_APP_KEY", "", "Datadog app key", secret=True),
            EnvEntry("DD_SITE", "datadoghq.com", "Datadog site"),
            EnvEntry("DD_OAUTH_TOKEN", "", "Datadog OAuth token", secret=True),
            EnvEntry("GITHUB_TOKEN", "", "GitHub token", secret=True),
            EnvEntry("GITHUB_OWNER", "", "GitHub owner"),
            EnvEntry("GITHUB_REPO", "", "GitHub repo"),
            EnvEntry("PAGERDUTY_API_KEY", "", "PagerDuty API key", secret=True),
            EnvEntry("PAGERDUTY_WEBHOOK_SECRET", "", "PagerDuty webhook secret", secret=True),
            EnvEntry("SLACK_BOT_TOKEN", "", "Slack bot token", secret=True),
            EnvEntry("SLACK_CHANNEL_ID", "", "Slack channel id"),
            EnvEntry("KUBECONFIG", "/root/.kube/config", "Container KUBECONFIG"),
        ),
    ),
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Initialize a clone-ready SENTINEL checkout.")
    parser.add_argument("--env-file", default=".env", help="Path to write the generated env file.")
    parser.add_argument("--venv", default=".venv", help="Python virtual environment directory.")
    parser.add_argument("--force", action="store_true", help="Overwrite an existing env file.")
    parser.add_argument(
        "--no-install",
        action="store_true",
        help="Only write configuration; skip venv creation and package install.",
    )
    args = parser.parse_args()

    env_path = _project_path(args.env_file)
    venv_path = _project_path(args.venv)
    interactive = sys.stdin.isatty() and sys.stdout.isatty()

    values = collect_env_values(interactive=interactive)
    wrote_env = write_env_file(env_path, values, force=args.force)
    _ensure_demo_kubeconfig(PROJECT_ROOT / ".sentinel" / "kubeconfig.container")
    if not args.no_install:
        ensure_virtualenv(venv_path)

    print(f"OK .env {'written' if wrote_env else 'kept'}: {env_path}")
    if args.no_install:
        print("OK Python install skipped by --no-install")
    else:
        print(f"OK Python environment ready: {venv_path}")
    print("Next: make doctor && make demo")


def collect_env_values(*, interactive: bool) -> dict[str, str]:
    values: dict[str, str] = {}
    generated_token = f"sentinel-{secrets.token_urlsafe(24)}"
    for _group, entries in ENV_GROUPS:
        for entry in entries:
            default = generated_token if entry.key == "SENTINEL_API_TOKEN" else entry.default
            values[entry.key] = _prompt(entry, default, interactive=interactive)
    return values


def write_env_file(path: Path, values: dict[str, str], *, force: bool = False) -> bool:
    if path.exists() and not force:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = [
        "# SENTINEL local configuration",
        "# Generated by scripts/init_sentinel.py",
        "",
    ]
    for group, entries in ENV_GROUPS:
        lines.append(f"# {group}")
        for entry in entries:
            lines.append(f"{entry.key}={_env_escape(values.get(entry.key, entry.default))}")
        lines.append("")
    temporary = path.with_name(f"{path.name}.tmp")
    temporary.write_text("\n".join(lines).rstrip() + "\n")
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    temporary.replace(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return True


def ensure_virtualenv(venv_path: Path) -> None:
    python = venv_path / "bin" / "python"
    if not python.exists():
        _run([sys.executable, "-m", "venv", str(venv_path)])
    _run([str(python), "-m", "pip", "install", "--upgrade", "pip"])
    _run([str(python), "-m", "pip", "install", "-e", "."])


def _prompt(entry: EnvEntry, default: str, *, interactive: bool) -> str:
    if not interactive:
        return default
    display_default = "<generated>" if entry.key == "SENTINEL_API_TOKEN" else default
    raw = input(f"{entry.prompt} [{display_default}]: ").strip()
    return raw or default


def _env_escape(value: str) -> str:
    if not value:
        return ""
    if any(char.isspace() or char in {'"', "'", "#"} for char in value):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return value


def _ensure_demo_kubeconfig(path: Path) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                "apiVersion: v1",
                "kind: Config",
                "clusters: []",
                "contexts: []",
                "users: []",
                "current-context: sentinel-local-demo",
                "",
            ]
        )
    )


def _project_path(value: str) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else PROJECT_ROOT / path


def _run(command: list[str]) -> None:
    try:
        subprocess.run(command, cwd=PROJECT_ROOT, check=True)
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"ERROR command failed ({exc.returncode}): {' '.join(command)}") from exc


if __name__ == "__main__":
    main()
