from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import httpx


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(SCRIPT_DIR))

import run_free_tier_sentinel_demo as free_demo
from sentinel.config import SentinelSettings
from sentinel.errors import redact_sensitive_text
from sentinel.live_receiver_preflight import (
    operator_auth_headers,
    receiver_check_exit_code,
    run_http_receiver_check,
)


def main(argv: list[str] | None = None) -> None:
    argv = list(argv or sys.argv[1:])
    env_file = (
        free_demo._env_file_from_argv(argv)
        or os.getenv("SENTINEL_ENV_FILE")
        or str(PROJECT_ROOT / ".env")
    )
    try:
        loaded_env = free_demo._load_env_file(Path(env_file))
    except Exception as exc:
        summary = {
            "status": "invalid_env_file",
            "env_file": env_file,
            "error": redact_sensitive_text(exc, max_length=500),
        }
        print(json.dumps(summary, indent=2))
        raise SystemExit(2) from exc

    parser = argparse.ArgumentParser(
        description=(
            "Validate the free-tier SENTINEL demo environment without posting a webhook "
            "or executing remediation."
        )
    )
    parser.add_argument("--env-file", default=env_file)
    parser.add_argument("--base-url", default=os.getenv("SENTINEL_BASE_URL", "http://localhost:8000"))
    parser.add_argument("--api-token", default=os.getenv("SENTINEL_API_TOKEN"))
    parser.add_argument("--timeout-seconds", type=float, default=20.0)
    parser.add_argument(
        "--skip-kind-bootstrap",
        action="store_true",
        help="Do not require a host-side kubeconfig path before reporting config readiness.",
    )
    parser.add_argument(
        "--allow-paid-provider-env",
        action="store_true",
        help="Allow Datadog, PagerDuty, or Slack credentials to be present.",
    )
    parser.add_argument(
        "--allow-local-discord-webhook",
        action="store_true",
        help="Allow a non-Discord webhook URL for local stub testing. Do not use this for final live-demo proof.",
    )
    parser.add_argument(
        "--skip-host-tool-check",
        action="store_true",
        help="Only validate configuration; do not check docker, kubectl, kind, or the active kube context.",
    )
    parser.add_argument(
        "--allow-non-kind-context",
        action="store_true",
        help="Allow host prerequisite checks to pass when kubectl's current context is not a kind context.",
    )
    parser.add_argument(
        "--check-receiver",
        action="store_true",
        help="Also call the deployed receiver's /ready/live and /live/connectivity endpoints.",
    )
    args = parser.parse_args(argv)

    summary = build_readiness_summary(args, env_file=env_file, loaded_env=loaded_env)
    print(json.dumps(summary, indent=2))
    raise SystemExit(exit_code(summary))


def build_readiness_summary(
    args: argparse.Namespace,
    *,
    env_file: str,
    loaded_env: dict[str, str] | None = None,
) -> dict:
    try:
        settings = SentinelSettings.from_env()
    except Exception as exc:
        return {
            "status": "invalid_config",
            "env_file": env_file,
            "env_file_loaded": bool(loaded_env),
            "error": redact_sensitive_text(exc, max_length=500),
        }

    paid_vars = free_demo._configured_paid_provider_env_vars()
    config_problem = free_demo._free_tier_config_problem(settings, args)
    host_prerequisites = _host_prerequisites(settings, args)
    receiver_summary = None
    receiver_check = None
    if getattr(args, "check_receiver", False):
        if config_problem is None:
            receiver_summary = _receiver_summary(settings, args)
        else:
            receiver_check = _skipped_receiver_check(config_problem)

    ready = (
        config_problem is None
        and (not paid_vars or bool(getattr(args, "allow_paid_provider_env", False)))
        and host_prerequisites["passed"]
        and (receiver_summary is None or receiver_summary.get("status") == "ready")
    )
    summary = {
        "status": "ready" if ready else "not_ready",
        "env_file": env_file,
        "env_file_loaded": bool(loaded_env),
        "loaded_env_keys": sorted((loaded_env or {}).keys()),
        "free_provider_configured": config_problem is None,
        "paid_provider_credentials_present": paid_vars,
        "paid_provider_credentials_allowed": bool(getattr(args, "allow_paid_provider_env", False)),
        "required_free_env": [name for name, _attr in free_demo.REQUIRED_FREE_SETTINGS],
        "host_kubeconfig": free_demo._host_kubeconfig(settings),
        "host_prerequisites": host_prerequisites,
        "next_commands": _next_commands(),
    }
    if config_problem is not None:
        summary["config_problem"] = config_problem
    if paid_vars and not bool(getattr(args, "allow_paid_provider_env", False)):
        summary["paid_provider_problem"] = {
            "message": (
                "Unset paid provider credentials to prove the free-provider path, "
                "or pass --allow-paid-provider-env for mixed-environment debugging."
            ),
            "variables": paid_vars,
        }
    if receiver_summary is not None:
        summary["receiver"] = receiver_summary
    if receiver_check is not None:
        summary["receiver_check"] = receiver_check
    return summary


def exit_code(summary: dict) -> int:
    if summary.get("status") == "ready":
        return 0
    receiver = summary.get("receiver")
    if isinstance(receiver, dict) and receiver.get("status") != "ready":
        return receiver_check_exit_code(receiver)
    if summary.get("status") in {"invalid_env_file", "invalid_config", "not_ready"}:
        return 2
    return 1


def _receiver_summary(settings: SentinelSettings, args: argparse.Namespace) -> dict:
    api_token = args.api_token or settings.api_token
    with httpx.Client(timeout=args.timeout_seconds) as client:
        return run_http_receiver_check(
            args.base_url,
            client,
            operator_headers=operator_auth_headers(api_token),
        )


def _skipped_receiver_check(config_problem: dict) -> dict:
    return {
        "requested": True,
        "status": "skipped",
        "reason": "free_provider_config_incomplete",
        "message": (
            "Receiver preflight was not attempted because local free-tier "
            "configuration is incomplete."
        ),
        "missing": config_problem.get("missing", []),
        "invalid": config_problem.get("invalid", []),
    }


def _host_prerequisites(settings: SentinelSettings, args: argparse.Namespace) -> dict:
    if bool(getattr(args, "skip_host_tool_check", False)):
        return {"checked": False, "passed": True, "checks": []}
    checks = [
        _binary_check("docker"),
        _binary_check("kubectl"),
        _binary_check("kind"),
    ]
    docker_path = checks[0].get("path")
    if docker_path:
        checks.append(_command_check([docker_path, "info", "--format", "{{.ServerVersion}}"], "docker.daemon"))

    kubeconfig = free_demo._host_kubeconfig(settings)
    kubectl_path = checks[1].get("path")
    if kubectl_path and kubeconfig and Path(kubeconfig).exists():
        command = [kubectl_path, "--kubeconfig", kubeconfig, "config", "current-context"]
        context_check = _command_check(command, "kubectl.current_context")
        context = str(context_check.get("stdout") or "").strip()
        if (
            context_check["passed"]
            and "kind" not in context.lower()
            and not bool(getattr(args, "allow_non_kind_context", False))
        ):
            context_check = {
                **context_check,
                "passed": False,
                "detail": "current kubectl context is not a kind context",
            }
        checks.append(context_check)
    return {
        "checked": True,
        "passed": all(bool(check.get("passed")) for check in checks),
        "checks": checks,
    }


def _binary_check(name: str) -> dict:
    path = shutil.which(name)
    return {
        "name": f"{name}.binary",
        "passed": bool(path),
        "path": path,
        "detail": "found" if path else f"{name} is not installed or not on PATH",
    }


def _command_check(command: list[str], name: str) -> dict:
    try:
        proc = subprocess.run(command, text=True, capture_output=True, timeout=10, check=False)
    except Exception as exc:
        return {
            "name": name,
            "passed": False,
            "detail": redact_sensitive_text(exc, max_length=300),
        }
    return {
        "name": name,
        "passed": proc.returncode == 0,
        "stdout": redact_sensitive_text(proc.stdout.strip(), max_length=300),
        "stderr": redact_sensitive_text(proc.stderr.strip(), max_length=300),
        "detail": "ok" if proc.returncode == 0 else f"command exited {proc.returncode}",
    }


def _next_commands() -> dict[str, str]:
    return {
        "bootstrap_env": (
            "python3 scripts/bootstrap_free_tier_env.py "
            "--github-token-from-gh-cli --github-owner <owner> --github-repo <repo>"
        ),
        "configure_discord": "python3 scripts/configure_discord_webhook.py --test-post",
        "prepare_host": "python3 scripts/prepare_free_tier_host.py --install-kind --create-cluster --use-context",
        "prepare_container_kubeconfig": (
            "python3 scripts/prepare_container_kubeconfig.py "
            "--update-env-file .env"
        ),
        "start_stack": "docker compose up --build",
        "check_receiver": "python3 scripts/check_free_tier_readiness.py --check-receiver",
        "run_demo": (
            "python3 scripts/run_free_tier_sentinel_demo.py FREE-DEMO-001 "
            "--base-url http://localhost:8000 "
            "--summary-output .sentinel/free-tier-demo-summary.json"
        ),
        "audit_goal": "python3 scripts/audit_free_tier_goal.py --demo-summary .sentinel/free-tier-demo-summary.json",
        "run_live_e2e": (
            "RUN_FREE_TIER_LIVE_APPROVAL_E2E_TESTS=1 "
            "SENTINEL_LIVE_RECEIVER_URL=http://localhost:8000 "
            "pytest tests/test_free_tier_live_e2e.py"
        ),
    }


if __name__ == "__main__":
    main()
