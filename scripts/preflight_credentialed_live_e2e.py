from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PORTS = {
    8000: "SENTINEL receiver",
    5432: "PostgreSQL",
    6379: "Redis",
    9090: "Prometheus",
    3100: "Loki",
}
REQUIRED_FILES = (
    "Dockerfile",
    "docker-compose.yml",
    "configs/prometheus.yml",
    "configs/prometheus.rules.yml",
    "scripts/run_credentialed_live_e2e.py",
    "scripts/verify_credentialed_live_log.py",
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run non-secret local checks before the credentialed SENTINEL live E2E."
    )
    parser.add_argument("--project-root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--compose-project", default="sentinel-live")
    parser.add_argument("--skip-compose", action="store_true")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    args = parser.parse_args()

    summary = run_preflight(
        project_root=args.project_root,
        compose_project=args.compose_project,
        check_compose=not args.skip_compose,
    )
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(_human_summary(summary))
    raise SystemExit(0 if summary["passed"] else 2)


def run_preflight(
    *,
    project_root: Path = PROJECT_ROOT,
    compose_project: str = "sentinel-live",
    check_compose: bool = True,
) -> dict[str, Any]:
    root = project_root.resolve()
    checks: list[dict[str, Any]] = []
    for relpath in REQUIRED_FILES:
        path = root / relpath
        checks.append(
            _check(
                f"file.{relpath}",
                path.exists(),
                "required file exists",
                f"missing required file: {relpath}",
                severity="error",
            )
        )
    checks.append(_command_available("python3"))
    checks.append(_command_available("docker"))
    if check_compose:
        checks.append(
            _run_command_check(
                "docker.daemon",
                ["docker", "info"],
                cwd=root,
                success_detail="Docker daemon is reachable.",
                failure_detail="Docker daemon is not reachable; start Docker Desktop before recording.",
            )
        )
        checks.append(
            _run_command_check(
                "docker.compose.version",
                ["docker", "compose", "version"],
                cwd=root,
                success_detail="Docker Compose plugin is available.",
                failure_detail="Docker Compose plugin is unavailable.",
            )
        )
        checks.append(
            _run_command_check(
                "docker.compose.config",
                ["docker", "compose", "config", "-q"],
                cwd=root,
                success_detail="docker-compose.yml renders successfully.",
                failure_detail="docker compose config -q failed.",
            )
        )
    for port, name in DEFAULT_PORTS.items():
        checks.append(_port_warning(port, name))
    kubeconfig = Path.home() / ".kube" / "config"
    checks.append(
        _check(
            "kubeconfig.default",
            kubeconfig.exists(),
            f"default kubeconfig exists at {kubeconfig}",
            (
                f"default kubeconfig missing at {kubeconfig}; press Enter only if you do not "
                "need Kubernetes rollback proof, or provide HOST/CONTAINER_KUBECONFIG in the live run."
            ),
            severity="warning",
        )
    )
    errors = [check for check in checks if check["severity"] == "error" and not check["passed"]]
    warnings = [check for check in checks if check["severity"] == "warning" and not check["passed"]]
    return {
        "passed": not errors,
        "status": "ready" if not errors else "not_ready",
        "compose_project": compose_project,
        "project_root": str(root),
        "errors": errors,
        "warnings": warnings,
        "checks": checks,
    }


def _command_available(name: str) -> dict[str, Any]:
    path = shutil.which(name)
    return _check(
        f"command.{name}",
        bool(path),
        f"{name} found at {path}",
        f"{name} is not available on PATH.",
        severity="error",
    )


def _run_command_check(
    name: str,
    command: list[str],
    *,
    cwd: Path,
    success_detail: str,
    failure_detail: str,
) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except Exception as exc:
        return {
            "name": name,
            "passed": False,
            "severity": "error",
            "detail": f"{failure_detail} {type(exc).__name__}: {exc}",
            "command": command,
        }
    passed = proc.returncode == 0
    detail = success_detail if passed else failure_detail
    return {
        "name": name,
        "passed": passed,
        "severity": "error",
        "detail": detail,
        "command": command,
        "returncode": proc.returncode,
        "stdout_tail": proc.stdout[-1000:],
        "stderr_tail": proc.stderr[-1000:],
    }


def _port_warning(port: int, service: str) -> dict[str, Any]:
    free = _port_free(port)
    return _check(
        f"port.{port}",
        free,
        f"localhost:{port} is free for {service}.",
        (
            f"localhost:{port} is already in use. This is okay if it is the existing "
            f"{service} container for compose project sentinel-live; otherwise stop the process before recording."
        ),
        severity="warning",
    )


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex(("127.0.0.1", port)) != 0


def _check(
    name: str,
    passed: bool,
    success_detail: str,
    failure_detail: str,
    *,
    severity: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "passed": bool(passed),
        "severity": severity,
        "detail": success_detail if passed else failure_detail,
    }


def _human_summary(summary: dict[str, Any]) -> str:
    lines = [
        f"SENTINEL credentialed live preflight: {summary['status']}",
        f"Project root: {summary['project_root']}",
    ]
    for check in summary["checks"]:
        mark = "PASS" if check["passed"] else check["severity"].upper()
        lines.append(f"- {mark}: {check['name']} - {check['detail']}")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
