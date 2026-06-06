from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from typing import Any


DEFAULT_CLUSTER_NAME = "sentinel-free-tier"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Inspect or prepare local host prerequisites for the SENTINEL free-tier kind demo."
    )
    parser.add_argument("--cluster-name", default=DEFAULT_CLUSTER_NAME)
    parser.add_argument("--install-kind", action="store_true", help="Install kind with Homebrew if missing.")
    parser.add_argument("--create-cluster", action="store_true", help="Create the kind cluster if missing.")
    parser.add_argument("--use-context", action="store_true", help="Switch kubectl to the kind context.")
    parser.add_argument("--dry-run", action="store_true", help="Report planned actions without changing the host.")
    args = parser.parse_args(argv)

    summary = prepare_host(args)
    print(json.dumps(summary, indent=2))
    raise SystemExit(0 if summary["status"] in {"ready", "would_prepare"} else 2)


def prepare_host(args: argparse.Namespace) -> dict[str, Any]:
    checks = _initial_checks()
    actions: list[dict[str, Any]] = []
    kind_path = checks["binaries"]["kind"]

    if not kind_path and args.install_kind:
        action = _install_kind(args)
        actions.append(action)
        if action["status"] == "ok":
            kind_path = shutil.which("kind")
            checks["binaries"]["kind"] = kind_path

    cluster = _kind_cluster_status(args.cluster_name) if kind_path else _missing_kind_cluster_status(args.cluster_name)
    if kind_path and cluster["status"] == "missing" and args.create_cluster:
        action = _create_kind_cluster(args)
        actions.append(action)
        if action["status"] == "ok":
            cluster = _kind_cluster_status(args.cluster_name)

    context = _kubectl_context()
    expected_context = f"kind-{args.cluster_name}"
    if args.use_context and kind_path and cluster["status"] == "ready" and context.get("context") != expected_context:
        action = _use_context(expected_context, args)
        actions.append(action)
        if action["status"] == "ok":
            context = _kubectl_context()

    ready = (
        bool(checks["binaries"]["docker"])
        and bool(checks["binaries"]["kubectl"])
        and bool(checks["binaries"]["kind"])
        and checks["docker_daemon"]["passed"]
        and cluster["status"] == "ready"
        and context.get("context") == expected_context
    )
    status = "ready" if ready else ("would_prepare" if args.dry_run and actions else "not_ready")
    return {
        "status": status,
        "cluster_name": args.cluster_name,
        "expected_context": expected_context,
        "checks": checks,
        "cluster": cluster,
        "kubectl_context": context,
        "actions": actions,
        "next_commands": _next_commands(args.cluster_name),
    }


def _initial_checks() -> dict[str, Any]:
    docker_path = shutil.which("docker")
    return {
        "binaries": {
            "docker": docker_path,
            "kubectl": shutil.which("kubectl"),
            "kind": shutil.which("kind"),
            "brew": shutil.which("brew"),
        },
        "docker_daemon": _command_status(
            [docker_path, "info", "--format", "{{.ServerVersion}}"],
            skipped=not docker_path,
            timeout=10,
        ),
    }


def _install_kind(args: argparse.Namespace) -> dict[str, Any]:
    brew = shutil.which("brew")
    if not brew:
        return {
            "name": "install_kind",
            "status": "skipped",
            "reason": "Homebrew is not installed or not on PATH.",
        }
    command = [brew, "install", "kind"]
    if args.dry_run:
        return {"name": "install_kind", "status": "planned", "command": command}
    return {"name": "install_kind", **_run_command(command, timeout=600)}


def _create_kind_cluster(args: argparse.Namespace) -> dict[str, Any]:
    kind = shutil.which("kind")
    if not kind:
        return {"name": "create_kind_cluster", "status": "skipped", "reason": "kind is missing."}
    command = [kind, "create", "cluster", "--name", args.cluster_name]
    if args.dry_run:
        return {"name": "create_kind_cluster", "status": "planned", "command": command}
    return {"name": "create_kind_cluster", **_run_command(command, timeout=600)}


def _use_context(context: str, args: argparse.Namespace) -> dict[str, Any]:
    kubectl = shutil.which("kubectl")
    if not kubectl:
        return {"name": "use_context", "status": "skipped", "reason": "kubectl is missing."}
    command = [kubectl, "config", "use-context", context]
    if args.dry_run:
        return {"name": "use_context", "status": "planned", "command": command}
    return {"name": "use_context", **_run_command(command, timeout=30)}


def _kind_cluster_status(cluster_name: str) -> dict[str, Any]:
    kind = shutil.which("kind")
    if not kind:
        return _missing_kind_cluster_status(cluster_name)
    status = _command_status([kind, "get", "clusters"], timeout=30)
    if not status["passed"]:
        return {"status": "unknown", "cluster_name": cluster_name, "detail": status}
    clusters = [line.strip() for line in status.get("stdout", "").splitlines() if line.strip()]
    return {
        "status": "ready" if cluster_name in clusters else "missing",
        "cluster_name": cluster_name,
        "clusters": clusters,
    }


def _missing_kind_cluster_status(cluster_name: str) -> dict[str, Any]:
    return {
        "status": "unknown",
        "cluster_name": cluster_name,
        "detail": "kind is missing.",
    }


def _kubectl_context() -> dict[str, Any]:
    kubectl = shutil.which("kubectl")
    if not kubectl:
        return {"status": "missing", "context": None, "detail": "kubectl is missing."}
    status = _command_status([kubectl, "config", "current-context"], timeout=30)
    return {
        "status": "ready" if status["passed"] else "missing",
        "context": status.get("stdout", "").strip() if status["passed"] else None,
        "detail": status,
    }


def _command_status(
    command: list[str | None],
    *,
    skipped: bool = False,
    timeout: int = 30,
) -> dict[str, Any]:
    if skipped or not command or command[0] is None:
        return {"passed": False, "skipped": True, "detail": "command unavailable"}
    result = _run_command([str(part) for part in command], timeout=timeout)
    return {"passed": result["status"] == "ok", **result}


def _run_command(command: list[str], *, timeout: int) -> dict[str, Any]:
    try:
        proc = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        return {"status": "timeout", "command": command, "stderr": str(exc), "stdout": ""}
    return {
        "status": "ok" if proc.returncode == 0 else "failed",
        "command": command,
        "returncode": proc.returncode,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
    }


def _next_commands(cluster_name: str) -> dict[str, str]:
    return {
        "install_kind": "python3 scripts/prepare_free_tier_host.py --install-kind",
        "create_cluster": (
            "python3 scripts/prepare_free_tier_host.py "
            f"--cluster-name {cluster_name} --create-cluster --use-context"
        ),
        "check_readiness": "python3 scripts/check_free_tier_readiness.py",
    }


if __name__ == "__main__":
    main()
