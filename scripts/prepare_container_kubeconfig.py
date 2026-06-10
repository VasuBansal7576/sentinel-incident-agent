from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse, urlunparse


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = PROJECT_ROOT / ".sentinel" / "kubeconfig.container"
LOCAL_KUBE_HOSTS = {"127.0.0.1", "localhost"}
CONTAINER_HOST = "host.docker.internal"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Write a container-safe kubeconfig for Docker Compose by rewriting local kind "
            "API server URLs to host.docker.internal."
        )
    )
    parser.add_argument("--input", default=os.getenv("HOST_KUBECONFIG") or str(Path.home() / ".kube" / "config"))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--context", default="")
    parser.add_argument(
        "--update-env-file",
        default="",
        help="Optional .env file whose CONTAINER_KUBECONFIG value should be updated to the output path.",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    summary = prepare_container_kubeconfig(args)
    print(json.dumps(summary, indent=2))
    raise SystemExit(0 if summary["status"] in {"created", "would_create"} else 2)


def prepare_container_kubeconfig(args: argparse.Namespace) -> dict:
    input_path = Path(args.input).expanduser()
    output_path = Path(args.output).expanduser()
    if not input_path.exists():
        return {"status": "input_missing", "input": str(input_path)}
    raw, problem = _read_minified_kubeconfig(input_path, context=args.context.strip())
    if problem is not None:
        return problem
    rewritten, rewrites = _rewrite_kubeconfig(raw)
    if not rewrites:
        return {
            "status": "no_localhost_cluster",
            "input": str(input_path),
            "message": "No localhost or 127.0.0.1 cluster server URL was found to rewrite.",
        }

    env_updated = False
    if not args.dry_run:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(rewritten, indent=2) + "\n")
        if args.update_env_file:
            env_updated = _update_env_file(Path(args.update_env_file).expanduser(), "CONTAINER_KUBECONFIG", str(output_path))
    return {
        "status": "would_create" if args.dry_run else "created",
        "input": str(input_path),
        "output": str(output_path),
        "rewrites": rewrites,
        "env_file_updated": env_updated,
        "next_command": "docker compose up -d --force-recreate sentinel",
    }


def _read_minified_kubeconfig(path: Path, *, context: str = "") -> tuple[dict, dict | None]:
    kubectl = shutil.which("kubectl")
    if not kubectl:
        return {}, {"status": "kubectl_missing", "message": "kubectl is not installed or not on PATH."}
    command = [kubectl, "--kubeconfig", str(path)]
    if context:
        command += ["--context", context]
    command += ["config", "view", "--raw", "--minify", "-o", "json"]
    try:
        proc = subprocess.run(command, text=True, capture_output=True, timeout=30, check=False)
    except subprocess.TimeoutExpired as exc:
        return {}, {"status": "kubectl_timeout", "command": _redacted_command(command), "error": str(exc)}
    if proc.returncode != 0:
        return {}, {
            "status": "kubectl_failed",
            "command": _redacted_command(command),
            "stderr": proc.stderr.strip(),
        }
    try:
        return json.loads(proc.stdout), None
    except json.JSONDecodeError as exc:
        return {}, {"status": "kubectl_malformed_json", "error": str(exc)}


def _rewrite_kubeconfig(config: dict) -> tuple[dict, list[dict[str, str]]]:
    rewrites: list[dict[str, str]] = []
    for item in config.get("clusters") or []:
        cluster = item.get("cluster") if isinstance(item, dict) else None
        if not isinstance(cluster, dict):
            continue
        server = cluster.get("server")
        if not isinstance(server, str):
            continue
        parsed = urlparse(server)
        if parsed.hostname not in LOCAL_KUBE_HOSTS or not parsed.port:
            continue
        replacement = parsed._replace(netloc=f"{CONTAINER_HOST}:{parsed.port}")
        cluster["server"] = urlunparse(replacement)
        cluster["tls-server-name"] = parsed.hostname
        rewrites.append(
            {
                "cluster": str(item.get("name") or ""),
                "from": server,
                "to": cluster["server"],
                "tls_server_name": parsed.hostname,
            }
        )
    return config, rewrites


def _update_env_file(path: Path, key: str, value: str) -> bool:
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
    path.write_text("\n".join(rendered) + "\n")
    return True


def _redacted_command(command: list[str]) -> list[str]:
    return ["<kubeconfig>" if index > 0 and command[index - 1] == "--kubeconfig" else part for index, part in enumerate(command)]


if __name__ == "__main__":
    main()
