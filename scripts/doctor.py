from __future__ import annotations

import argparse
import importlib.util
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from sentinel.profiles import load_selected_profile, profile_missing_credentials


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MIN_PYTHON = (3, 13)
REQUIRED_ENV_KEYS = (
    "SENTINEL_ENV",
    "SENTINEL_API_TOKEN",
    "SENTINEL_APPROVER_ID",
    "DATABASE_URL",
    "REDIS_URL",
    "CONTAINER_KUBECONFIG",
)
REQUIRED_IMPORTS = (
    "fastapi",
    "httpx",
    "kubernetes",
    "opentelemetry",
    "psycopg",
    "pydantic",
    "redis",
    "uvicorn",
)


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    detail: str


def main() -> None:
    parser = argparse.ArgumentParser(description="Check whether SENTINEL can run locally.")
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--venv", default=".venv")
    args = parser.parse_args()

    env_path = _project_path(args.env_file)
    venv_path = _project_path(args.venv)
    env = _effective_env(env_path)
    checks = run_checks(env_path=env_path, venv_path=venv_path, env=env)
    for check in checks:
        marker = "PASS" if check.passed else "FAIL"
        print(f"{marker} {check.name}: {check.detail}")
    raise SystemExit(0 if all(check.passed for check in checks) else 1)


def run_checks(*, env_path: Path, venv_path: Path, env: dict[str, str]) -> list[Check]:
    checks = [
        _check_python_version(),
        _check_venv(venv_path),
        _check_env_file(env_path),
        _check_required_env(env),
        _check_profile_credentials(env),
        _check_command("docker"),
        _check_docker_compose(),
        _check_imports(),
        _check_compose_config(env_path),
    ]
    return checks


def _check_python_version() -> Check:
    version = sys.version_info[:3]
    passed = version >= MIN_PYTHON
    return Check(
        "python",
        passed,
        f"{version[0]}.{version[1]}.{version[2]} installed; need {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+",
    )


def _check_venv(venv_path: Path) -> Check:
    python = venv_path / "bin" / "python"
    return Check("venv", python.exists(), str(python) if python.exists() else "run make init")


def _check_env_file(env_path: Path) -> Check:
    return Check("env_file", env_path.exists(), str(env_path) if env_path.exists() else "run make init")


def _check_required_env(env: dict[str, str]) -> Check:
    missing = [key for key in REQUIRED_ENV_KEYS if not env.get(key)]
    if missing:
        return Check("required_env", False, "missing " + ", ".join(missing))
    return Check("required_env", True, f"{len(REQUIRED_ENV_KEYS)} required values present")


def _check_profile_credentials(env: dict[str, str]) -> Check:
    try:
        profile = load_selected_profile(env)
    except Exception as exc:
        return Check("profile_credentials", False, _one_line(str(exc)))
    missing = profile_missing_credentials(profile, env)
    if missing:
        return Check(
            "profile_credentials",
            False,
            f"{profile.name} missing " + ", ".join(missing),
        )
    return Check(
        "profile_credentials",
        True,
        f"{profile.name} credential checks passed",
    )


def _check_command(name: str) -> Check:
    path = shutil.which(name)
    return Check(name, bool(path), path or "not found on PATH")


def _check_docker_compose() -> Check:
    try:
        proc = subprocess.run(
            ["docker", "compose", "version"],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
    except Exception as exc:
        return Check("docker_compose", False, _one_line(str(exc)))
    output = (proc.stdout or proc.stderr).strip().splitlines()
    return Check("docker_compose", proc.returncode == 0, output[0] if output else "docker compose unavailable")


def _check_imports() -> Check:
    missing = [name for name in REQUIRED_IMPORTS if importlib.util.find_spec(name) is None]
    if missing:
        return Check("python_deps", False, "missing " + ", ".join(missing))
    return Check("python_deps", True, f"{len(REQUIRED_IMPORTS)} imports available")


def _check_compose_config(env_path: Path) -> Check:
    if shutil.which("docker") is None:
        return Check("compose_config", False, "docker not found")
    command = ["docker", "compose"]
    if env_path.exists():
        command.extend(["--env-file", str(env_path)])
    command.extend(["config", "-q"])
    try:
        proc = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except Exception as exc:
        return Check("compose_config", False, _one_line(str(exc)))
    if proc.returncode != 0:
        detail = _one_line(proc.stderr or proc.stdout or "docker compose config failed")
        return Check("compose_config", False, detail)
    return Check("compose_config", True, "docker compose config -q passed")


def _read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _effective_env(path: Path) -> dict[str, str]:
    values = _read_env(path)
    for key, value in os.environ.items():
        if value:
            values[key] = value
    return values


def _project_path(value: str) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else PROJECT_ROOT / path


def _one_line(value: str) -> str:
    return " ".join(value.strip().split())[:500] or "no detail"


if __name__ == "__main__":
    main()
