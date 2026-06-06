from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from sentinel.connectivity import run_live_connectivity_checks
from sentinel.errors import redact_sensitive_text
from sentinel.live_receiver_preflight import (
    operator_auth_headers as _operator_headers,
    receiver_check_exit_code as _exit_code,
    response_body as _body,
    run_http_receiver_check as _run_http_receiver_check,
)


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    env_file = _env_file_from_argv(argv) or os.getenv("SENTINEL_ENV_FILE") or str(PROJECT_ROOT / ".env")
    try:
        _load_env_file(Path(env_file))
    except Exception as exc:
        summary = {
            "status": "invalid_env_file",
            "env_file": env_file,
            "error": redact_sensitive_text(exc, max_length=500),
        }
        print(json.dumps(summary, indent=2))
        raise SystemExit(2) from exc

    parser = argparse.ArgumentParser(
        description="Check SENTINEL live provider connectivity locally or through a deployed receiver."
    )
    parser.add_argument(
        "--env-file",
        default=env_file,
        help="Load environment variables from this file before reading SENTINEL settings. Defaults to .env.",
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help="Deployed SENTINEL receiver URL. If omitted, checks connectivity in-process.",
    )
    parser.add_argument(
        "--api-token",
        default=os.getenv("SENTINEL_API_TOKEN"),
        help="Bearer token for deployed receiver operator endpoints.",
    )
    parser.add_argument("--timeout-seconds", type=float, default=20.0)
    args = parser.parse_args(argv)

    if args.base_url:
        with httpx.Client(timeout=args.timeout_seconds) as client:
            summary = run_http_receiver_check(args.base_url, args.api_token, client)
        print(json.dumps(summary, indent=2))
        raise SystemExit(_exit_code(summary))

    report = run_live_connectivity_checks()
    print(json.dumps(report.model_dump(mode="json"), indent=2))
    if _configuration_failed(report):
        raise SystemExit(2)
    if report.missing_live_credentials:
        raise SystemExit(2)
    if not report.ready:
        raise SystemExit(1)


def run_http_receiver_check(base_url: str, api_token: str | None, client: httpx.Client) -> dict:
    return _run_http_receiver_check(base_url, client, api_token=api_token)


def _configuration_failed(report) -> bool:
    for check in getattr(report, "checks", []):
        name = check.get("name") if isinstance(check, dict) else getattr(check, "name", None)
        if name == "sentinel.config":
            return True
    return False


def _env_file_from_argv(argv: list[str]) -> str | None:
    for index, item in enumerate(argv):
        if item == "--env-file" and index + 1 < len(argv):
            return argv[index + 1]
        if item.startswith("--env-file="):
            return item.partition("=")[2]
    return None


def _load_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    loaded: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text().splitlines(), start=1):
        parsed = _parse_env_line(raw_line, line_number=line_number, path=path)
        if parsed is None:
            continue
        key, value = parsed
        if key in os.environ:
            continue
        os.environ[key] = value
        loaded[key] = value
    return loaded


def _parse_env_line(raw_line: str, *, line_number: int, path: Path) -> tuple[str, str] | None:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("export "):
        line = line[len("export "):].strip()
    if "=" not in line:
        raise ValueError(f"{path}:{line_number} must be KEY=VALUE")
    key, value = line.split("=", 1)
    key = key.strip()
    if not key or not key.replace("_", "").isalnum() or key[0].isdigit():
        raise ValueError(f"{path}:{line_number} has invalid environment variable name")
    return key, _clean_env_value(value)


def _clean_env_value(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


if __name__ == "__main__":
    main()
