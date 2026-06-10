from __future__ import annotations

import argparse
import json
from pathlib import Path


EXPECTED_STATES = {
    "received",
    "triage",
    "evidence_collection",
    "service_investigation",
    "correlation",
    "response_proposal",
    "remediation",
    "post_mortem",
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Assert that make demo completed the full SENTINEL flow.")
    parser.add_argument("summary", help="Path written by scripts/run_sentinel_demo.py --summary-output")
    args = parser.parse_args()

    summary_path = Path(args.summary)
    summary = json.loads(summary_path.read_text())
    failures = validate_summary(summary)
    if failures:
        for failure in failures:
            print(f"FAIL demo: {failure}")
        raise SystemExit(1)
    print("PASS demo: exit=0 and all 8 phases completed")


def validate_summary(summary: dict) -> list[str]:
    failures: list[str] = []
    if summary.get("status") != "completed":
        failures.append(f"status is {summary.get('status')!r}")
    if summary.get("current_state") != "post_mortem":
        failures.append(f"current_state is {summary.get('current_state')!r}")
    visited = set(summary.get("visited_states") or [])
    missing = sorted(EXPECTED_STATES - visited)
    if missing:
        failures.append("missing visited states: " + ", ".join(missing))
    if len(summary.get("plan_steps") or []) < 26:
        failures.append("expected at least 26 plan steps")
    if summary.get("tool_calls", 0) < 26:
        failures.append("expected at least 26 tool calls")
    if not summary.get("all_tool_calls_have_reasoning_trace"):
        failures.append("tool calls are missing reasoning traces")
    return failures


if __name__ == "__main__":
    main()
