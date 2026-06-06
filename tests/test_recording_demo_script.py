import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_recording_demo_prints_crisp_timeline_without_raw_json(tmp_path):
    summary_path = tmp_path / "recording-summary.json"
    proc = subprocess.run(
        [
            sys.executable,
            "scripts/run_sentinel_demo.py",
            "--skip-compose",
            "--summary-output",
            str(summary_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    output = proc.stdout
    required_diagnosis = (
        "PR #847 by @alice added SELECT * FROM orders WHERE user_id = ? "
        "without an index on orders.user_id, causing sequential scans. "
        "Query time: 4ms \u2192 2.3s (575x)."
    )

    assert "🚨 SENTINEL RECORDING DEMO" in output
    assert "🧠 Autonomy Trace" in output
    assert "🧾 Incident Timeline" in output
    assert "📣 Discord Message Preview" in output
    assert "story-facing tools shown: 8" in output
    assert "Full run: 35 tool calls, 26 plan steps, status=completed" in output
    assert required_diagnosis in output
    assert "repo.diff_pull_request" in output
    assert "Blame points payment_service/orders.py:84 to @alice" in output
    assert not output.lstrip().startswith("{")

    summary = json.loads(summary_path.read_text())
    assert summary["status"] == "completed"
    assert summary["all_tool_calls_have_reasoning_trace"] is True
    assert summary["story_tools"] == [
        "observe.fetch_service_logs",
        "observe.query_metrics_range",
        "observe.check_db_slow_queries",
        "repo.get_deploy_history",
        "repo.diff_pull_request",
        "repo.blame_file_line",
        "infra.rollback_deployment",
        "observe.get_error_rate_timeseries",
    ]
