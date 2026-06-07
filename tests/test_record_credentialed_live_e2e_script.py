from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "record_credentialed_live_e2e.sh"


def test_recording_wrapper_is_shell_valid_and_names_both_logs():
    result = subprocess.run(
        ["bash", "-n", str(SCRIPT)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    content = SCRIPT.read_text()
    assert "--log-path" in content
    assert ".sentinel/live-run-${run_id}.log" in content
    assert ".sentinel/live-run-${run_id}.terminal.log" in content
    assert "tee" in content
