from __future__ import annotations

import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (PROJECT_ROOT / path).read_text(encoding="utf-8")


def test_video_script_satisfies_problem_md_walkthrough_requirements():
    script = _read("VIDEO_SCRIPT.md")

    assert "37 tool calls" in script
    assert "35 tool calls" not in script
    assert "52-tool registry" in script
    assert "IsolatedSubagentContext" in script
    assert "model" in script.lower()
    assert "diverged" in script.lower() or "divergence" in script.lower()


def test_memo_is_one_page_and_answers_required_sections():
    memo = _read("MEMO.md")
    words = re.findall(r"\S+", memo)

    assert len(words) <= 450
    assert "## What I Built" in memo
    assert "## What I Cut" in memo
    assert "## More Time" in memo
    assert "## Decision I Defend" in memo
    assert "52-tool registry" in memo
    assert "37 recorded tool calls" in memo


def test_submission_trace_strategy_distinguishes_unedited_and_public_safe_artifacts():
    submission = _read("SUBMISSION.md")
    gitignore = _read(".gitignore")

    assert "native, unedited Codex JSONL export" in submission
    assert "codex-traces-redacted.jsonl" in submission
    assert "not the required unedited trace artifact" in submission
    assert "submitted outside the public repository" in submission
    assert "codex-traces-native*.jsonl" in gitignore
    assert "codex-traces-unedited*.jsonl" in gitignore


def test_public_submission_artifacts_do_not_contain_live_secret_shapes():
    artifact_paths = [
        "MEMO.md",
        "README.md",
        "SUBMISSION.md",
        "VIDEO_SCRIPT.md",
        "docs/live-proof.md",
        "codex-traces-redacted.jsonl",
    ]
    combined = "\n".join(_read(path) for path in artifact_paths if (PROJECT_ROOT / path).exists())

    forbidden_patterns = {
        "discord_webhook": r"https://discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]{20,}",
        "github_token": r"gh[oprsu]_[A-Za-z0-9_]{20,}",
        "openai_key": r"sk-[A-Za-z0-9_-]{20,}",
        "slack_token": r"xox[baprs]-\d{6,}-[A-Za-z0-9-]{10,}",
        "encrypted_reasoning": r'"encrypted_content":"gAAAA',
    }

    leaks = {
        name: pattern
        for name, pattern in forbidden_patterns.items()
        if re.search(pattern, combined)
    }
    assert leaks == {}
