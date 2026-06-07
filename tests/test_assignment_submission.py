from __future__ import annotations

import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (PROJECT_ROOT / path).read_text(encoding="utf-8")


def test_public_proof_docs_satisfy_problem_md_requirements():
    public_proof = "\n".join(
        [
            _read("README.md"),
            _read("architecture.md"),
            _read("MEMO.md"),
            _read("docs/model-driven-proof.md"),
            _read("docs/subagent-proof.md"),
            _read("docs/live-proof.md"),
        ]
    )

    assert "37 tool calls" in public_proof
    assert "35 tool calls" not in public_proof
    assert "52-tool registry" in public_proof
    assert "ServiceIncidentReport" in public_proof
    assert "model_response_parsed" in public_proof
    assert "framework-style agent stack" in public_proof
    assert "deterministic guardrails" in public_proof
    assert "52 ToolContract registry" in public_proof
    assert "infra.spawn_service_investigator" in public_proof
    assert "Reviewer File Map" in public_proof


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
    readme = _read("README.md")
    gitignore = _read(".gitignore")

    assert "codex-traces-redacted.jsonl" in readme
    assert "public-safe redacted trace copy" in readme
    assert "Native unedited Codex trace" in readme
    assert "submitted separately as the email attachment required by `Problem.md`" in readme
    assert "do not use it as a substitute for the native unedited Codex trace attachment" in readme
    assert "codex-traces-native*.jsonl" in gitignore
    assert "codex-traces-unedited*.jsonl" in gitignore
    assert "codex-traces.jsonl" in gitignore


def test_public_submission_artifacts_do_not_contain_live_secret_shapes():
    artifact_paths = [
        "MEMO.md",
        "README.md",
        "docs/live-proof.md",
        "docs/model-driven-proof.md",
        "docs/subagent-proof.md",
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
