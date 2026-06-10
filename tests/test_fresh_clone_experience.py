from __future__ import annotations

import json

from scripts import assert_demo_summary, doctor, init_sentinel


def test_init_writes_grouped_env_without_prompting(tmp_path):
    env_path = tmp_path / ".env"
    values = init_sentinel.collect_env_values(interactive=False)

    init_sentinel.write_env_file(env_path, values)

    body = env_path.read_text()
    assert "# REQUIRED" in body
    assert "# FREE_TIER" in body
    assert "# OPTIONAL_ENTERPRISE" in body
    assert "SENTINEL_API_TOKEN=sentinel-" in body
    assert "SENTINEL_APPROVER_ID=eng-oncall" in body
    assert "PROMETHEUS_URL=http://prometheus:9090" in body


def test_doctor_required_env_check_is_line_oriented():
    missing = doctor._check_required_env({"SENTINEL_ENV": "development"})
    passing = doctor._check_required_env(
        {key: "set" for key in doctor.REQUIRED_ENV_KEYS}
    )

    assert missing.passed is False
    assert missing.name == "required_env"
    assert "\n" not in missing.detail
    assert "SENTINEL_API_TOKEN" in missing.detail
    assert passing.passed is True


def test_demo_summary_asserts_all_8_phases(tmp_path):
    summary = {
        "status": "completed",
        "current_state": "post_mortem",
        "visited_states": sorted(assert_demo_summary.EXPECTED_STATES),
        "plan_steps": [{"number": index} for index in range(1, 27)],
        "tool_calls": 37,
        "all_tool_calls_have_reasoning_trace": True,
    }
    path = tmp_path / "summary.json"
    path.write_text(json.dumps(summary))

    assert assert_demo_summary.validate_summary(summary) == []

    broken = {**summary, "visited_states": ["received"]}
    assert "missing visited states" in assert_demo_summary.validate_summary(broken)[0]
