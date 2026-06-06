import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_free_tier_sentinel_demo.py"
PAID_PROVIDER_PROOF_NAMES = ("datadog", "pagerduty", "slack")


pytestmark = pytest.mark.live


def test_free_tier_deployed_receiver_reaches_discord_proposal():
    if not os.getenv("RUN_FREE_TIER_LIVE_E2E_TESTS"):
        pytest.skip("RUN_FREE_TIER_LIVE_E2E_TESTS unset")

    summary = _run_free_tier_demo(proposal_only=True)

    assert summary["status"] == "waiting_for_approval", json.dumps(summary, indent=2)
    _assert_free_provider_proofs(summary, approved=False)
    assert summary["notification_provider"] == "discord"
    assert summary["discord_notified"] is True
    assert summary["approval_slack_notified"] is True
    assert summary["approval_slack_notification_request_id"] == summary["approval_request_id"]
    assert summary["rollback_attempted"] is False
    assert summary["rollback_executed"] is False


def test_free_tier_deployed_receiver_approval_executes_kind_rollback():
    if not os.getenv("RUN_FREE_TIER_LIVE_APPROVAL_E2E_TESTS"):
        pytest.skip("RUN_FREE_TIER_LIVE_APPROVAL_E2E_TESTS unset")

    summary = _run_free_tier_demo(proposal_only=False)

    assert summary["status"] == "completed", json.dumps(summary, indent=2)
    _assert_free_provider_proofs(summary, approved=True)
    assert summary["notification_provider"] == "discord"
    assert summary["discord_notified"] is True
    assert summary["approval_slack_notified"] is True
    assert summary["approval_slack_notification_request_id"] == summary["approval_request_id"]
    assert summary["approval_command_received"] is True
    assert summary["approval_command_request_id"] == summary["approval_request_id"]
    assert summary["approval_command_decision"] == "approve"
    assert summary["approval_command_approver_id"] in summary["approval_approver_ids"]
    assert summary["rollback_attempted"] is True
    assert summary["rollback_executed"] is True
    assert summary["remediation_result"]["status"] == "executed"


def test_free_tier_e2e_proof_helper_rejects_paid_provider_leakage():
    summary = {
        "requested_incident_id": "FREE-1",
        "webhook_source": "generic_webhook",
        "generic_webhook_received": True,
        "webhook_ingress": {
            "source": "generic_webhook",
            "incident_id": "FREE-1",
        },
        "live_provider_proofs": {
            "prometheus": 1,
            "loki": 1,
            "github": 1,
            "generic_webhook": 1,
            "discord": 1,
            "kubernetes": 1,
            "datadog": 1,
        },
        "live_tool_proofs": {
            "observe.fetch_service_logs": 1,
            "observe.get_error_rate_timeseries": 1,
            "observe.fetch_apm_data": 1,
            "repo.get_deploy_history": 1,
            "repo.get_rollback_targets": 1,
            "observe.check_pod_health": 1,
            "comms.page_oncall_engineer": 1,
            "comms.post_to_slack": 1,
        },
    }

    with pytest.raises(AssertionError) as exc:
        _assert_free_provider_proofs(summary, approved=False)

    assert "paid_providers" in str(exc.value)


def _run_free_tier_demo(*, proposal_only: bool) -> dict:
    incident_id = _free_incident_id("proposal" if proposal_only else "approval")
    base_url = (
        os.getenv("SENTINEL_LIVE_RECEIVER_URL")
        or os.getenv("SENTINEL_BASE_URL")
        or "http://localhost:8000"
    )
    command = [
        sys.executable,
        str(SCRIPT),
        incident_id,
        "--base-url",
        base_url,
    ]
    if proposal_only:
        command.append("--proposal-only")

    timeout = int(os.getenv("SENTINEL_LIVE_E2E_TIMEOUT_SECONDS", "180")) + 120
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    try:
        summary = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            "free-tier demo script did not emit JSON\n"
            f"returncode={result.returncode}\nstdout={result.stdout}\nstderr={result.stderr}"
        ) from exc
    assert result.returncode == 0, json.dumps(
        {
            "returncode": result.returncode,
            "stdout": summary,
            "stderr": result.stderr,
        },
        indent=2,
    )
    assert summary["requested_incident_id"] == incident_id
    assert summary["incident_id"] == incident_id
    return summary


def _free_incident_id(suffix: str) -> str:
    prefix = os.getenv("SENTINEL_FREE_TIER_LIVE_TEST_INCIDENT_ID", "FREE-TIER-LIVE-E2E")
    return f"{prefix}-{suffix}-{int(time.time())}"


def _assert_free_provider_proofs(summary: dict, *, approved: bool) -> None:
    required_providers = (
        "prometheus",
        "loki",
        "github",
        "generic_webhook",
        "discord",
        "kubernetes",
    )
    required_tools = [
        "observe.fetch_service_logs",
        "observe.get_error_rate_timeseries",
        "observe.fetch_apm_data",
        "repo.get_deploy_history",
        "repo.get_rollback_targets",
        "observe.check_pod_health",
        "comms.page_oncall_engineer",
        "comms.post_to_slack",
    ]
    if approved:
        required_tools.append("infra.rollback_deployment")

    missing_providers = [
        provider
        for provider in required_providers
        if _proof_count(summary["live_provider_proofs"].get(provider, 0)) <= 0
    ]
    paid_providers = [
        provider
        for provider in PAID_PROVIDER_PROOF_NAMES
        if _proof_count(summary["live_provider_proofs"].get(provider, 0)) > 0
    ]
    missing_tools = [
        tool_name
        for tool_name in required_tools
        if _proof_count(summary["live_tool_proofs"].get(tool_name, 0)) <= 0
    ]
    assert summary.get("webhook_source") == "generic_webhook", summary
    assert summary.get("generic_webhook_received") is True, summary
    webhook_ingress = summary.get("webhook_ingress")
    assert isinstance(webhook_ingress, dict), summary
    assert webhook_ingress.get("source") == "generic_webhook", summary
    assert webhook_ingress.get("incident_id") == summary.get("requested_incident_id"), summary
    assert not missing_providers, {
        "missing_providers": missing_providers,
        "proofs": summary["live_provider_proofs"],
    }
    assert not paid_providers, {
        "paid_providers": paid_providers,
        "proofs": summary["live_provider_proofs"],
    }
    assert not missing_tools, {
        "missing_tools": missing_tools,
        "proofs": summary["live_tool_proofs"],
    }


def _proof_count(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
