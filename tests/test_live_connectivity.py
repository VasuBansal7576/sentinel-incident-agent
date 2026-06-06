import os

import pytest

from sentinel.config import SentinelSettings
from sentinel.connectivity import run_live_connectivity_checks


pytestmark = pytest.mark.live

EXPECTED_LIVE_CONNECTIVITY_CHECKS = {
    "sentinel.state_store",
    "sentinel.redis",
    "datadog.logs",
    "datadog.metrics",
    "datadog.apm_spans",
    "github.commits",
    "github.pull_requests",
    "github.deployments",
    "pagerduty.incidents",
    "pagerduty.on_calls",
    "slack.auth",
    "slack.default_channel",
    "slack.channels",
    "kubernetes.pods",
    "kubernetes.deployments",
    "kubernetes.rollout_revisions",
}


def test_live_api_connectivity_when_credentials_are_present():
    settings = SentinelSettings.from_env()
    if not os.getenv("RUN_LIVE_TESTS"):
        pytest.skip("RUN_LIVE_TESTS unset")

    report = run_live_connectivity_checks(settings)
    if report.missing_live_credentials:
        pytest.fail(f"RUN_LIVE_TESTS is set but live credentials are missing: {report.missing_live_credentials}")

    assert report.ready
    assert {check.provider for check in report.checks} == {
        "sentinel",
        "datadog",
        "github",
        "pagerduty",
        "slack",
        "kubernetes",
    }
    assert {check.name for check in report.checks} == EXPECTED_LIVE_CONNECTIVITY_CHECKS
    assert all(check.passed for check in report.checks)
