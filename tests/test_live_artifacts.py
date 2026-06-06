import base64
import json
import subprocess
from dataclasses import replace
from types import SimpleNamespace

import pytest

from sentinel.circuit_breaker import CircuitBreaker
from sentinel.config import SentinelSettings
from sentinel.errors import ToolErrorKind, ToolExecutionError
from sentinel.live_clients import (
    GenericAlertClient,
    KubernetesClient,
    _created_within,
    _deployment_selector,
    _replica_set_revisions,
    _replica_sets_owned_by,
)
from sentinel.models import InvestigationState, RemediationReadinessReport
from sentinel.orchestrator import SentinelOrchestrator
from sentinel.rate_limiters import InMemoryRateLimitBackend, SharedRateLimiter
from sentinel.real_tools import (
    LIVE_TOOL_HANDLERS,
    LiveToolRouter,
    _dashboard,
    _evidence_from_live_result,
    _github_blame,
    _github_commits,
    _github_contents,
    _github_deployments,
    _github_issue,
    _github_pr,
    _github_runbook,
    _github_status,
    _logs,
    _k8s_drain,
    _k8s_job,
    _k8s_patch,
    _k8s_rollback,
    _k8s_restart,
    _k8s_scale,
    _pagerduty_close,
    _pagerduty_oncall,
    _rollback_targets,
    _slack_channel,
    _slack_post,
    _slack_schedule,
)
from sentinel.time_windows import repository_payload


def test_live_github_pr_handler_infers_recent_pr_instead_of_defaulting_to_one():
    router = LiveToolRouter(_FakeClients())

    result = _github_pr(router, {"service": "checkout-service"})

    assert result["pull_request"]["number"] == 231
    assert _FakeClients.github.requested_pull_request == 231
    assert _FakeClients.github.requested_pull_request != 1


def test_live_github_pr_handler_infers_pr_from_incident_window_commit_sha():
    clients = _FakePrCorrelationClients(
        commits=[{"sha": "sha-window", "commit": {"message": "Deploy checkout change"}}],
        pull_requests=[
            {"number": 999, "merge_commit_sha": "sha-other"},
            {"number": 456, "merge_commit_sha": "sha-window"},
        ],
    )
    router = LiveToolRouter(clients)

    result = _github_pr(
        router,
        {
            "service": "checkout-service",
            "time_window": "2024-01-15T02:42:00Z",
            "time_window_end": "2024-01-15T03:27:00Z",
        },
    )

    assert result["pull_request"]["number"] == 456
    assert clients.github.requested_pull_request == 456
    assert clients.github.pull_request_kwargs == {"state": "closed", "per_page": 20}
    assert clients.github.commit_kwargs == {
        "per_page": 10,
        "since": "2024-01-15T02:42:00Z",
        "until": "2024-01-15T03:27:00Z",
    }


def test_live_github_pr_handler_confirms_pr_by_paginated_pr_commits():
    clients = _FakePrCorrelationClients(
        commits=[{"sha": "sha-window", "commit": {"message": "Deploy checkout change"}}],
        pull_requests=[
            {"number": 999, "merge_commit_sha": "sha-other"},
            {"number": 456, "merge_commit_sha": "sha-not-window"},
        ],
        pull_request_commits={
            999: [{"sha": "sha-other"}],
            456: [{"sha": "sha-window"}],
        },
    )
    router = LiveToolRouter(clients)

    result = _github_pr(router, {"service": "checkout-service"})

    assert result["pull_request"]["number"] == 456
    assert clients.github.requested_pull_request_commits == [999, 456]
    assert clients.github.requested_pull_request == 456


def test_live_github_pr_handler_rejects_uncorrelated_recent_pr():
    clients = _FakePrCorrelationClients(
        commits=[{"sha": "sha-window", "commit": {"message": "Deploy checkout change"}}],
        pull_requests=[{"number": 999, "merge_commit_sha": "sha-other"}],
    )
    router = LiveToolRouter(clients)

    with pytest.raises(ToolExecutionError) as exc:
        _github_pr(router, {"service": "checkout-service"})

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "No incident-window pull request" in str(exc.value)


def test_live_github_pr_handler_rejects_unconfirmed_commit_message_pr_reference():
    clients = _FakePrCorrelationClients(
        commits=[
            {
                "sha": "sha-window",
                "commit": {"message": "Merge pull request #999 from example/unrelated"},
            }
        ],
        pull_requests=[],
    )
    router = LiveToolRouter(clients)

    with pytest.raises(ToolExecutionError) as exc:
        _github_pr(router, {"service": "checkout-service"})

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "No incident-window pull request" in str(exc.value)
    assert clients.github.requested_pull_request == 999
    assert clients.github.pull_request_kwargs == {"state": "closed", "per_page": 20}


def test_live_github_pr_handler_rejects_invalid_explicit_pr_before_network():
    clients = _FakePrCorrelationClients(commits=[], pull_requests=[])
    router = LiveToolRouter(clients)

    with pytest.raises(ToolExecutionError) as exc:
        _github_pr(router, {"pr": "not-a-number"})

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "positive integer" in str(exc.value)
    assert clients.github.commit_kwargs is None
    assert clients.github.pull_request_kwargs is None
    assert clients.github.requested_pull_request is None


def test_live_github_commit_handler_honors_incident_time_window():
    clients = _FakeTimeWindowClients()
    router = LiveToolRouter(clients)

    result = _github_commits(
        router,
        {
            "service": "checkout-service",
            "path": "checkout/payment.py",
            "time_window": "2024-01-15T02:42:00Z",
            "time_window_end": "2024-01-15T03:27:00Z",
        },
    )

    assert result["commits"] == [{"sha": "windowed"}]
    assert clients.github.commit_kwargs == {
        "path": "checkout/payment.py",
        "since": "2024-01-15T02:42:00Z",
        "until": "2024-01-15T03:27:00Z",
    }


def test_live_github_deployment_handler_honors_incident_time_window():
    clients = _FakeTimeWindowClients()
    router = LiveToolRouter(clients)

    result = _github_deployments(
        router,
        {
            "service": "checkout-service",
            "time_window": "2024-01-15T02:42:00Z",
            "time_window_end": "2024-01-15T03:27:00Z",
        },
    )

    assert result["deployments"] == [{"sha": "deploy-windowed"}]
    assert clients.github.deployment_kwargs == {
        "since": "2024-01-15T02:42:00Z",
        "until": "2024-01-15T03:27:00Z",
    }


def test_live_repository_payload_carries_collected_ref_and_pull_request():
    state = InvestigationState(
        incident_id="PD-LIVE",
        scenario_name="live",
        affected_services=["checkout-service"],
        service_priority=["checkout-service"],
    )
    state.artifacts.update(
        {
            "repo_window": "2024-01-15T02:42:00Z",
            "repo_window_end": "2024-01-15T03:27:00Z",
            "deployment_ref": "sha-deploy",
            "commit_sha": "sha-commit",
            "pull_request": 456,
        }
    )

    payload = repository_payload(state, "checkout-service")

    assert payload == {
        "service": "checkout-service",
        "time_window": "2024-01-15T02:42:00Z",
        "time_window_end": "2024-01-15T03:27:00Z",
        "ref": "sha-deploy",
        "pull_request": 456,
    }


def test_live_github_status_handler_infers_incident_window_commit_when_ref_missing():
    clients = _FakeStatusClients(commits=[{"sha": "sha-window"}])
    router = LiveToolRouter(clients)

    result = _github_status(
        router,
        {
            "service": "checkout-service",
            "time_window": "2024-01-15T02:42:00Z",
            "time_window_end": "2024-01-15T03:27:00Z",
        },
    )

    assert result["ref"] == "sha-window"
    assert result["ref_source"] == "incident_window_commit"
    assert result["status"] == {"sha": "sha-window", "state": "success"}
    assert result["check_runs"] == {"total_count": 1, "check_runs": [{"name": "tests"}]}
    assert clients.github.commit_kwargs == {
        "per_page": 1,
        "since": "2024-01-15T02:42:00Z",
        "until": "2024-01-15T03:27:00Z",
    }
    assert clients.github.requested_statuses == ["sha-window"]
    assert clients.github.requested_check_runs == ["sha-window"]


def test_live_github_status_handler_uses_explicit_sha_for_status_and_checks():
    clients = _FakeStatusClients()
    router = LiveToolRouter(clients)

    result = _github_status(router, {"sha": "sha-live"})

    assert result == {
        "ref": "sha-live",
        "ref_source": "payload",
        "status": {"sha": "sha-live", "state": "success"},
        "check_runs": {"total_count": 1, "check_runs": [{"name": "tests"}]},
    }
    assert clients.github.requested_statuses == ["sha-live"]
    assert clients.github.requested_check_runs == ["sha-live"]


def test_live_github_content_handler_falls_back_across_real_repo_candidates():
    clients = _FakeContentsClients(
        {
            "deployment.yml": ToolExecutionError(ToolErrorKind.PERMANENT, "github request failed 404: not found"),
            "deployment.yaml": {"name": "deployment.yaml", "sha": "sha-deploy"},
        }
    )
    router = LiveToolRouter(clients)

    handler = _github_contents(["deployment.yml", "deployment.yaml", "Dockerfile"])
    result = handler(router, {"service": "checkout-service", "ref": "main"})

    assert result == {
        "path": "deployment.yaml",
        "content": {"name": "deployment.yaml", "sha": "sha-deploy"},
    }
    assert clients.github.requested == [
        ("deployment.yml", "main"),
        ("deployment.yaml", "main"),
    ]


def test_live_github_content_handler_keeps_explicit_paths_strict():
    clients = _FakeContentsClients(
        {
            "custom/deploy.yaml": ToolExecutionError(
                ToolErrorKind.PERMANENT,
                "github request failed 404: not found",
            ),
            "deployment.yaml": {"name": "deployment.yaml", "sha": "sha-deploy"},
        }
    )
    router = LiveToolRouter(clients)

    handler = _github_contents(["deployment.yml", "deployment.yaml"])

    with pytest.raises(ToolExecutionError) as exc:
        handler(router, {"path": "custom/deploy.yaml", "ref": "main"})

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert clients.github.requested == [("custom/deploy.yaml", "main")]


def test_live_github_content_handler_surfaces_non_missing_provider_errors():
    clients = _FakeContentsClients(
        {
            "deployment.yml": ToolExecutionError(
                ToolErrorKind.RATE_LIMITED,
                "github rate limited",
                retryable=True,
            ),
            "deployment.yaml": {"name": "deployment.yaml", "sha": "sha-deploy"},
        }
    )
    router = LiveToolRouter(clients)

    handler = _github_contents(["deployment.yml", "deployment.yaml"])

    with pytest.raises(ToolExecutionError) as exc:
        handler(router, {})

    assert exc.value.kind == ToolErrorKind.RATE_LIMITED
    assert clients.github.requested == [("deployment.yml", None)]


def test_live_feature_flags_return_not_configured_when_no_candidate_file_exists():
    clients = _FakeContentsClients({})
    router = LiveToolRouter(clients)

    result = LIVE_TOOL_HANDLERS["repo.get_feature_flags"](router, {"service": "checkout-service", "ref": "main"})

    assert result["provider"] == "github"
    assert result["path"] is None
    assert result["content"] is None
    assert result["configured"] is False
    assert result["absent_kind"] == "feature_flags_not_configured"
    assert ("feature-flags.yml", "main") in clients.github.requested
    assert (".launchdarkly.json", "main") in clients.github.requested


def test_live_github_blame_handler_infers_path_from_correlated_pr_files():
    clients = _FakePrCorrelationClients(
        commits=[{"sha": "sha-window", "commit": {"message": "Merge pull request #456 from checkout/fix"}}],
        pull_requests=[],
        pull_request_commits={456: [{"sha": "sha-window", "commit": {"message": "Deploy checkout fix"}}]},
    )
    router = LiveToolRouter(clients)

    result = _github_blame(
        router,
        {
            "service": "checkout-service",
            "time_window": "2024-01-15T02:42:00Z",
            "time_window_end": "2024-01-15T03:27:00Z",
        },
    )

    assert result["path"] == "checkout/payment.py"
    assert result["path_source"] == "pull_request_files"
    assert result["commits"] == [{"sha": "sha-window", "commit": {"message": "Merge pull request #456 from checkout/fix"}}]
    assert clients.github.requested_pull_request == 456


def test_live_github_blame_handler_queries_commits_for_explicit_file_path():
    clients = _FakeTimeWindowClients()
    router = LiveToolRouter(clients)

    result = _github_blame(
        router,
        {
            "service": "checkout-service",
            "file": "checkout/payment.py",
            "line": "84",
            "time_window": "2024-01-15T02:42:00Z",
            "time_window_end": "2024-01-15T03:27:00Z",
        },
    )

    assert result["path"] == "checkout/payment.py"
    assert result["line"] == 84
    assert result["blame_source"] == "github_commits_for_path"
    assert result["path_source"] == "payload"
    assert result["commits"] == [{"sha": "windowed"}]
    assert clients.github.commit_kwargs == {
        "path": "checkout/payment.py",
        "per_page": 5,
        "since": "2024-01-15T02:42:00Z",
        "until": "2024-01-15T03:27:00Z",
    }


def test_live_github_blame_handler_rejects_invalid_line_payload():
    router = LiveToolRouter(_FakeTimeWindowClients())

    try:
        _github_blame(router, {"path": "checkout/payment.py", "line": "zero"})
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.PERMANENT
        assert exc.retryable is False
        assert "line to be a positive integer" in str(exc)
    else:
        raise AssertionError("expected invalid blame line to fail closed")


def test_live_deployment_timestamp_filter_keeps_only_incident_window_items():
    assert _created_within(
        {"created_at": "2024-01-15T03:00:00Z"},
        since="2024-01-15T02:42:00Z",
        until="2024-01-15T03:27:00Z",
    )
    assert not _created_within(
        {"created_at": "2024-01-15T01:00:00Z"},
        since="2024-01-15T02:42:00Z",
        until="2024-01-15T03:27:00Z",
    )


def test_live_dashboard_handler_requires_explicit_dashboard_id():
    clients = _FakeDashboardClients()
    router = LiveToolRouter(clients)

    try:
        _dashboard(router, {"service": "checkout-service"})
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.PERMANENT
        assert exc.retryable is False
        assert "requires an explicit dashboard_id" in str(exc)
    else:
        raise AssertionError("expected dashboard lookup without dashboard_id to fail closed")

    assert clients.datadog.requested_dashboard is None


def test_live_dashboard_handler_uses_explicit_dashboard_id():
    clients = _FakeDashboardClients()
    router = LiveToolRouter(clients)

    result = _dashboard(router, {"dashboard_id": "dash-payments-overview"})

    assert result == {"id": "dash-payments-overview", "title": "Payments overview", "provider": "datadog"}
    assert clients.datadog.requested_dashboard == "dash-payments-overview"


@pytest.mark.parametrize(
    "tool_name",
    [
        "observe.fetch_service_logs",
        "observe.query_metrics_range",
        "observe.get_distributed_traces",
        "observe.check_pod_health",
        "observe.get_error_rate_timeseries",
        "observe.fetch_apm_data",
        "observe.read_queue_depth",
        "observe.check_db_slow_queries",
        "observe.get_network_latency",
        "observe.fetch_cdn_logs",
        "observe.read_flame_graph",
        "observe.check_uptime_history",
        "observe.get_memory_cpu_usage",
        "observe.fetch_alerting_rules",
        "repo.get_rollback_targets",
    ],
)
def test_live_service_scoped_read_handlers_require_explicit_service_before_provider_call(tool_name):
    clients = _NoNetworkClients()
    router = LiveToolRouter(clients)

    with pytest.raises(ToolExecutionError) as exc:
        LIVE_TOOL_HANDLERS[tool_name](router, {})

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "requires an explicit service or affected_service" in str(exc.value)
    assert clients.provider_calls == []


def test_live_service_scoped_read_handlers_accept_affected_service_payload():
    clients = _RecordingDatadogClients()
    router = LiveToolRouter(clients)

    result = _logs(
        router,
        {
            "affected_service": "checkout-service",
            "time_window": "2024-01-15T02:42:00Z",
            "time_window_end": "2024-01-15T03:27:00Z",
        },
    )

    assert result["events"] == [{"id": "log-1"}]
    assert clients.datadog.searches == [
        (
            "service:checkout-service",
            "2024-01-15T02:42:00Z",
            "2024-01-15T03:27:00Z",
        )
    ]


def test_generic_alert_client_uses_shared_reliability_envelope():
    backend = InMemoryRateLimitBackend()
    rate_limiter = SharedRateLimiter(backend, limit=1, window_seconds=60)
    circuit_breaker = CircuitBreaker("generic_webhook", failure_threshold=1)
    client = GenericAlertClient(
        SimpleNamespace(approver_id="eng-oncall"),
        rate_limiter=rate_limiter,
        circuit_breaker=circuit_breaker,
    )

    result = client.on_call_context("FREE-1")

    assert result["provider"] == "generic_webhook"
    assert result["incident"]["id"] == "FREE-1"
    assert result["oncalls"][0]["user"]["id"] == "eng-oncall"
    with pytest.raises(ToolExecutionError) as exc:
        client.on_call_context("FREE-2")
    assert exc.value.kind == ToolErrorKind.RATE_LIMITED
    assert exc.value.retryable is True
    assert circuit_breaker.state.value == "closed"


def test_live_slack_channel_artifact_routes_later_comms_payloads():
    orchestrator = SentinelOrchestrator()
    state = InvestigationState(
        incident_id="PD-LIVE",
        scenario_name="live",
        affected_services=["checkout-service"],
        service_priority=["checkout-service"],
    )

    orchestrator._collect_artifacts_from_result(
        state,
        {"channel": {"id": "C-live-incident", "name": "inc-pd-live-checkout"}},
    )
    payload = orchestrator._comms_payload(
        state,
        "checkout-service",
        {"message": "SENTINEL is investigating."},
    )

    assert state.artifacts["slack_channel_id"] == "C-live-incident"
    assert state.artifacts["slack_channel_name"] == "inc-pd-live-checkout"
    assert payload["channel"] == "C-live-incident"


def test_live_slack_channel_handler_requires_explicit_channel_name():
    router = LiveToolRouter(_FakeSlackClients())

    try:
        _slack_channel(router, {"service": "checkout-service"})
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.PERMANENT
        assert exc.retryable is False
        assert "requires an explicit channel_name" in str(exc)
    else:
        raise AssertionError("expected missing channel_name to fail closed")


def test_live_slack_channel_handler_creates_explicit_channel_name():
    clients = _FakeSlackClients()
    router = LiveToolRouter(clients)

    result = _slack_channel(router, {"channel_name": "inc-pd-live-checkout"})

    assert result == {"channel": {"id": "C-live", "name": "inc-pd-live-checkout"}}
    assert clients.slack.channels == ["inc-pd-live-checkout"]


def test_live_slack_channel_handler_returns_discord_channel_receipt_when_slack_is_disabled():
    router = LiveToolRouter(_FakeDiscordFallbackClients())

    result = _slack_channel(router, {"channel_name": "inc-free-alert-checkout"})

    assert result == {
        "provider": "discord",
        "channel": {"id": "discord-webhook", "name": "inc-free-alert-checkout"},
        "created": False,
        "reused": True,
    }


def test_live_pagerduty_oncall_handler_includes_incident_when_id_is_present():
    clients = _FakePagerDutyClients()
    router = LiveToolRouter(clients)

    result = _pagerduty_oncall(router, {"incident_id": "PD-LIVE-123"})

    assert result["incident"]["id"] == "PD-LIVE-123"
    assert result["incident"]["status"] == "triggered"
    assert result["oncalls"] == [{"user": {"id": "U-oncall"}}]
    assert result["escalation_policy_ids"] == ["EP-live"]
    assert result["oncall_scope"] == "incident_escalation_policy"
    assert clients.pagerduty.requested_incident == "PD-LIVE-123"
    assert clients.pagerduty.requested_oncall_policy_ids == ["EP-live"]


def test_live_pagerduty_oncall_handler_does_not_broaden_when_incident_policy_has_no_oncall():
    clients = _FakePagerDutyClients(
        policy_oncalls={("EP-empty",): []},
        incident_policy_id="EP-empty",
    )
    router = LiveToolRouter(clients)

    result = _pagerduty_oncall(router, {"incident_id": "PD-LIVE-123"})

    assert result["escalation_policy_ids"] == ["EP-empty"]
    assert result["oncall_scope"] == "incident_escalation_policy"
    assert result["oncalls"] == []
    assert clients.pagerduty.requested_oncall_policy_ids == ["EP-empty"]


def test_live_pagerduty_oncall_empty_incident_policy_yields_empty_live_evidence():
    clients = _FakePagerDutyClients(
        policy_oncalls={("EP-empty",): []},
        incident_policy_id="EP-empty",
    )
    router = LiveToolRouter(clients)

    result = _pagerduty_oncall(router, {"incident_id": "PD-LIVE-123", "service": "checkout-service"})
    evidence = _evidence_from_live_result(
        "comms.page_oncall_engineer",
        {"incident_id": "PD-LIVE-123", "service": "checkout-service"},
        result,
    )

    assert evidence[0].provenance == "live_empty::comms.page_oncall_engineer"
    assert "no provider-confirming records" in evidence[0].claim


def test_live_pagerduty_oncall_handler_does_not_use_account_oncall_without_incident_policy():
    clients = _FakePagerDutyClients(incident_policy_id=None)
    router = LiveToolRouter(clients)

    result = _pagerduty_oncall(router, {"incident_id": "PD-LIVE-123"})

    assert result["escalation_policy_ids"] == []
    assert result["oncall_scope"] == "unconfirmed_incident_escalation_policy"
    assert result["oncalls"] == []
    assert clients.pagerduty.requested_oncall_policy_ids is None


def test_live_pagerduty_oncall_unconfirmed_incident_policy_yields_empty_live_evidence():
    clients = _FakePagerDutyClients(incident_policy_id=None)
    router = LiveToolRouter(clients)

    result = _pagerduty_oncall(router, {"incident_id": "PD-LIVE-123", "service": "checkout-service"})
    evidence = _evidence_from_live_result(
        "comms.page_oncall_engineer",
        {"incident_id": "PD-LIVE-123", "service": "checkout-service"},
        result,
    )

    assert evidence[0].provenance == "live_empty::comms.page_oncall_engineer"
    assert "no provider-confirming records" in evidence[0].claim


def test_live_pagerduty_oncall_confirmed_incident_policy_yields_live_evidence():
    clients = _FakePagerDutyClients()
    router = LiveToolRouter(clients)

    result = _pagerduty_oncall(router, {"incident_id": "PD-LIVE-123", "service": "checkout-service"})
    evidence = _evidence_from_live_result(
        "comms.page_oncall_engineer",
        {"incident_id": "PD-LIVE-123", "service": "checkout-service"},
        result,
    )

    assert evidence[0].provenance == "live::comms.page_oncall_engineer"
    assert "observed 1 provider item" in evidence[0].claim


def test_loki_live_evidence_counts_log_entries_not_streams():
    evidence = _evidence_from_live_result(
        "observe.fetch_service_logs",
        {"service": "checkout-service"},
        {
            "provider": "loki",
            "events": [
                {
                    "stream": {"service": "checkout-service"},
                    "values": [
                        ["1717425600000000000", "first checkout log"],
                        ["1717425601000000000", "second checkout log"],
                    ],
                }
            ],
            "streams": [
                {
                    "stream": {"service": "checkout-service"},
                    "values": [
                        ["1717425600000000000", "first checkout log"],
                        ["1717425601000000000", "second checkout log"],
                    ],
                }
            ],
        },
    )

    assert evidence[0].provenance == "live::observe.fetch_service_logs"
    assert "observed 2 provider item" in evidence[0].claim


def test_loki_empty_streams_yield_empty_live_evidence():
    evidence = _evidence_from_live_result(
        "observe.fetch_service_logs",
        {"service": "checkout-service"},
        {
            "provider": "loki",
            "events": [{"stream": {"service": "checkout-service"}, "values": []}],
            "streams": [{"stream": {"service": "checkout-service"}, "values": []}],
        },
    )

    assert evidence[0].provenance == "live_empty::observe.fetch_service_logs"
    assert "no provider-confirming records" in evidence[0].claim


def test_live_pagerduty_close_handler_requires_explicit_incident_id():
    router = LiveToolRouter(_FakePagerDutyClients())

    try:
        _pagerduty_close(router, {"requester_email": "oncall@example.com"})
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.PERMANENT
        assert exc.retryable is False
        assert "requires an explicit incident_id" in str(exc)
    else:
        raise AssertionError("expected close incident without incident_id to fail closed")


def test_live_pagerduty_close_handler_trims_explicit_incident_id():
    clients = _FakePagerDutyClients()
    router = LiveToolRouter(clients)

    result = _pagerduty_close(
        router,
        {"incident_id": " PD-LIVE-123 ", "requester_email": "oncall@example.com"},
    )

    assert result["incident"]["id"] == "PD-LIVE-123"
    assert result["incident"]["status"] == "resolved"
    assert clients.pagerduty.updated_incident == ("PD-LIVE-123", "resolved", "oncall@example.com")


def test_live_pagerduty_artifacts_are_collected_from_context_result():
    orchestrator = SentinelOrchestrator()
    state = InvestigationState(
        incident_id="PD-LIVE",
        scenario_name="live",
        affected_services=["checkout-service"],
        service_priority=["checkout-service"],
    )

    orchestrator._collect_artifacts_from_result(
        state,
        {
            "incident": {
                "id": "PD-LIVE",
                "status": "triggered",
                "urgency": "high",
                "html_url": "https://example.pagerduty.com/incidents/PD-LIVE",
            },
            "escalation_policy_ids": ["EP-live"],
            "oncall_scope": "incident_escalation_policy",
            "oncalls": [{"user": {"id": "U-oncall", "summary": "On Call"}}],
        },
    )

    assert state.artifacts["pagerduty_incident_status"] == "triggered"
    assert state.artifacts["pagerduty_incident_urgency"] == "high"
    assert state.artifacts["pagerduty_incident_url"].endswith("/PD-LIVE")
    assert state.artifacts["pagerduty_escalation_policy_ids"] == ["EP-live"]
    assert state.artifacts["pagerduty_oncall_scope"] == "incident_escalation_policy"
    assert state.artifacts["pagerduty_oncall_user"] == "U-oncall"


def test_live_account_scoped_pagerduty_oncalls_do_not_authorize_remediation():
    orchestrator = SentinelOrchestrator()
    state = InvestigationState(
        incident_id="PD-LIVE",
        scenario_name="live",
        affected_services=["checkout-service"],
        service_priority=["checkout-service"],
    )

    orchestrator._collect_artifacts_from_result(
        state,
        {
            "oncall_scope": "account",
            "oncalls": [{"user": {"id": "U-account-oncall"}}],
        },
    )

    assert state.artifacts["pagerduty_oncall_scope"] == "account"
    assert "pagerduty_oncall_user" not in state.artifacts


def test_live_pagerduty_oncall_summary_without_user_id_does_not_authorize_remediation():
    orchestrator = SentinelOrchestrator()
    state = InvestigationState(
        incident_id="PD-LIVE",
        scenario_name="live",
        affected_services=["checkout-service"],
        service_priority=["checkout-service"],
    )

    orchestrator._collect_artifacts_from_result(
        state,
        {
            "oncall_scope": "incident_escalation_policy",
            "oncalls": [{"user": {"summary": "On Call"}}],
        },
    )

    assert state.artifacts["pagerduty_oncall_scope"] == "incident_escalation_policy"
    assert "pagerduty_oncall_user" not in state.artifacts


def test_live_paged_user_shortcut_does_not_authorize_remediation():
    orchestrator = SentinelOrchestrator()
    state = InvestigationState(
        incident_id="PD-LIVE",
        scenario_name="live",
        affected_services=["checkout-service"],
        service_priority=["checkout-service"],
    )

    orchestrator._collect_artifacts_from_result(
        state,
        {"paged_user": "legacy-shortcut"},
    )

    assert "pagerduty_oncall_user" not in state.artifacts


def test_live_slack_post_handler_requires_explicit_message_payload():
    router = LiveToolRouter(_FakeSlackClients())

    try:
        _slack_post(router, {"channel": "C-live"})
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.PERMANENT
        assert exc.retryable is False
        assert "requires an explicit message or text" in str(exc)
    else:
        raise AssertionError("expected missing Slack message payload to fail closed")


def test_live_slack_post_handler_sends_explicit_text_payload():
    clients = _FakeSlackClients()
    router = LiveToolRouter(clients)

    result = _slack_post(router, {"text": " SENTINEL is investigating. ", "channel": "C-live"})

    assert result == {
        "provider": "slack",
        "channel": "C-live",
        "ts": "1717425600.000100",
        "text": "SENTINEL is investigating.",
    }
    assert clients.slack.posts == [("SENTINEL is investigating.", "C-live")]


def test_live_slack_post_handler_falls_back_to_discord_webhook():
    clients = _FakeDiscordFallbackClients()
    router = LiveToolRouter(clients)

    result = _slack_post(router, {"message": " SENTINEL is investigating. "})

    assert result == {
        "ok": True,
        "provider": "discord",
        "content": "SENTINEL is investigating.",
        "id": "discord-message-id",
    }
    assert clients.discord.posts == ["SENTINEL is investigating."]


def test_discord_live_evidence_requires_confirmed_message_id():
    evidence = _evidence_from_live_result(
        "comms.post_to_slack",
        {"service": "checkout-service"},
        {
            "provider": "discord",
            "content": "SENTINEL is investigating.",
        },
    )

    assert evidence[0].provenance == "live_empty::comms.post_to_slack"
    assert "no provider-confirming records" in evidence[0].claim


def test_discord_live_evidence_counts_confirmed_message_id():
    evidence = _evidence_from_live_result(
        "comms.post_to_slack",
        {"service": "checkout-service"},
        {
            "provider": "discord",
            "id": "discord-message-id",
            "content": "SENTINEL is investigating.",
        },
    )

    assert evidence[0].provenance == "live::comms.post_to_slack"
    assert "observed 1 provider item" in evidence[0].claim


def test_live_slack_post_handler_fails_closed_when_slack_and_discord_are_missing():
    router = LiveToolRouter(_DiscordMissingClients())

    with pytest.raises(ToolExecutionError) as exc:
        _slack_post(router, {"message": "SENTINEL is investigating."})

    assert exc.value.kind == ToolErrorKind.AUTHORIZATION
    assert exc.value.retryable is False
    assert "SLACK_BOT_TOKEN is missing and DISCORD_WEBHOOK_URL is not configured" in str(exc.value)


def test_live_status_page_update_is_out_of_scope_for_v1_without_slack_fallback():
    clients = _FakeSlackClients()
    router = LiveToolRouter(clients)

    with pytest.raises(ToolExecutionError) as exc:
        LIVE_TOOL_HANDLERS["comms.update_status_page"](
            router,
            {"service": "checkout-service", "message": "Customer-facing update"},
        )

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert exc.value.retryable is False
    assert "out of scope" in str(exc.value)
    assert "external customer communication" in str(exc.value)
    assert clients.slack.posts == []


@pytest.mark.parametrize(
    "tool_name",
    [
        "infra.restart_service",
        "infra.scale_replicas",
        "infra.toggle_feature_flag",
        "infra.flush_cache",
        "infra.update_rate_limit",
        "infra.drain_node",
        "infra.redeploy_service",
        "infra.modify_env_config",
        "infra.open_circuit_breaker",
        "infra.run_migration",
        "comms.close_incident",
    ],
)
def test_live_non_rollback_mutations_are_out_of_scope_for_v1(tool_name):
    router = LiveToolRouter(object())

    with pytest.raises(ToolExecutionError) as exc:
        LIVE_TOOL_HANDLERS[tool_name](router, {"service": "checkout-service"})

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert exc.value.retryable is False
    assert "out of scope" in str(exc.value)


def test_live_add_database_index_executes_supported_sqlite_index(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINEL_SLOW_QUERY_DB_PATH", str(tmp_path / "slow-query.db"))
    monkeypatch.setenv("SENTINEL_PUSH_SLOW_QUERY_LOGS_TO_LOKI", "false")
    router = LiveToolRouter(object())

    result = LIVE_TOOL_HANDLERS["infra.add_database_index"](
        router,
        {"service": "payment-service", "table": "orders", "column": "user_id"},
    )

    assert result["provider"] == "sqlite"
    assert result["status"] == "executed"
    assert result["verified"] is True
    assert result["index"] == "idx_orders_user_id"
    assert result["verification_query"]["index_present"] is True


def test_live_add_database_index_rejects_unscoped_index_target(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINEL_SLOW_QUERY_DB_PATH", str(tmp_path / "slow-query.db"))
    router = LiveToolRouter(object())

    with pytest.raises(ToolExecutionError) as exc:
        LIVE_TOOL_HANDLERS["infra.add_database_index"](
            router,
            {"service": "payment-service", "table": "customers", "column": "email"},
        )

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "only orders.user_id" in str(exc.value)


def test_live_slack_schedule_handler_requires_explicit_message_and_post_at():
    router = LiveToolRouter(_FakeSlackClients())

    try:
        _slack_schedule(router, {"message": "SENTINEL retrospective", "channel": "C-live"})
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.PERMANENT
        assert exc.retryable is False
        assert "explicit positive integer post_at" in str(exc)
    else:
        raise AssertionError("expected missing Slack post_at payload to fail closed")

    try:
        _slack_schedule(router, {"post_at": 1717429200, "channel": "C-live"})
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.PERMANENT
        assert exc.retryable is False
        assert "requires an explicit message or text" in str(exc)
    else:
        raise AssertionError("expected missing scheduled Slack message payload to fail closed")


def test_live_slack_schedule_handler_sends_explicit_message_and_post_at():
    clients = _FakeSlackClients()
    router = LiveToolRouter(clients)

    result = _slack_schedule(
        router,
        {"message": "SENTINEL retrospective", "post_at": "1717429200", "channel": "C-live"},
    )

    assert result == {
        "channel": "C-live",
        "scheduled_message_id": "Q1298393284",
        "post_at": 1717429200,
        "text": "SENTINEL retrospective",
    }
    assert clients.slack.schedules == [("SENTINEL retrospective", 1717429200, "C-live")]


def test_simulated_slack_channel_artifact_is_preserved_without_overwrite():
    orchestrator = SentinelOrchestrator()
    state = InvestigationState(
        incident_id="PD-SIM",
        scenario_name="golden_path",
        affected_services=["payment-service"],
        service_priority=["payment-service"],
    )

    orchestrator._collect_artifacts_from_result(state, {"channel": "#inc-payment"})
    orchestrator._collect_artifacts_from_result(state, {"channel": "#default-channel"})

    assert state.artifacts["slack_channel_id"] == "#inc-payment"


def test_live_recommendation_without_known_target_is_not_executable():
    orchestrator = SentinelOrchestrator()
    state = InvestigationState(
        incident_id="PD-LIVE",
        scenario_name="live",
        affected_services=["checkout-service"],
        service_priority=["checkout-service"],
    )

    recommendation = orchestrator._build_recommendation(state)

    assert recommendation.command == "collect Kubernetes rollout revision target for checkout-service before rollback"
    assert recommendation.executable is False
    assert "revision target" in recommendation.risk
    assert "v2.3.1" not in recommendation.command
    assert "847" not in recommendation.command


def test_live_recommendation_with_non_executable_live_rollback_target_is_not_executable():
    orchestrator = SentinelOrchestrator()
    state = InvestigationState(
        incident_id="PD-LIVE",
        scenario_name="live",
        affected_services=["checkout-service"],
        service_priority=["checkout-service"],
        remediation_readiness_report=RemediationReadinessReport(
            safe_rollback_target="release-2026-06-02",
            blockers=[],
            evidence=[],
            isolated_context_id="ctx-live",
            scoped_tool_names=["repo.get_rollback_targets"],
        ),
    )

    recommendation = orchestrator._build_recommendation(state)

    assert recommendation.command == "collect Kubernetes rollout revision target for checkout-service before rollback"
    assert recommendation.executable is False
    assert "release-2026-06-02" not in recommendation.command


def test_live_recommendation_uses_kubernetes_revision_target_when_available():
    orchestrator = SentinelOrchestrator()
    state = InvestigationState(
        incident_id="PD-LIVE",
        scenario_name="live",
        affected_services=["checkout-service"],
        service_priority=["checkout-service"],
        remediation_readiness_report=RemediationReadinessReport(
            safe_rollback_target="revision:12",
            blockers=[],
            evidence=[],
            isolated_context_id="ctx-live",
            scoped_tool_names=["repo.get_rollback_targets"],
        ),
    )

    recommendation = orchestrator._build_recommendation(state)

    assert recommendation.command == "rollback checkout-service to revision:12"
    assert recommendation.executable is True


def test_live_artifact_collection_separates_deploy_ref_from_executable_rollback_target():
    orchestrator = SentinelOrchestrator()
    state = InvestigationState(
        incident_id="PD-LIVE",
        scenario_name="live",
        affected_services=["checkout-service"],
        service_priority=["checkout-service"],
    )

    orchestrator._collect_artifacts_from_result(
        state,
        {
            "deployments": [
                {
                    "sha": "sha-new",
                    "ref": "main",
                    "environment": "production",
                    "statuses": [{"state": "success", "environment": "production"}],
                },
                {
                    "sha": "sha-old",
                    "ref": "release-2026-06-02",
                    "latest_status": {"state": "inactive"},
                },
            ],
            "commits": [
                {"sha": "sha-new", "commit": {"message": "Merge pull request #912 from checkout/fix"}}
            ],
            "pull_request": {
                "number": 912,
                "title": "Fix checkout latency",
                "head": {"sha": "sha-pr"},
            },
            "files": [{"filename": "checkout/payment.py"}],
        },
    )

    assert state.artifacts["pull_request"] == 912
    assert state.artifacts["pull_request_title"] == "Fix checkout latency"
    assert state.artifacts["changed_file"] == "checkout/payment.py"
    assert state.artifacts["latest_deployment_status"] == "success"
    assert state.artifacts["latest_deployment_environment"] == "production"
    assert state.artifacts["previous_deployment_status"] == "inactive"
    assert state.artifacts["previous_deployment_ref"] == "release-2026-06-02"
    assert "rollback_target" not in state.artifacts
    assert state.artifacts["commit_sha"] == "sha-new"


def test_live_deployment_artifacts_do_not_persist_raw_provider_payloads():
    orchestrator = SentinelOrchestrator()
    state = InvestigationState(
        incident_id="PD-LIVE",
        scenario_name="live",
        affected_services=["checkout-service"],
        service_priority=["checkout-service"],
    )

    orchestrator._collect_artifacts_from_result(
        state,
        {
            "deployments": [
                {
                    "id": 10,
                    "sha": "sha-new",
                    "ref": "main",
                    "environment": "production",
                    "payload": {
                        "kubernetes_revision": 42,
                        "raw_change_notes": "internal rollout notes",
                        "secret": "do-not-persist",
                    },
                    "statuses": [
                        {
                            "state": "success",
                            "environment": "production",
                            "creator": {"login": "deploy-bot"},
                        }
                    ],
                },
                {
                    "id": 9,
                    "sha": "sha-old",
                    "ref": "release-2026-06-02",
                    "payload": {
                        "kubernetes_revision": 41,
                        "secret": "old-secret",
                    },
                }
            ],
        },
    )

    assert state.artifacts["latest_deployment"] == {
        "id": 10,
        "sha": "sha-new",
        "ref": "main",
        "environment": "production",
        "latest_status": "success",
        "rollout_target": "revision:42",
    }
    assert state.artifacts["previous_deployment"] == {
        "id": 9,
        "sha": "sha-old",
        "ref": "release-2026-06-02",
        "rollout_target": "revision:41",
    }
    assert state.artifacts["rollback_target"] == "revision:41"
    assert "payload" not in state.artifacts["latest_deployment"]
    assert "statuses" not in state.artifacts["latest_deployment"]
    assert "do-not-persist" not in str(state.artifacts)
    assert "old-secret" not in str(state.artifacts)


def test_live_artifact_collection_extracts_kubernetes_revision_target():
    orchestrator = SentinelOrchestrator()
    state = InvestigationState(
        incident_id="PD-LIVE",
        scenario_name="live",
        affected_services=["checkout-service"],
        service_priority=["checkout-service"],
    )

    orchestrator._collect_artifacts_from_result(
        state,
        {
            "target": "revision:18",
            "rollout": {
                "current_revision": "revision:19",
                "previous_revision": "revision:18",
            },
        },
    )

    assert state.artifacts["current_rollout_revision"] == "revision:19"
    assert state.artifacts["rollback_target"] == "revision:18"


def test_live_rollback_targets_come_from_kubernetes_rollout_revisions():
    router = LiveToolRouter(_FakeRollbackClients())

    result = _rollback_targets(router, {"service": "checkout-service"})

    assert result["target"] == "revision:41"
    assert result["target_source"] == "kubernetes_rollout_revision"
    assert result["rollout"]["current_revision"] == "revision:42"
    assert result["deployments"] == [{"sha": "sha-new", "ref": "main"}]


def test_kubernetes_rollout_revision_helpers_parse_deployment_selector_and_revisions():
    deployment = {
        "metadata": {"name": "checkout-service", "uid": "deploy-uid"},
        "spec": {"selector": {"matchLabels": {"app": "checkout", "tier": "api"}}},
    }
    replica_sets = [
        {
            "metadata": {
                "name": "checkout-rs-2",
                "annotations": {"deployment.kubernetes.io/revision": "2"},
                "ownerReferences": [
                    {"kind": "Deployment", "name": "checkout-service", "uid": "deploy-uid", "controller": True}
                ],
            }
        },
        {
            "metadata": {
                "name": "checkout-rs-1",
                "annotations": {"deployment.kubernetes.io/revision": "1"},
                "ownerReferences": [
                    {"kind": "Deployment", "name": "checkout-service", "uid": "deploy-uid", "controller": True}
                ],
            }
        },
        {
            "metadata": {
                "name": "checkout-rs-bad",
                "annotations": {"deployment.kubernetes.io/revision": "not-a-number"},
                "ownerReferences": [
                    {"kind": "Deployment", "name": "checkout-service", "uid": "deploy-uid", "controller": True}
                ],
            }
        },
        {
            "metadata": {
                "name": "other-rs-99",
                "annotations": {"deployment.kubernetes.io/revision": "99"},
                "ownerReferences": [
                    {"kind": "Deployment", "name": "other-service", "uid": "other-uid", "controller": True}
                ],
            }
        },
    ]

    assert _deployment_selector(deployment) == "app=checkout,tier=api"
    owned = _replica_sets_owned_by(deployment, replica_sets)
    assert [item["metadata"]["name"] for item in owned] == ["checkout-rs-2", "checkout-rs-1", "checkout-rs-bad"]
    assert _replica_set_revisions(owned) == [1, 2]


def test_kubernetes_replica_set_lookup_filters_unowned_selector_matches():
    client = _MalformedReplicaSetKubernetesClient(
        {
            "items": [
                {
                    "metadata": {
                        "name": "checkout-owned-41",
                        "annotations": {"deployment.kubernetes.io/revision": "41"},
                        "ownerReferences": [{"kind": "Deployment", "name": "checkout-service", "controller": True}],
                    }
                },
                {
                    "metadata": {
                        "name": "checkout-unowned-99",
                        "annotations": {"deployment.kubernetes.io/revision": "99"},
                        "ownerReferences": [{"kind": "Deployment", "name": "other-service", "controller": True}],
                    }
                },
                {
                    "metadata": {
                        "name": "checkout-no-owner-100",
                        "annotations": {"deployment.kubernetes.io/revision": "100"},
                    }
                },
            ]
        }
    )

    result = client.rollout_revisions("checkout-service")

    assert [item["metadata"]["name"] for item in result["replica_sets"]] == ["checkout-owned-41"]
    assert result["revisions"] == [41]
    assert result["current_revision"] == "revision:41"
    assert result["previous_revision"] is None


def test_kubernetes_replica_set_lookup_requires_controller_owner_and_matching_uid():
    deployment = {
        "metadata": {"name": "checkout-service", "uid": "deploy-uid"},
        "spec": {"selector": {"matchLabels": {"app": "checkout"}}},
    }
    replica_sets = [
        {
            "metadata": {
                "name": "checkout-controller-41",
                "ownerReferences": [
                    {"kind": "Deployment", "name": "checkout-service", "uid": "deploy-uid", "controller": True}
                ],
            }
        },
        {
            "metadata": {
                "name": "checkout-missing-uid-42",
                "ownerReferences": [{"kind": "Deployment", "name": "checkout-service", "controller": True}],
            }
        },
        {
            "metadata": {
                "name": "checkout-non-controller-43",
                "ownerReferences": [
                    {"kind": "Deployment", "name": "checkout-service", "uid": "deploy-uid", "controller": False}
                ],
            }
        },
        {
            "metadata": {
                "name": "checkout-wrong-uid-44",
                "ownerReferences": [
                    {"kind": "Deployment", "name": "checkout-service", "uid": "other-uid", "controller": True}
                ],
            }
        },
    ]

    owned = _replica_sets_owned_by(deployment, replica_sets)

    assert [item["metadata"]["name"] for item in owned] == ["checkout-controller-41"]


def test_kubernetes_pod_lookup_falls_back_to_deployment_selector():
    client = _RecordingKubernetesClient(
        app_label_pods=[],
        selector_pods=[{"metadata": {"name": "checkout-abc"}}],
    )

    result = client.list_pods("checkout-service")

    assert result["items"] == [{"metadata": {"name": "checkout-abc"}}]
    assert client.commands == [
        ["get", "pods", "-n", "prod", "-l", "app=checkout-service", "-o", "json"],
        ["get", "deployment", "checkout-service", "-n", "prod", "-o", "json"],
        ["get", "pods", "-n", "prod", "-l", "app.kubernetes.io/name=checkout,tier=api", "-o", "json"],
    ]


def test_kubernetes_pod_lookup_keeps_common_app_label_fast_path():
    client = _RecordingKubernetesClient(
        app_label_pods=[{"metadata": {"name": "checkout-fast"}}],
        selector_pods=[{"metadata": {"name": "checkout-selector"}}],
    )

    result = client.list_pods("checkout-service")

    assert result["items"] == [{"metadata": {"name": "checkout-fast"}}]
    assert client.commands == [
        ["get", "pods", "-n", "prod", "-l", "app=checkout-service", "-o", "json"],
    ]


def test_kubernetes_client_rejects_flag_like_service_before_kubectl():
    client = _RecordingKubernetesClient(app_label_pods=[], selector_pods=[])

    with pytest.raises(ToolExecutionError) as exc:
        client.list_pods("--all-namespaces")

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "Kubernetes service/deployment" in str(exc.value)
    assert client.commands == []


def test_kubernetes_pod_lookup_rejects_malformed_pod_list_without_fallback():
    client = _MalformedKubernetesListClient({"items": {"metadata": {"name": "not-a-list"}}})

    with pytest.raises(ToolExecutionError) as exc:
        client.list_pods("checkout-service")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "pods" in str(exc.value)
    assert client.commands == [
        ["get", "pods", "-n", "prod", "-l", "app=checkout-service", "-o", "json"],
    ]


def test_kubernetes_pod_lookup_rejects_non_object_pod_items_without_fallback():
    client = _MalformedKubernetesListClient({"items": ["not-a-pod"]})

    with pytest.raises(ToolExecutionError) as exc:
        client.list_pods("checkout-service")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "pods.items[0]" in str(exc.value)
    assert client.commands == [
        ["get", "pods", "-n", "prod", "-l", "app=checkout-service", "-o", "json"],
    ]


def test_kubernetes_pod_lookup_requires_pod_metadata_name_without_fallback():
    client = _MalformedKubernetesListClient({"items": [{"metadata": {}}]})

    with pytest.raises(ToolExecutionError) as exc:
        client.list_pods("checkout-service")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "items[0].metadata.name" in str(exc.value)
    assert client.commands == [
        ["get", "pods", "-n", "prod", "-l", "app=checkout-service", "-o", "json"],
    ]


def test_kubernetes_list_deployments_rejects_malformed_items_field():
    client = _MalformedKubernetesListClient({"items": {"metadata": {"name": "not-a-list"}}})

    with pytest.raises(ToolExecutionError) as exc:
        client.list_deployments()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "deployments" in str(exc.value)


def test_kubernetes_list_deployments_requires_item_metadata_name():
    client = _MalformedKubernetesListClient({"items": [{"kind": "Deployment", "metadata": {}}]})

    with pytest.raises(ToolExecutionError) as exc:
        client.list_deployments()

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "items[0].metadata.name" in str(exc.value)


def test_kubernetes_deployment_read_requires_target_name_confirmation():
    client = _MalformedDeploymentReadKubernetesClient(
        {"kind": "Deployment", "metadata": {"name": "other-service"}}
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.deployment("checkout-service")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "metadata.name=other-service" in str(exc.value)


def test_kubernetes_replica_set_lookup_rejects_malformed_items_field():
    client = _MalformedReplicaSetKubernetesClient()

    with pytest.raises(ToolExecutionError) as exc:
        client.replica_sets_for_deployment("checkout-service")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "replicasets" in str(exc.value)


def test_kubernetes_replica_set_lookup_requires_item_metadata_name():
    client = _MalformedReplicaSetKubernetesClient({"items": [{"metadata": {}}]})

    with pytest.raises(ToolExecutionError) as exc:
        client.replica_sets_for_deployment("checkout-service")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "items[0].metadata.name" in str(exc.value)


def test_kubernetes_deployment_selector_rejects_selector_injection_characters():
    deployment = {
        "metadata": {"name": "checkout-service"},
        "spec": {"selector": {"matchLabels": {"app": "checkout,app=other"}}},
    }

    with pytest.raises(ToolExecutionError) as exc:
        _deployment_selector(deployment)

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "selector" in str(exc.value)


def test_kubernetes_client_rejects_invalid_namespace_on_init():
    settings = replace(
        SentinelSettings.from_env(),
        kubeconfig=__file__,
        kubernetes_namespace="--all-namespaces",
    )

    with pytest.raises(ToolExecutionError) as exc:
        KubernetesClient(settings)

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "Kubernetes namespace" in str(exc.value)


def test_kubernetes_client_normalizes_kubectl_timeout_as_retryable(monkeypatch):
    settings = replace(
        SentinelSettings.from_env(),
        kubeconfig=__file__,
        kubernetes_namespace="prod",
        kubectl_timeout_seconds=0.01,
    )
    client = KubernetesClient(settings)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs["timeout"])

    monkeypatch.setattr("sentinel.live_clients.subprocess.run", timeout)

    with pytest.raises(ToolExecutionError) as exc:
        client.list_deployments()

    assert exc.value.kind == ToolErrorKind.RETRYABLE
    assert exc.value.retryable is True
    assert "kubectl timed out after 0.01s" in str(exc.value)


def test_kubernetes_client_applies_rate_limiter_before_kubectl_subprocess(monkeypatch):
    settings = replace(
        SentinelSettings.from_env(),
        kubeconfig=__file__,
        kubernetes_namespace="prod",
    )
    client = KubernetesClient(
        settings,
        SharedRateLimiter(InMemoryRateLimitBackend(), limit=0, window_seconds=60),
        CircuitBreaker(name="kubernetes-test", failure_threshold=1),
    )
    subprocess_calls = []

    def run(*args, **kwargs):
        subprocess_calls.append((args, kwargs))
        raise AssertionError("kubectl subprocess should not run after rate limit rejection")

    monkeypatch.setattr("sentinel.live_clients.subprocess.run", run)

    with pytest.raises(ToolExecutionError) as exc:
        client.list_deployments()

    assert exc.value.kind == ToolErrorKind.RATE_LIMITED
    assert exc.value.retryable is True
    assert subprocess_calls == []
    assert client.circuit_breaker.state.value == "closed"


def test_kubernetes_client_redacts_sensitive_timeout_command_payload(monkeypatch):
    settings = replace(
        SentinelSettings.from_env(),
        kubeconfig=__file__,
        kubernetes_namespace="prod",
        kubectl_timeout_seconds=0.01,
    )
    client = KubernetesClient(settings)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs["timeout"])

    monkeypatch.setattr("sentinel.live_clients.subprocess.run", timeout)

    with pytest.raises(ToolExecutionError) as exc:
        client.patch_deployment(
            "checkout-service",
            {"spec": {"template": {"metadata": {"annotations": {"password": "db-secret"}}}}},
        )

    message = str(exc.value)
    assert exc.value.kind == ToolErrorKind.RETRYABLE
    assert "db-secret" not in message
    assert "[redacted]" in message


def test_kubernetes_client_redacts_sensitive_failure_stderr(monkeypatch):
    settings = replace(
        SentinelSettings.from_env(),
        kubeconfig=__file__,
        kubernetes_namespace="prod",
    )
    client = KubernetesClient(settings)

    def fail(*args, **kwargs):
        return subprocess.CompletedProcess(
            args[0],
            1,
            stdout="",
            stderr="authentication failed token=token-secret password=db-secret",
        )

    monkeypatch.setattr("sentinel.live_clients.subprocess.run", fail)

    with pytest.raises(ToolExecutionError) as exc:
        client.list_deployments()

    message = str(exc.value)
    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "token-secret" not in message
    assert "db-secret" not in message
    assert "[redacted]" in message


def test_kubernetes_client_normalizes_api_server_connectivity_failure_as_retryable(monkeypatch):
    settings = replace(
        SentinelSettings.from_env(),
        kubeconfig=__file__,
        kubernetes_namespace="prod",
    )
    client = KubernetesClient(settings)

    def fail(*args, **kwargs):
        return subprocess.CompletedProcess(
            args[0],
            1,
            stdout="",
            stderr="Unable to connect to the server: dial tcp 10.0.0.1:443: connection refused",
        )

    monkeypatch.setattr("sentinel.live_clients.subprocess.run", fail)

    with pytest.raises(ToolExecutionError) as exc:
        client.list_deployments()

    assert exc.value.kind == ToolErrorKind.RETRYABLE
    assert exc.value.retryable is True
    assert exc.value.circuit_breaker_failure is True


def test_kubernetes_client_normalizes_api_server_throttling_as_rate_limited(monkeypatch):
    settings = replace(
        SentinelSettings.from_env(),
        kubeconfig=__file__,
        kubernetes_namespace="prod",
    )
    client = KubernetesClient(settings)

    def fail(*args, **kwargs):
        return subprocess.CompletedProcess(
            args[0],
            1,
            stdout="",
            stderr="Error from server (TooManyRequests): client rate limit exceeded",
        )

    monkeypatch.setattr("sentinel.live_clients.subprocess.run", fail)

    with pytest.raises(ToolExecutionError) as exc:
        client.list_deployments()

    assert exc.value.kind == ToolErrorKind.RATE_LIMITED
    assert exc.value.retryable is True
    assert exc.value.circuit_breaker_failure is False


def test_kubernetes_client_normalizes_rbac_failures_as_authorization(monkeypatch):
    settings = replace(
        SentinelSettings.from_env(),
        kubeconfig=__file__,
        kubernetes_namespace="prod",
    )
    client = KubernetesClient(settings)

    def fail(*args, **kwargs):
        return subprocess.CompletedProcess(
            args[0],
            1,
            stdout="",
            stderr='Error from server (Forbidden): deployments.apps is forbidden: User "sentinel" cannot list resource "deployments"',
        )

    monkeypatch.setattr("sentinel.live_clients.subprocess.run", fail)

    with pytest.raises(ToolExecutionError) as exc:
        client.list_deployments()

    assert exc.value.kind == ToolErrorKind.AUTHORIZATION
    assert exc.value.retryable is False
    assert exc.value.circuit_breaker_failure is False


def test_kubernetes_rollout_undo_waits_for_rollout_status_before_success():
    client = _RecordingRolloutKubernetesClient()

    result = client.rollout_undo("checkout-service", target="revision:41")

    assert result["verified"] is True
    assert result["target"] == "revision:41"
    assert result["revision"] == 41
    assert result["undo"]["output"] == "deployment.apps/checkout-service rolled back"
    assert result["rollout_status"]["output"] == 'deployment "checkout-service" successfully rolled out'
    assert client.commands == [
        ["rollout", "undo", "deployment/checkout-service", "-n", "prod", "--to-revision=41"],
        ["rollout", "status", "deployment/checkout-service", "-n", "prod", "--timeout=20s"],
    ]


def test_kubernetes_rollout_undo_requires_explicit_revision_before_kubectl():
    client = _RecordingRolloutKubernetesClient()

    with pytest.raises(ToolExecutionError) as exc:
        client.rollout_undo("checkout-service")

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "revision:<positive integer>" in str(exc.value)
    assert client.commands == []


def test_kubernetes_rollout_undo_rejects_invalid_revision_before_kubectl():
    client = _RecordingRolloutKubernetesClient()

    with pytest.raises(ToolExecutionError) as exc:
        client.rollout_undo("checkout-service", target="revision:--force")

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "revision:<positive integer>" in str(exc.value)
    assert client.commands == []


def test_kubernetes_rollout_undo_fails_if_rollout_status_does_not_complete():
    client = _RecordingRolloutKubernetesClient(status_fails=True)

    with pytest.raises(ToolExecutionError) as exc:
        client.rollout_undo("checkout-service", target="revision:41")

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "rollout status failed" in str(exc.value)
    assert client.commands == [
        ["rollout", "undo", "deployment/checkout-service", "-n", "prod", "--to-revision=41"],
        ["rollout", "status", "deployment/checkout-service", "-n", "prod", "--timeout=20s"],
    ]


def test_kubernetes_rollout_restart_waits_for_status_before_success():
    client = _RecordingMutationKubernetesClient()

    result = client.rollout_restart("checkout-service")

    assert result["verified"] is True
    assert result["restart"]["output"] == "deployment.apps/checkout-service restarted"
    assert result["rollout_status"]["output"] == 'deployment "checkout-service" successfully rolled out'
    assert result["deployment"]["spec"]["template"]["metadata"]["annotations"]["kubectl.kubernetes.io/restartedAt"]
    assert client.commands == [
        ["rollout", "restart", "deployment/checkout-service", "-n", "prod"],
        ["rollout", "status", "deployment/checkout-service", "-n", "prod", "--timeout=20s"],
        ["get", "deployment", "checkout-service", "-n", "prod", "-o", "json"],
    ]


def test_kubernetes_rollout_restart_rejects_unconfirmed_restart_receipt():
    client = _RecordingMutationKubernetesClient(restart_output="deployment.apps/other-service restarted")

    with pytest.raises(ToolExecutionError) as exc:
        client.rollout_restart("checkout-service")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "rollout restart" in str(exc.value)
    assert client.commands == [
        ["rollout", "restart", "deployment/checkout-service", "-n", "prod"],
    ]


def test_kubernetes_rollout_restart_rejects_missing_restart_annotation_readback():
    client = _RecordingMutationKubernetesClient(restart_annotation=None)

    with pytest.raises(ToolExecutionError) as exc:
        client.rollout_restart("checkout-service")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "kubectl.kubernetes.io/restartedAt" in str(exc.value)


def test_kubernetes_scale_reads_back_requested_replica_count():
    client = _RecordingMutationKubernetesClient(replicas=3)

    result = client.scale("checkout-service", 3)

    assert result["verified"] is True
    assert result["deployment"]["metadata"]["name"] == "checkout-service"
    assert result["deployment"]["spec"]["replicas"] == 3
    assert result["deployment"]["status"]["observedGeneration"] == result["deployment"]["metadata"]["generation"]
    assert client.commands == [
        ["scale", "deployment/checkout-service", "-n", "prod", "--replicas=3"],
        ["get", "deployment", "checkout-service", "-n", "prod", "-o", "json"],
    ]


@pytest.mark.parametrize("replicas", [-1, True, "3"])
def test_kubernetes_scale_rejects_invalid_replicas_before_kubectl(replicas):
    client = _RecordingMutationKubernetesClient(replicas=3)

    with pytest.raises(ToolExecutionError) as exc:
        client.scale("checkout-service", replicas)

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "non-negative integer replicas value" in str(exc.value)
    assert client.commands == []


def test_kubernetes_scale_rejects_mismatched_replica_readback():
    client = _RecordingMutationKubernetesClient(replicas=2)

    with pytest.raises(ToolExecutionError) as exc:
        client.scale("checkout-service", 3)

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "expected 3, observed 2" in str(exc.value)


def test_kubernetes_scale_rejects_unobserved_generation_readback():
    client = _RecordingMutationKubernetesClient(replicas=3, generation=8, observed_generation=7)

    with pytest.raises(ToolExecutionError) as exc:
        client.scale("checkout-service", 3)

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "status.observedGeneration" in str(exc.value)


def test_kubernetes_patch_reads_back_target_deployment():
    client = _RecordingMutationKubernetesClient()
    patch = {"spec": {"template": {"metadata": {"annotations": {"sentinel/restarted": "yes"}}}}}

    result = client.patch_deployment("checkout-service", patch)

    assert result["verified"] is True
    assert result["deployment"]["metadata"]["name"] == "checkout-service"
    assert result["deployment"]["spec"]["template"]["metadata"]["annotations"]["sentinel/restarted"] == "yes"
    assert client.commands == [
        [
            "patch",
            "deployment",
            "checkout-service",
            "-n",
            "prod",
            "--type=merge",
            "-p",
            json.dumps(patch),
        ],
        ["get", "deployment", "checkout-service", "-n", "prod", "-o", "json"],
    ]


def test_kubernetes_patch_rejects_missing_patch_field_readback():
    client = _RecordingMutationKubernetesClient(
        patch_readback={"spec": {"template": {"metadata": {"annotations": {"other": "yes"}}}}}
    )
    patch = {"spec": {"template": {"metadata": {"annotations": {"sentinel/restarted": "yes"}}}}}

    with pytest.raises(ToolExecutionError) as exc:
        client.patch_deployment("checkout-service", patch)

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "spec.template.metadata.annotations.sentinel/restarted" in str(exc.value)


def test_kubernetes_create_job_reads_back_created_job():
    client = _RecordingMutationKubernetesClient()
    command = ["redis-cli", "-n", "2", "FLUSHDB"]

    result = client.create_job("sentinel-flush-cache-checkout-service", command)

    assert result["verified"] is True
    assert result["job"]["metadata"]["name"] == "sentinel-flush-cache-checkout-service"
    assert result["job"]["spec"]["template"]["spec"]["containers"][0]["command"] == command
    assert client.commands == [
        ["apply", "-f", "-"],
        ["get", "job", "sentinel-flush-cache-checkout-service", "-n", "prod", "-o", "json"],
    ]
    manifest = json.loads(client.input_texts[0])
    assert manifest["metadata"] == {"name": "sentinel-flush-cache-checkout-service", "namespace": "prod"}
    assert manifest["spec"]["template"]["spec"]["containers"][0]["command"] == command


def test_kubernetes_create_job_rejects_mismatched_job_readback():
    client = _RecordingMutationKubernetesClient(job_readback_name="other-job")

    with pytest.raises(ToolExecutionError) as exc:
        client.create_job("sentinel-flush-cache-checkout-service", ["true"])

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "metadata.name=other-job" in str(exc.value)


def test_kubernetes_create_job_rejects_mismatched_command_readback():
    client = _RecordingMutationKubernetesClient(job_readback_command=["redis-cli", "PING"])

    with pytest.raises(ToolExecutionError) as exc:
        client.create_job("sentinel-flush-cache-checkout-service", ["redis-cli", "FLUSHDB"])

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "spec.template.spec.containers[0].command" in str(exc.value)
    assert "FLUSHDB" not in str(exc.value)


def test_kubernetes_create_job_rejects_invalid_job_name_before_kubectl():
    client = _RecordingMutationKubernetesClient()

    with pytest.raises(ToolExecutionError) as exc:
        client.create_job("--force", ["true"])

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "Kubernetes job" in str(exc.value)
    assert client.commands == []


def test_kubernetes_drain_node_requires_node_name_before_kubectl():
    client = _RecordingMutationKubernetesClient()

    with pytest.raises(ToolExecutionError) as exc:
        client.drain_node("")

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "node name" in str(exc.value)
    assert client.commands == []


def test_kubernetes_drain_node_rejects_flag_like_node_before_kubectl():
    client = _RecordingMutationKubernetesClient()

    with pytest.raises(ToolExecutionError) as exc:
        client.drain_node("--force")

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert "Kubernetes node name" in str(exc.value)
    assert client.commands == []


def test_kubernetes_drain_node_requires_confirmed_drain_receipt():
    client = _RecordingMutationKubernetesClient(drain_output="node/ip-10-0-0-2 drained")

    with pytest.raises(ToolExecutionError) as exc:
        client.drain_node("ip-10-0-0-1")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "drain node" in str(exc.value)
    assert client.commands == [
        ["drain", "ip-10-0-0-1", "--ignore-daemonsets", "--delete-emptydir-data"],
    ]


def test_kubernetes_drain_node_returns_verified_receipt():
    client = _RecordingMutationKubernetesClient(drain_output="node/ip-10-0-0-1 drained")

    result = client.drain_node("ip-10-0-0-1")

    assert result["drain"] == {"output": "node/ip-10-0-0-1 drained"}
    assert result["node"] == "ip-10-0-0-1"
    assert result["node_readback"]["spec"]["unschedulable"] is True
    assert result["verified"] is True
    assert client.commands == [
        ["drain", "ip-10-0-0-1", "--ignore-daemonsets", "--delete-emptydir-data"],
        ["get", "node", "ip-10-0-0-1", "-o", "json"],
    ]


def test_kubernetes_drain_node_rejects_schedulable_node_readback():
    client = _RecordingMutationKubernetesClient(
        drain_output="node/ip-10-0-0-1 drained",
        node_unschedulable=False,
    )

    with pytest.raises(ToolExecutionError) as exc:
        client.drain_node("ip-10-0-0-1")

    assert exc.value.kind == ToolErrorKind.MALFORMED_OUTPUT
    assert "spec.unschedulable" in str(exc.value)


def test_live_kubernetes_drain_handler_requires_explicit_node_payload():
    router = LiveToolRouter(_FakeMutatingClients())

    try:
        _k8s_drain(router, {"service": "checkout-service"})
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.PERMANENT
        assert exc.retryable is False
        assert "explicit Kubernetes node" in str(exc)
    else:
        raise AssertionError("expected missing node payload to fail closed")


def test_live_kubernetes_drain_handler_trims_explicit_node_payload():
    clients = _FakeMutatingClients()
    router = LiveToolRouter(clients)

    result = _k8s_drain(router, {"node_name": " ip-10-0-0-1 "})

    assert result == {"drained": True, "node": "ip-10-0-0-1"}
    assert clients.kubernetes.drains == ["ip-10-0-0-1"]


@pytest.mark.parametrize(
    ("handler", "payload"),
    [
        (_k8s_rollback, {"target": "revision:41"}),
        (_k8s_restart, {}),
        (_k8s_scale, {"replicas": 3}),
        (_k8s_patch("toggle-feature-flag"), {"patch": {"metadata": {"annotations": {"flag": "off"}}}}),
        (_k8s_job("flush-cache"), {"command": ["redis-cli", "FLUSHDB"]}),
    ],
)
def test_live_kubernetes_mutation_handlers_require_explicit_service_payload(handler, payload):
    router = LiveToolRouter(_FakeMutatingClients())

    try:
        handler(router, payload)
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.PERMANENT
        assert exc.retryable is False
        assert "requires an explicit service or affected_service" in str(exc)
    else:
        raise AssertionError("expected missing mutation service payload to fail closed")


@pytest.mark.parametrize("target", [None, "", "release-2026-06-02", "revision:0", "revision:--force"])
def test_live_rollback_handler_requires_explicit_kubernetes_revision_target(target):
    router = LiveToolRouter(_FakeMutatingClients())
    payload = {"service": "checkout-service"}
    if target is not None:
        payload["target"] = target

    with pytest.raises(ToolExecutionError) as exc:
        _k8s_rollback(router, payload)

    assert exc.value.kind == ToolErrorKind.PERMANENT
    assert exc.value.retryable is False
    assert "revision:<positive integer>" in str(exc.value)


def test_live_kubernetes_mutation_handlers_accept_affected_service_payload():
    clients = _FakeMutatingClients()
    router = LiveToolRouter(clients)
    patch = {"spec": {"template": {"metadata": {"annotations": {"feature.checkout": "disabled"}}}}}

    result = _k8s_patch("toggle-feature-flag")(router, {"affected_service": "checkout-service", "patch": patch})

    assert result == {"patched": True, "service": "checkout-service", "patch": patch}
    assert clients.kubernetes.patches == [("checkout-service", patch)]


def test_live_kubernetes_mutation_handlers_reject_unknown_service_target():
    router = LiveToolRouter(_FakeMutatingClients())
    patch = {"spec": {"template": {"metadata": {"annotations": {"feature.checkout": "disabled"}}}}}

    try:
        _k8s_patch("toggle-feature-flag")(router, {"service": "unknown-service", "patch": patch})
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.PERMANENT
        assert exc.retryable is False
        assert "requires an explicit service or affected_service" in str(exc)
    else:
        raise AssertionError("expected unknown-service mutation target to fail closed")


def test_live_kubernetes_scale_handler_requires_explicit_replicas_payload():
    router = LiveToolRouter(_FakeMutatingClients())

    try:
        _k8s_scale(router, {"service": "checkout-service"})
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.PERMANENT
        assert exc.retryable is False
        assert "explicit non-negative integer replicas value" in str(exc)
    else:
        raise AssertionError("expected missing replicas payload to fail closed")


def test_live_kubernetes_scale_handler_accepts_explicit_replicas_payload():
    clients = _FakeMutatingClients()
    router = LiveToolRouter(clients)

    result = _k8s_scale(router, {"service": "checkout-service", "replicas": "3"})

    assert result == {"scaled": True, "service": "checkout-service", "replicas": 3}
    assert clients.kubernetes.scales == [("checkout-service", 3)]


def test_live_kubernetes_patch_handlers_require_explicit_patch_payload():
    router = LiveToolRouter(_FakeMutatingClients())
    handler = _k8s_patch("toggle-feature-flag")

    try:
        handler(router, {"service": "checkout-service"})
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.PERMANENT
        assert exc.retryable is False
        assert "explicit non-empty Kubernetes patch payload" in str(exc)
    else:
        raise AssertionError("expected missing patch payload to fail closed")


def test_live_kubernetes_patch_handlers_apply_explicit_patch_payload():
    clients = _FakeMutatingClients()
    router = LiveToolRouter(clients)
    patch = {"spec": {"template": {"metadata": {"annotations": {"feature.checkout": "disabled"}}}}}

    result = _k8s_patch("toggle-feature-flag")(router, {"service": "checkout-service", "patch": patch})

    assert result == {"patched": True, "service": "checkout-service", "patch": patch}
    assert clients.kubernetes.patches == [("checkout-service", patch)]


def test_live_kubernetes_job_handlers_require_explicit_command_payload():
    router = LiveToolRouter(_FakeMutatingClients())
    handler = _k8s_job("flush-cache")

    try:
        handler(router, {"service": "checkout-service"})
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.PERMANENT
        assert exc.retryable is False
        assert "explicit Kubernetes job command list" in str(exc)
    else:
        raise AssertionError("expected missing job command to fail closed")


def test_live_kubernetes_job_handlers_run_explicit_command_payload():
    clients = _FakeMutatingClients()
    router = LiveToolRouter(clients)
    command = ["redis-cli", "-n", "2", "FLUSHDB"]

    result = _k8s_job("flush-cache")(router, {"service": "checkout-service", "command": command})

    assert result == {
        "job": "sentinel-flush-cache-checkout-service",
        "command": command,
    }
    assert clients.kubernetes.jobs == [("sentinel-flush-cache-checkout-service", command)]


def test_live_github_issue_handler_requires_explicit_title_and_body():
    router = LiveToolRouter(_FakeIssueClients())

    try:
        _github_issue(router, {"service": "checkout-service", "body": "Investigate checkout latency."})
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.PERMANENT
        assert exc.retryable is False
        assert "requires an explicit title" in str(exc)
    else:
        raise AssertionError("expected missing GitHub issue title to fail closed")

    try:
        _github_issue(router, {"service": "checkout-service", "title": "Follow-up"})
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.PERMANENT
        assert exc.retryable is False
        assert "requires an explicit body" in str(exc)
    else:
        raise AssertionError("expected missing GitHub issue body to fail closed")


def test_live_github_issue_handler_creates_explicit_followup_issue():
    clients = _FakeIssueClients()
    router = LiveToolRouter(clients)

    result = _github_issue(
        router,
        {
            "title": "SENTINEL follow-up: PD-LIVE checkout-service",
            "body": "Investigate checkout latency.",
            "labels": ["sentinel", "incident"],
        },
    )

    assert result == {"number": 42, "html_url": "https://github.example/issues/42"}
    assert clients.github.issues == [
        (
            "SENTINEL follow-up: PD-LIVE checkout-service",
            "Investigate checkout latency.",
            ["sentinel", "incident"],
        )
    ]


def test_live_github_issue_handler_dry_runs_when_github_writes_disabled():
    clients = _FakeIssueClients(write_enabled=False)
    router = LiveToolRouter(clients)

    result = _github_issue(
        router,
        {
            "title": "SENTINEL follow-up: PD-LIVE checkout-service",
            "body": "Investigate checkout latency.",
            "labels": ["sentinel", "incident"],
        },
    )

    assert result == {
        "provider": "github",
        "action": "create_issue",
        "write_enabled": False,
        "write_skipped": True,
        "reason": "SENTINEL_GITHUB_WRITE_ENABLED is not true",
        "title": "SENTINEL follow-up: PD-LIVE checkout-service",
        "labels": ["sentinel", "incident"],
    }
    assert clients.github.issues == []


def test_live_github_issue_dry_run_yields_empty_live_evidence():
    clients = _FakeIssueClients(write_enabled=False)
    router = LiveToolRouter(clients)

    result = _github_issue(
        router,
        {
            "service": "checkout-service",
            "title": "SENTINEL follow-up: PD-LIVE checkout-service",
            "body": "Investigate checkout latency.",
            "labels": ["sentinel", "incident"],
        },
    )
    evidence = _evidence_from_live_result(
        "comms.create_jira_ticket",
        {"service": "checkout-service"},
        result,
    )

    assert evidence[0].provenance == "live_empty::comms.create_jira_ticket"
    assert "no provider-confirming records" in evidence[0].claim


def test_live_runbook_update_requires_explicit_note_content():
    clients = _FakeRunbookClients("Existing runbook\n")
    router = LiveToolRouter(clients)

    try:
        _github_runbook(router, {"path": "docs/RUNBOOK.md"})
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.PERMANENT
        assert "requires an explicit body" in str(exc)
    else:
        raise AssertionError("expected missing runbook note to fail closed")
    assert clients.github.updated == []


def test_live_runbook_update_appends_to_existing_github_file():
    clients = _FakeRunbookClients("Existing runbook\n")
    router = LiveToolRouter(clients)

    result = _github_runbook(
        router,
        {
            "path": "docs/RUNBOOK.md",
            "content": "## SENTINEL update\nInvestigated checkout latency.",
        },
    )

    assert result["updated"] is True
    assert clients.github.requested_path == "docs/RUNBOOK.md"
    assert clients.github.updated == [
        {
            "path": "docs/RUNBOOK.md",
            "message": "SENTINEL runbook update",
            "content": "Existing runbook\n\n## SENTINEL update\nInvestigated checkout latency.\n",
            "sha": "sha-runbook",
        }
    ]


def test_live_runbook_update_dry_runs_when_github_writes_disabled():
    clients = _FakeRunbookClients("Existing runbook\n", write_enabled=False)
    router = LiveToolRouter(clients)

    result = _github_runbook(
        router,
        {
            "path": "docs/RUNBOOK.md",
            "content": "## SENTINEL update\nInvestigated checkout latency.",
        },
    )

    assert result == {
        "provider": "github",
        "action": "update_runbook",
        "write_enabled": False,
        "write_skipped": True,
        "reason": "SENTINEL_GITHUB_WRITE_ENABLED is not true",
        "path": "docs/RUNBOOK.md",
    }
    assert clients.github.requested_path is None
    assert clients.github.updated == []


def test_live_runbook_update_dry_run_yields_empty_live_evidence():
    clients = _FakeRunbookClients("Existing runbook\n", write_enabled=False)
    router = LiveToolRouter(clients)

    result = _github_runbook(
        router,
        {
            "service": "checkout-service",
            "path": "docs/RUNBOOK.md",
            "content": "## SENTINEL update\nInvestigated checkout latency.",
        },
    )
    evidence = _evidence_from_live_result(
        "comms.update_runbook",
        {"service": "checkout-service"},
        result,
    )

    assert evidence[0].provenance == "live_empty::comms.update_runbook"
    assert "no provider-confirming records" in evidence[0].claim


def test_live_runbook_update_refuses_non_file_github_content():
    clients = _FakeRunbookClients(
        "not used",
        contents={"type": "dir", "sha": "sha-dir", "content": "", "encoding": "base64"},
    )
    router = LiveToolRouter(clients)

    try:
        _github_runbook(router, {"path": "docs/RUNBOOK.md", "content": "note"})
    except ToolExecutionError as exc:
        assert exc.kind == ToolErrorKind.PERMANENT
        assert "not a file" in str(exc)
    else:
        raise AssertionError("expected runbook directory content to fail closed")
    assert clients.github.updated == []


class _NoNetworkProvider:
    def __init__(self, provider_calls):
        self.provider_calls = provider_calls

    def __getattr__(self, name):
        def _fail(*args, **kwargs):
            self.provider_calls.append(name)
            raise AssertionError(f"{name} should not be called without explicit service")

        return _fail


class _NoNetworkClients:
    def __init__(self):
        self.provider_calls = []
        self.datadog = _NoNetworkProvider(self.provider_calls)
        self.kubernetes = _NoNetworkProvider(self.provider_calls)
        self.github = _NoNetworkProvider(self.provider_calls)


class _RecordingDatadog:
    def __init__(self):
        self.searches = []

    def search_logs(self, query, *, start, end):
        self.searches.append((query, start, end))
        return {"events": [{"id": "log-1"}], "query": query}


class _RecordingDatadogClients:
    def __init__(self):
        self.datadog = _RecordingDatadog()


class _FakeGitHub:
    requested_pull_request = None

    def commits(self, *args, **kwargs):
        return [
            {
                "sha": "abc",
                "commit": {"message": "Merge pull request #231 from example/live-fix"},
            }
        ]

    def pull_requests(self, *args, **kwargs):
        return [{"number": 999}]

    def pull_request(self, number):
        self.__class__.requested_pull_request = number
        return {"number": number, "title": "Live fix", "merge_commit_sha": "abc"}

    def pull_request_files(self, number):
        return [{"filename": "service.py"}]


class _FakeClients:
    github = _FakeGitHub()


class _FakePrCorrelationGitHub:
    def __init__(self, *, commits, pull_requests, pull_request_commits=None):
        self._commits = commits
        self._pull_requests = pull_requests
        self._pull_request_commits = pull_request_commits or {}
        self.commit_kwargs = None
        self.pull_request_kwargs = None
        self.requested_pull_request = None
        self.requested_pull_request_commits = []

    def commits(self, **kwargs):
        self.commit_kwargs = kwargs
        return self._commits

    def pull_requests(self, **kwargs):
        self.pull_request_kwargs = kwargs
        return self._pull_requests

    def pull_request(self, number):
        self.requested_pull_request = number
        return {"number": number, "title": "Correlated live PR"}

    def pull_request_commits(self, number):
        self.requested_pull_request_commits.append(number)
        return self._pull_request_commits.get(number, [])

    def pull_request_files(self, number):
        return [{"filename": "checkout/payment.py"}]


class _FakePrCorrelationClients:
    def __init__(self, *, commits, pull_requests, pull_request_commits=None):
        self.github = _FakePrCorrelationGitHub(
            commits=commits,
            pull_requests=pull_requests,
            pull_request_commits=pull_request_commits,
        )


class _FakeDashboardDatadog:
    def __init__(self):
        self.requested_dashboard = None

    def get_dashboard(self, dashboard_id):
        self.requested_dashboard = dashboard_id
        return {"id": dashboard_id, "title": "Payments overview"}


class _FakeDashboardClients:
    def __init__(self):
        self.datadog = _FakeDashboardDatadog()


class _FakeStatusGitHub:
    def __init__(self, commits=None):
        self._commits = commits if commits is not None else [{"sha": "sha-live-default"}]
        self.commit_kwargs = None
        self.requested_statuses = []
        self.requested_check_runs = []

    def commits(self, **kwargs):
        self.commit_kwargs = kwargs
        return self._commits

    def statuses(self, ref):
        self.requested_statuses.append(ref)
        return {"sha": ref, "state": "success"}

    def check_runs(self, ref):
        self.requested_check_runs.append(ref)
        return {"total_count": 1, "check_runs": [{"name": "tests"}]}


class _FakeStatusClients:
    def __init__(self, commits=None):
        self.github = _FakeStatusGitHub(commits=commits)


class _FakeTimeWindowGitHub:
    def __init__(self):
        self.commit_kwargs = None
        self.deployment_kwargs = None

    def commits(self, **kwargs):
        self.commit_kwargs = kwargs
        return [{"sha": "windowed"}]

    def deployments(self, **kwargs):
        self.deployment_kwargs = kwargs
        return [{"sha": "deploy-windowed"}]


class _FakeTimeWindowClients:
    def __init__(self):
        self.github = _FakeTimeWindowGitHub()


class _FakeContentsGitHub:
    def __init__(self, responses):
        self.responses = responses
        self.requested = []

    def contents(self, path, ref=None):
        self.requested.append((path, ref))
        response = self.responses.get(path)
        if isinstance(response, Exception):
            raise response
        if response is None:
            raise ToolExecutionError(ToolErrorKind.PERMANENT, f"github request failed 404: {path} not found")
        return response


class _FakeContentsClients:
    def __init__(self, responses):
        self.github = _FakeContentsGitHub(responses)


class _FakePagerDuty:
    def __init__(self, *, policy_oncalls=None, incident_policy_id="EP-live"):
        self.policy_oncalls = policy_oncalls or {("EP-live",): [{"user": {"id": "U-oncall"}}]}
        self.incident_policy_id = incident_policy_id
        self.requested_incident = None
        self.updated_incident = None
        self.requested_oncall_policy_ids = None

    def on_calls(self, *, escalation_policy_ids=None):
        self.requested_oncall_policy_ids = escalation_policy_ids
        if escalation_policy_ids:
            return self.policy_oncalls[tuple(escalation_policy_ids)]
        return [{"user": {"id": "U-account-oncall"}}]

    def get_incident(self, incident_id):
        self.requested_incident = incident_id
        incident = {
            "id": incident_id,
            "status": "triggered",
            "urgency": "high",
        }
        if self.incident_policy_id is not None:
            incident["escalation_policy"] = {"id": self.incident_policy_id}
        return {"incident": incident}

    def update_incident_status(self, incident_id, status, requester_email=None):
        self.updated_incident = (incident_id, status, requester_email)
        return {"incident": {"id": incident_id, "status": status}}


class _FakePagerDutyClients:
    def __init__(self, *, policy_oncalls=None, incident_policy_id="EP-live"):
        self.pagerduty = _FakePagerDuty(
            policy_oncalls=policy_oncalls,
            incident_policy_id=incident_policy_id,
        )


class _FakeSlack:
    def __init__(self):
        self.channels = []
        self.posts = []
        self.schedules = []

    def create_channel(self, name):
        self.channels.append(name)
        return {"channel": {"id": "C-live", "name": name}}

    def post_message(self, text, channel=None):
        self.posts.append((text, channel))
        return {"channel": channel, "ts": "1717425600.000100", "text": text}

    def schedule_message(self, text, post_at, channel=None):
        self.schedules.append((text, post_at, channel))
        return {
            "channel": channel,
            "scheduled_message_id": "Q1298393284",
            "post_at": post_at,
            "text": text,
        }


class _FakeSlackClients:
    def __init__(self):
        self.slack = _FakeSlack()


class _DisabledSlack:
    enabled = False


class _FakeDiscord:
    def __init__(self):
        self.posts = []

    def post_to_discord(self, text):
        self.posts.append(text)
        return {
            "ok": True,
            "provider": "discord",
            "content": text,
            "id": "discord-message-id",
        }


class _FakeDiscordFallbackClients:
    def __init__(self):
        self.slack = _DisabledSlack()
        self.discord = _FakeDiscord()


class _DiscordMissingClients:
    def __init__(self):
        self.slack = _DisabledSlack()
        self.discord = None


class _FakeIssueGitHub:
    def __init__(self, *, write_enabled=True):
        self.write_enabled = write_enabled
        self.issues = []

    def create_issue(self, title, body, labels=None):
        self.issues.append((title, body, labels))
        return {"number": 42, "html_url": "https://github.example/issues/42"}


class _FakeIssueClients:
    def __init__(self, *, write_enabled=True):
        self.github = _FakeIssueGitHub(write_enabled=write_enabled)


class _FakeRollbackGitHub:
    def deployments(self, **kwargs):
        return [{"sha": "sha-new", "ref": "main"}]


class _FakeRollbackKubernetes:
    def rollout_revisions(self, service):
        return {
            "service": service,
            "current_revision": "revision:42",
            "previous_revision": "revision:41",
            "revisions": [40, 41, 42],
        }


class _FakeRollbackClients:
    github = _FakeRollbackGitHub()
    kubernetes = _FakeRollbackKubernetes()


class _FakeMutatingKubernetes:
    def __init__(self):
        self.patches = []
        self.jobs = []
        self.drains = []
        self.scales = []

    def patch_deployment(self, service, patch):
        self.patches.append((service, patch))
        return {"patched": True, "service": service, "patch": patch}

    def scale(self, service, replicas):
        self.scales.append((service, replicas))
        return {"scaled": True, "service": service, "replicas": replicas}

    def create_job(self, name, command):
        self.jobs.append((name, command))
        return {"job": name, "command": command}

    def drain_node(self, node):
        self.drains.append(node)
        return {"drained": True, "node": node}


class _FakeMutatingClients:
    def __init__(self):
        self.kubernetes = _FakeMutatingKubernetes()


class _FakeRunbookGitHub:
    def __init__(self, text, *, contents=None, write_enabled=True):
        self.write_enabled = write_enabled
        encoded = base64.b64encode(text.encode()).decode()
        self.contents_result = contents or {
            "type": "file",
            "sha": "sha-runbook",
            "encoding": "base64",
            "content": encoded,
        }
        self.requested_path = None
        self.updated = []

    def contents(self, path):
        self.requested_path = path
        return self.contents_result

    def update_file(self, path, message, content, sha=None):
        self.updated.append(
            {
                "path": path,
                "message": message,
                "content": content,
                "sha": sha,
            }
        )
        return {"updated": True, "content": {"path": path}, "commit": {"sha": "sha-new"}}


class _FakeRunbookClients:
    def __init__(self, text, *, contents=None, write_enabled=True):
        self.github = _FakeRunbookGitHub(text, contents=contents, write_enabled=write_enabled)


class _RecordingKubernetesClient(KubernetesClient):
    def __init__(self, *, app_label_pods, selector_pods):
        self.namespace = "prod"
        self.app_label_pods = app_label_pods
        self.selector_pods = selector_pods
        self.commands = []

    def kubectl(self, args, *, input_text=None):
        self.commands.append(args)
        if args[:2] == ["get", "pods"] and "app=checkout-service" in args:
            return {"items": self.app_label_pods}
        if args[:2] == ["get", "deployment"]:
            return {
                "metadata": {"name": "checkout-service"},
                "spec": {
                    "selector": {
                        "matchLabels": {
                            "app.kubernetes.io/name": "checkout",
                            "tier": "api",
                        }
                    }
                },
            }
        if args[:2] == ["get", "pods"] and "app.kubernetes.io/name=checkout,tier=api" in args:
            return {"items": self.selector_pods}
        raise AssertionError(args)


class _MalformedKubernetesListClient(KubernetesClient):
    def __init__(self, response):
        self.namespace = "prod"
        self.response = response
        self.commands = []

    def kubectl(self, args, *, input_text=None):
        self.commands.append(args)
        if args[:2] == ["get", "pods"] or args[:2] == ["get", "deployments"]:
            return self.response
        if args[:2] == ["get", "deployment"]:
            raise AssertionError("malformed pod response should not fall back to deployment lookup")
        raise AssertionError(args)


class _MalformedDeploymentReadKubernetesClient(KubernetesClient):
    def __init__(self, response):
        self.namespace = "prod"
        self.response = response

    def kubectl(self, args, *, input_text=None):
        if args[:2] == ["get", "deployment"]:
            return self.response
        raise AssertionError(args)


class _MalformedReplicaSetKubernetesClient(KubernetesClient):
    def __init__(self, replica_set_response=None):
        self.namespace = "prod"
        self.replica_set_response = replica_set_response or {"items": {"metadata": {"name": "not-a-list"}}}

    def deployment(self, service):
        return {
            "kind": "Deployment",
            "metadata": {"name": service},
            "spec": {"selector": {"matchLabels": {"app": service}}},
        }

    def kubectl(self, args, *, input_text=None):
        if args[:2] == ["get", "replicasets"]:
            return self.replica_set_response
        raise AssertionError(args)


class _RecordingRolloutKubernetesClient(KubernetesClient):
    def __init__(self, *, status_fails=False):
        self.namespace = "prod"
        self.timeout_seconds = 20
        self.status_fails = status_fails
        self.commands = []

    def kubectl(self, args, *, input_text=None):
        self.commands.append(args)
        if args[:2] == ["rollout", "undo"]:
            return {"output": "deployment.apps/checkout-service rolled back"}
        if args[:2] == ["rollout", "status"]:
            if self.status_fails:
                raise ToolExecutionError(
                    ToolErrorKind.PERMANENT,
                    "rollout status failed: deployment exceeded progress deadline",
                    retryable=False,
                )
            return {"output": 'deployment "checkout-service" successfully rolled out'}
        raise AssertionError(args)


class _RecordingMutationKubernetesClient(KubernetesClient):
    def __init__(
        self,
        *,
        restart_output="deployment.apps/checkout-service restarted",
        restart_annotation="2026-06-05T00:00:00Z",
        replicas=3,
        generation=8,
        observed_generation=None,
        patch_readback=None,
        job_readback_name="sentinel-flush-cache-checkout-service",
        job_readback_command=None,
        drain_output="node/ip-10-0-0-1 drained",
        node_unschedulable=True,
    ):
        self.namespace = "prod"
        self.timeout_seconds = 20
        self.restart_output = restart_output
        self.restart_annotation = restart_annotation
        self.restarted = False
        self.replicas = replicas
        self.generation = generation
        self.observed_generation = observed_generation if observed_generation is not None else generation
        self.patch_readback = patch_readback
        self.applied_patch = {}
        self.job_readback_name = job_readback_name
        self.job_readback_command = job_readback_command
        self.applied_job_manifest = {}
        self.drain_output = drain_output
        self.node_unschedulable = node_unschedulable
        self.commands = []
        self.input_texts = []

    def kubectl(self, args, *, input_text=None):
        self.commands.append(args)
        if input_text is not None:
            self.input_texts.append(input_text)
        if args[:2] == ["rollout", "restart"]:
            self.restarted = True
            return {"output": self.restart_output}
        if args[:2] == ["rollout", "status"]:
            return {"output": 'deployment "checkout-service" successfully rolled out'}
        if args[:1] == ["scale"]:
            return {"output": "deployment.apps/checkout-service scaled"}
        if args[:2] == ["patch", "deployment"]:
            self.applied_patch = json.loads(args[args.index("-p") + 1])
            return {"output": "deployment.apps/checkout-service patched"}
        if args[:2] == ["get", "deployment"]:
            deployment = {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": "checkout-service", "namespace": "prod", "generation": self.generation},
                "spec": {"replicas": self.replicas},
                "status": {"observedGeneration": self.observed_generation},
            }
            if self.restarted and self.restart_annotation is not None:
                deployment = _json_merge(
                    deployment,
                    {
                        "spec": {
                            "template": {
                                "metadata": {
                                    "annotations": {
                                        "kubectl.kubernetes.io/restartedAt": self.restart_annotation
                                    }
                                }
                            }
                        }
                    },
                )
            patch = self.patch_readback if self.patch_readback is not None else self.applied_patch
            return _json_merge(deployment, patch)
        if args[:2] == ["apply", "-f"]:
            self.applied_job_manifest = json.loads(input_text or "{}")
            return {"output": "job.batch/sentinel-flush-cache-checkout-service created"}
        if args[:2] == ["get", "job"]:
            manifest_command = (
                self.applied_job_manifest.get("spec", {})
                .get("template", {})
                .get("spec", {})
                .get("containers", [{}])[0]
                .get("command", [])
            )
            command = self.job_readback_command if self.job_readback_command is not None else manifest_command
            return {
                "apiVersion": "batch/v1",
                "kind": "Job",
                "metadata": {"name": self.job_readback_name, "namespace": "prod"},
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": self.job_readback_name,
                                    "image": "alpine:3.20",
                                    "command": command,
                                }
                            ]
                        }
                    }
                },
            }
        if args[:1] == ["drain"]:
            return {"output": self.drain_output}
        if args[:2] == ["get", "node"]:
            return {
                "apiVersion": "v1",
                "kind": "Node",
                "metadata": {"name": args[2]},
                "spec": {"unschedulable": self.node_unschedulable},
            }
        raise AssertionError(args)


def _json_merge(base, patch):
    result = json.loads(json.dumps(base))
    if not isinstance(patch, dict):
        return patch
    for key, value in patch.items():
        if value is None:
            result.pop(key, None)
        elif isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _json_merge(result[key], value)
        else:
            result[key] = value
    return result
