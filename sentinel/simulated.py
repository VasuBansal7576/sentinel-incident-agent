from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sentinel.errors import ToolErrorKind, ToolExecutionError
from sentinel.models import Evidence, IncidentScenario, ToolContract


TOOL_IMPLEMENTATIONS: dict[str, dict[str, Any]] = {
    "observe.fetch_service_logs": {
        "claim": "{service} logs show slow SELECT * FROM orders WHERE user_id = ? queries and SqlTimeoutError spikes during {window}.",
        "data": {
            "log_count": 1280,
            "error_classes": ["SqlTimeoutError", "CheckoutTimeout"],
            "slow_query": "SELECT * FROM orders WHERE user_id = ?",
            "sample_hash": "logs-pay-847",
        },
    },
    "observe.query_metrics_range": {
        "claim": "{service} payment latency spiked from 4ms baseline to 2.3s p95 during {window}.",
        "data": {
            "baseline_latency_ms": 4,
            "p95_latency_ms": 2300,
            "latency_multiplier": 575,
            "p50_latency_ms": 420,
            "throughput_drop_pct": 28,
        },
    },
    "observe.get_distributed_traces": {
        "claim": "Distributed traces show payment requests spend most time in the orders.user_id lookup.",
        "data": {"trace_count": 94, "dominant_span": "orders.lookup_by_user", "span_duration_ms": 2210},
    },
    "observe.check_pod_health": {
        "claim": "{service} pods are running but readiness probes show elevated latency under traffic.",
        "data": {"ready_pods": 6, "desired_pods": 6, "restart_count": 0, "readiness_p95_ms": 880},
    },
    "observe.get_error_rate_timeseries": {
        "claim": "{service} error rate moved from baseline to incident level during {window}.",
        "data": {"baseline_error_rate": 0.001, "current_error_rate": 0.072, "points": [0.001, 0.003, 0.011, 0.072]},
    },
    "observe.fetch_apm_data": {
        "claim": "APM attributes checkout latency to payment-service database wait time.",
        "data": {"top_component": "database", "db_wait_pct": 81, "endpoint": "POST /checkout/pay"},
    },
    "observe.read_queue_depth": {
        "claim": "Payment authorization queue depth increased as slow orders lookups consumed workers.",
        "data": {"queue": "payment-authorizations", "depth": 1540, "baseline_depth": 80},
    },
    "observe.check_db_slow_queries": {
        "claim": "SELECT * FROM orders WHERE user_id = ? performs sequential scans because orders.user_id has no index; query time moved from 4ms to 2.3s.",
        "data": {
            "query": "SELECT * FROM orders WHERE user_id = ?",
            "before_ms": 4,
            "after_ms": 2300,
            "latency_multiplier": 575,
            "query_plan": "Seq Scan on orders",
            "missing_index": "orders.user_id",
            "suggested_fix": "add_index :orders, :user_id",
        },
    },
    "observe.get_network_latency": {
        "claim": "Network latency between api-gateway and payment-service remained within normal bounds.",
        "data": {"p95_network_ms": 18, "baseline_network_ms": 16, "packet_loss_pct": 0.0},
    },
    "observe.fetch_cdn_logs": {
        "claim": "CDN logs show checkout clients retrying payment submissions after upstream 504s.",
        "data": {"edge_5xx": 320, "retry_header_count": 244, "top_path": "/checkout/pay"},
    },
    "observe.read_flame_graph": {
        "claim": "Flame graph highlights database lookup wait dominating payment-service request time.",
        "data": {"hot_frame": "orders.lookup_by_user", "self_time_pct": 67, "profile_id": "fg-847"},
    },
    "observe.check_uptime_history": {
        "claim": "Uptime history shows 18 minutes of degraded checkout payment authorization.",
        "data": {"affected_users": 18420, "duration_minutes": 18, "availability_pct": 97.1},
    },
    "observe.get_memory_cpu_usage": {
        "claim": "Memory and CPU stayed below saturation, making resource pressure unlikely.",
        "data": {"cpu_pct": 54, "memory_pct": 63, "oom_kills": 0},
    },
    "observe.fetch_alerting_rules": {
        "claim": "PagerDuty alert fired from payment-service latency and checkout error-rate monitors.",
        "data": {"rules": ["payment_latency_p95", "checkout_error_rate"], "pagerduty_incident": "PD-2026-06-03-0312"},
    },
    "observe.read_dashboard_snapshot": {
        "claim": "Dashboard snapshot shows latency spike beginning shortly after the 02:58 UTC deploy.",
        "data": {"dashboard": "payments-overview", "snapshot_id": "dash-pay-0312", "spike_started_at": "03:01 UTC"},
    },
    "repo.get_recent_commits": {
        "claim": "Recent commits include abc1234 from PR #847 touching payment-service order lookup code.",
        "data": {
            "commits": [
                {
                    "sha": "abc1234",
                    "pr": 847,
                    "html_url": "https://github.com/example/payments/commit/abc1234",
                    "commit": {"message": "PR #847 Optimize checkout order lookup"},
                    "author": {"login": "alice"},
                }
            ]
        },
    },
    "repo.diff_pull_request": {
        "claim": "PR #847 added SELECT * FROM orders WHERE user_id = ? without adding an index on orders.user_id.",
        "data": {
            "pull_request": 847,
            "commit_sha": "abc1234",
            "files": [
                {
                    "filename": "payment_service/orders.py",
                    "patch": (
                        "@@ def orders_for_user(user_id):\n"
                        "+    return db.execute('SELECT * FROM orders WHERE user_id = ?', [user_id]).fetchall()\n"
                    ),
                }
            ],
            "change": "Added orders lookup by orders.user_id without creating an index.",
            "missing_migration": "CREATE INDEX idx_orders_user_id ON orders(user_id)",
            "risk": "Sequential scan under checkout traffic",
        },
    },
    "repo.get_deploy_history": {
        "claim": "payment-service v2.3.2 deployed PR #847 commit abc1234 at 02:58 UTC, minutes before the latency spike.",
        "data": {
            "deploys": [
                {
                    "version": "v2.3.2",
                    "deployed_at": "02:58 UTC",
                    "service": "payment-service",
                    "pr": 847,
                    "sha": "abc1234",
                },
                {
                    "version": "v2.3.1",
                    "deployed_at": "19:15 UTC",
                    "service": "payment-service",
                    "safe_rollback": True,
                },
            ],
        },
    },
    "repo.read_ci_pipeline_status": {
        "claim": "CI was green for PR #847 but did not include a high-cardinality query-plan check.",
        "data": {"pipeline": "green", "missing_checks": ["query_plan_regression"], "duration_seconds": 612},
    },
    "repo.fetch_test_results": {
        "claim": "Test results passed unit and API checks but lacked checkout load coverage.",
        "data": {"passed": 1432, "failed": 0, "coverage_gap": "checkout order lookup latency"},
    },
    "repo.blame_file_line": {
        "claim": "Blame points payment_service/orders.py:84 to @alice in PR #847 commit abc1234.",
        "data": {
            "file": "payment_service/orders.py",
            "line": 84,
            "author": "@alice",
            "author_login": "alice",
            "owner": "payments-platform",
            "pr": 847,
            "commit_sha": "abc1234",
        },
    },
    "repo.get_rollback_targets": {
        "claim": "v2.3.1 is the latest safe rollback target for payment-service.",
        "data": {"target": "v2.3.1", "safe": True, "previous_version": "v2.3.0"},
    },
    "repo.read_changelog": {
        "claim": "Changelog for v2.3.2 lists order lookup optimization as the only payment-service change.",
        "data": {"version": "v2.3.2", "entries": ["Optimize order lookup path"], "risk_flags": ["database_query"]},
    },
    "repo.check_dependency_changes": {
        "claim": "Dependency changes are absent, reducing likelihood of library regression.",
        "data": {"changed_dependencies": [], "lockfile_changed": False},
    },
    "repo.get_feature_flags": {
        "claim": "The order lookup change was not protected by a feature flag.",
        "data": {"flags": [{"name": "checkout_fast_path", "enabled": True}], "guarded_pr_847": False},
    },
    "repo.fetch_pr_metadata": {
        "claim": "PR #847 by @alice was merged at 02:44 UTC and deployed as commit abc1234 at 02:58 UTC.",
        "data": {
            "pull_request_metadata": {
                "number": 847,
                "title": "Optimize checkout order lookup",
                "html_url": "https://github.com/example/payments/pull/847",
                "merged_at": "02:44 UTC",
                "user": {"login": "alice"},
                "head": {"sha": "abc1234"},
            },
            "author": "@alice",
            "review_count": 1,
            "reviewers": ["@bob"],
            "labels": ["payments", "performance"],
        },
    },
    "repo.get_commit_author": {
        "claim": "Commit abc1234 was authored by @alice from payments-platform.",
        "data": {"author": "@alice", "login": "alice", "team": "payments-platform", "timezone": "UTC"},
    },
    "repo.read_deployment_config": {
        "claim": "Deployment config supports rollback to v2.3.1 through the standard rollout controller.",
        "data": {"strategy": "rolling", "rollback_command": "deploy rollback payment-service v2.3.1", "max_unavailable": 1},
    },
    "infra.rollback_deployment": {
        "claim": "payment-service rollback to v2.3.1 executed after human approval.",
        "data": {"status": "executed", "target": "v2.3.1", "rollout_id": "roll-pay-231"},
    },
    "infra.restart_service": {
        "claim": "{service} restart command completed against the simulated runtime.",
        "data": {"status": "executed", "restarted_pods": 6, "strategy": "rolling_restart"},
    },
    "infra.scale_replicas": {
        "claim": "{service} replica count changed in the simulated runtime.",
        "data": {"status": "executed", "from_replicas": 6, "to_replicas": 9},
    },
    "infra.toggle_feature_flag": {
        "claim": "Feature flag change was applied in the simulated configuration store.",
        "data": {"status": "executed", "flag": "checkout_fast_path", "enabled": False},
    },
    "infra.add_database_index": {
        "claim": "Database index migration plan for orders.user_id was prepared and applied in simulation.",
        "data": {"status": "executed", "index": "idx_orders_user_id", "estimated_lock_ms": 0},
    },
    "infra.flush_cache": {
        "claim": "{service} cache namespace was flushed in the simulated cache backend.",
        "data": {"status": "executed", "cache_namespace": "payments", "keys_flushed": 8200},
    },
    "infra.update_rate_limit": {
        "claim": "Rate limit update reduced checkout retries while payment-service recovered.",
        "data": {"status": "executed", "limit_per_minute": 1200, "previous_limit_per_minute": 2400},
    },
    "infra.drain_node": {
        "claim": "Node drain moved payment-service pods away from the selected node.",
        "data": {"status": "executed", "node": "ip-10-0-12-44", "pods_evicted": 3},
    },
    "infra.redeploy_service": {
        "claim": "{service} redeploy completed using the current approved artifact.",
        "data": {"status": "executed", "artifact": "payment-service:v2.3.2", "rollout_id": "redeploy-pay-847"},
    },
    "infra.modify_env_config": {
        "claim": "Environment configuration change was written to the simulated deployment spec.",
        "data": {"status": "executed", "key": "DB_QUERY_TIMEOUT_MS", "value": "1500"},
    },
    "infra.open_circuit_breaker": {
        "claim": "Circuit breaker opened to shed checkout payment traffic safely.",
        "data": {"status": "executed", "breaker": "checkout-payment", "mode": "open"},
    },
    "infra.run_migration": {
        "claim": "Migration runner executed the approved migration in the simulated database.",
        "data": {"status": "executed", "migration": "20260603_add_orders_user_id_index", "duration_seconds": 4},
    },
    "comms.post_to_slack": {
        "claim": "SENTINEL posted the incident update to the Discord alerts channel.",
        "data": {"provider": "discord", "channel": "#alerts", "message_id": "discord-1847"},
    },
    "comms.create_incident_channel": {
        "claim": "SENTINEL created or found the internal incident channel for coordination.",
        "data": {"channel": "#inc-payment-2026-06-03", "created": True},
    },
    "comms.page_oncall_engineer": {
        "claim": "SENTINEL paged the configured on-call engineer through the incident system.",
        "data": {"paged_user": "eng-oncall", "escalation_policy": "payments-primary"},
    },
    "comms.update_status_page": {
        "claim": "SENTINEL prepared a status-page draft without publishing external communication.",
        "data": {"draft_id": "status-draft-847", "published": False, "requires_human": True},
    },
    "comms.write_post_mortem": {
        "claim": "SENTINEL drafted a post-mortem with facts separated from inferences.",
        "data": {"document": "Summary: payment latency incident caused by PR #847 with facts and inferences separated."},
    },
    "comms.notify_stakeholders": {
        "claim": "SENTINEL sent an internal stakeholder notification summary.",
        "data": {"audience": ["support-leads", "payments-leads"], "notification_id": "notify-847"},
    },
    "comms.escalate_incident": {
        "claim": "SENTINEL escalated the incident internally to payments-platform leadership.",
        "data": {"escalated_to": "payments-platform-lead", "reason": "customer-facing checkout impact"},
    },
    "comms.close_incident": {
        "claim": "SENTINEL prepared an internal closeout update after mitigation verification.",
        "data": {"closeout_ready": True, "external_status_changed": False},
    },
    "comms.create_jira_ticket": {
        "claim": "SENTINEL created a follow-up ticket owned by payments-platform.",
        "data": {"ticket_id": "SRE-1847", "owner": "payments-platform"},
    },
    "comms.send_executive_summary": {
        "claim": "SENTINEL produced an internal executive summary of blast radius and mitigation.",
        "data": {"summary_id": "exec-847", "recipients": ["vp-engineering"], "sent": True},
    },
    "comms.schedule_retro_meeting": {
        "claim": "SENTINEL scheduled a retrospective with service owners and incident commander.",
        "data": {"calendar_event": "retro-847", "attendees": ["payments-platform", "incident-commander"]},
    },
    "comms.update_runbook": {
        "claim": "SENTINEL appended the missing-index detection lesson to the payments runbook.",
        "data": {"runbook": "payments latency", "revision": "runbook-rev-847"},
    },
}


class SimulatedIncidentEnvironment:
    """Scenario-backed source material for all v1 tool adapters."""

    def __init__(self, scenario: IncidentScenario):
        self.scenario = scenario
        self.call_counts: dict[str, int] = {}
        self.remediated_services: list[str] = []

    def invoke(self, contract: ToolContract, payload: dict[str, Any]) -> dict[str, Any]:
        self.call_counts[contract.name] = self.call_counts.get(contract.name, 0) + 1
        count = self.call_counts[contract.name]

        transient_limit = self.scenario.transient_failures.get(contract.name, 0)
        if count <= transient_limit:
            raise ToolExecutionError(
                ToolErrorKind.RETRYABLE,
                f"{contract.name} transient upstream timeout",
                retryable=True,
            )

        if contract.name in self.scenario.degraded_tools:
            raise ToolExecutionError(
                ToolErrorKind.PERMANENT,
                self.scenario.degraded_tools[contract.name],
                retryable=False,
            )

        service = payload.get("service") or self.scenario.affected_services[0]
        window = payload.get("time_window", "02:30-03:30 UTC")
        implementation = TOOL_IMPLEMENTATIONS.get(contract.name)
        if implementation is None:
            raise ToolExecutionError(
                ToolErrorKind.PERMANENT,
                f"{contract.name} has no simulated implementation",
                retryable=False,
            )

        evidence = self._evidence_for(contract.name, service, window, implementation)
        if contract.name == "observe.get_error_rate_timeseries" and service in self.remediated_services:
            evidence.claim = (
                f"{service} metrics recovered after rollback: error rate returned near baseline "
                "and payment latency moved back toward 4ms."
            )
        data = {
            "tool": contract.name,
            "implementation": f"simulated::{contract.name}",
            "stub": False,
            "scenario": self.scenario.name,
            "service": service,
            "timestamp": datetime.now(UTC).isoformat(),
            "observation": evidence.claim,
            "evidence": [item.model_dump(mode="json") for item in [evidence]],
        }
        data.update(implementation["data"])

        if contract.name == "infra.rollback_deployment":
            self.remediated_services.append(service)
            data.update({"status": "executed", "target": payload.get("target", "v2.3.1")})
        elif contract.name == "observe.get_error_rate_timeseries":
            current = data["current_error_rate"]
            if service in self.remediated_services:
                current = 0.003
            if self.scenario.trigger_kind == "watch":
                current = 0.008
            data.update({"current_error_rate": current})

        return data

    def _evidence_for(
        self,
        tool_name: str,
        service: str,
        window: str,
        implementation: dict[str, Any],
    ) -> Evidence:
        claim = str(implementation["claim"]).format(service=service, window=window)
        if self.scenario.trigger_kind == "watch":
            claim = (
                f"Watch: {claim} The condition is trending up before PagerDuty "
                "thresholds are crossed."
            )

        return Evidence(
            source=tool_name,
            time_window=window,
            affected_service=service,
            claim=claim,
            provenance=f"{self.scenario.name}:{tool_name}",
        )
