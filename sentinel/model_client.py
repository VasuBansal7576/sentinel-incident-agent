from __future__ import annotations

from typing import Protocol

from sentinel.models import InvestigationState, StateName, ToolContract


class ModelClient(Protocol):
    def plan_tools(
        self,
        *,
        state: InvestigationState,
        available_contracts: list[ToolContract],
        objective: str,
    ) -> list[str]:
        ...


class DeterministicIncidentModelClient:
    """Typed model-client seam used for deterministic evals and tests."""

    def plan_tools(
        self,
        *,
        state: InvestigationState,
        available_contracts: list[ToolContract],
        objective: str,
    ) -> list[str]:
        available = {contract.name for contract in available_contracts}
        desired = self._desired_plan(state.current_state, state.trigger_kind)
        return [name for name in desired if name in available]

    def _desired_plan(self, state_name: StateName, trigger_kind: str) -> list[str]:
        if trigger_kind == "watch":
            return {
                StateName.RECEIVED: ["comms.post_to_slack"],
                StateName.TRIAGE: [
                    "observe.get_error_rate_timeseries",
                    "observe.query_metrics_range",
                    "observe.fetch_alerting_rules",
                ],
                StateName.EVIDENCE_COLLECTION: [
                    "observe.fetch_service_logs",
                    "observe.fetch_apm_data",
                    "repo.get_feature_flags",
                ],
                StateName.CORRELATION: ["observe.check_uptime_history"],
                StateName.RESPONSE_PROPOSAL: ["comms.post_to_slack"],
                StateName.POST_MORTEM: ["comms.update_runbook"],
            }.get(state_name, [])

        return {
            StateName.RECEIVED: [
                "comms.create_incident_channel",
                "comms.post_to_slack",
            ],
            StateName.TRIAGE: [
                "observe.fetch_alerting_rules",
                "observe.get_error_rate_timeseries",
                "observe.query_metrics_range",
                "repo.get_deploy_history",
                "observe.check_pod_health",
            ],
            StateName.EVIDENCE_COLLECTION: [
                "observe.fetch_service_logs",
                "observe.fetch_service_logs",
                "observe.get_distributed_traces",
                "observe.check_db_slow_queries",
                "observe.fetch_apm_data",
                "repo.diff_pull_request",
                "repo.fetch_pr_metadata",
                "repo.fetch_test_results",
                "repo.blame_file_line",
                "repo.get_feature_flags",
            ],
            StateName.CORRELATION: [
                "observe.check_uptime_history",
                "repo.get_rollback_targets",
                "repo.read_deployment_config",
            ],
            StateName.RESPONSE_PROPOSAL: ["comms.post_to_slack"],
            StateName.REMEDIATION: ["infra.rollback_deployment", "observe.get_error_rate_timeseries"],
            StateName.POST_MORTEM: [
                "comms.write_post_mortem",
                "comms.create_jira_ticket",
                "comms.update_runbook",
                "comms.post_to_slack",
            ],
        }.get(state_name, [])

