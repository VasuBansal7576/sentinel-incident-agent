# Subagent Proof

Date: 2026-06-06

Source command:

```bash
python3 scripts/run_sentinel_demo.py --summary-output .sentinel/recording-demo-summary.json
```

Fresh deterministic proof:

```text
tool_calls 37
plan_steps 26
status completed
current_state post_mortem
all_tool_calls_have_reasoning_trace True
```

## Spawn Tool Registry Entry

The subagent is not a renamed helper call. It is exposed as a tool in the registry:

```text
spawn_contract_name infra.spawn_service_investigator
spawn_contract_namespace infra
spawn_contract_permission read_only
spawn_contract_phase_allowlist service_investigation
```

That means the parent can only spawn the Service Investigator during the `service_investigation` phase.

## Isolated Context

Sample Service Investigator report from a real `golden_path` run:

```text
service_report_service payment-service
service_report_context_id ctx-abf519068e
service_report_confidence high
```

Additional subagents in the same run had different isolated contexts:

```text
blast_context ctx-40e1adcb4a
readiness_context ctx-d2d1332ff0
```

## Scoped Tool List

The Service Investigator received 28 scoped tools. They are observe/repo tools only:

```text
observe.check_db_slow_queries
observe.check_pod_health
observe.check_uptime_history
observe.fetch_alerting_rules
observe.fetch_apm_data
observe.fetch_cdn_logs
observe.fetch_service_logs
observe.get_distributed_traces
observe.get_error_rate_timeseries
observe.get_memory_cpu_usage
observe.get_network_latency
observe.query_metrics_range
observe.read_dashboard_snapshot
observe.read_flame_graph
observe.read_queue_depth
repo.blame_file_line
repo.check_dependency_changes
repo.diff_pull_request
repo.fetch_pr_metadata
repo.fetch_test_results
repo.get_commit_author
repo.get_deploy_history
repo.get_feature_flags
repo.get_recent_commits
repo.get_rollback_targets
repo.read_changelog
repo.read_ci_pipeline_status
repo.read_deployment_config
```

No `infra.*` remediation tool and no `comms.*` human-facing communication tool is in that scoped list.

## Denied Infra And Comms Access

I attempted to invoke infra and comms tools inside the Service Investigator's scoped registry. Both were denied:

```text
denied_tool infra.rollback_deployment False permission_denied Tool is outside scoped registry
denied_tool comms.post_to_slack False permission_denied Tool is outside scoped registry
```

This is the safety boundary the reviewer should see: subagents can investigate, but they cannot mutate infrastructure or talk to the incident channel.

## Parent Reconciliation

The parent consumed two `ServiceIncidentReport` objects and reconciled them into the final diagnosis:

```text
service_reports_consumed 2
reconciled_confidence high
reconciled_diagnosis PR #847 by @alice added SELECT * FROM orders WHERE user_id = ? without an index on orders.user_id, causing sequential scans. Query time: 4ms -> 2.3s (575x). Affected users: 18420 in checkout payment authorization. Confirmed missing index: orders.user_id.
```

The parent owns the final diagnosis, approval request, remediation, and post-mortem. The Service Investigator contributes a structured local report, not a free-form final answer.
