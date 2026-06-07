# Live Proof

Tracked source artifact: [real-slow-query-summary.json](real-slow-query-summary.json)

Generated local artifacts: `.sentinel/live-run-1780827203.log` and `.sentinel/live-run-1780827203.structured.log`

Run date: 2026-06-07

Status: `completed`

Final state: `post_mortem`

Tool calls: `34`

Checkpoint backend: `sqlite`

Notification target: Discord webhook redacted

## Incident

SENTINEL received a real generic Prometheus alert for `payment-service` on route `/slow-query`. The alert was firing from `sentinel_slow_query_last_duration_seconds` with service label `payment-service`.

Redacted alert excerpt:

```json
{
  "alertname": "SentinelSlowQueryLatency",
  "instance": "sentinel:8000",
  "job": "sentinel",
  "route": "/slow-query",
  "service": "payment-service",
  "severity": "critical",
  "state": "firing",
  "activeAt": "2026-06-07T10:14:11.556260173Z",
  "value": "1.18198e-01"
}
```

## Model And Checkpoint Proof

The credentialed run used Groq's OpenAI-compatible Responses endpoint for model tool planning. The received and triage phases returned model-selected tools with model rationales. The evidence-collection phase recorded a `HTTPStatusError` and used SENTINEL's deterministic fallback, which is the intended fail-closed reliability behavior.

The run also restarted the receiver at the approval checkpoint, recovered the same investigation from the SQLite checkpoint store, submitted the structured approval command, and completed remediation and verification after restart.

## Prometheus Evidence

Before remediation, Prometheus showed `/slow-query` latency of `115.2ms`.

After approved remediation, Prometheus showed `/slow-query` latency of `1.2ms`.

The live investigation also checked Prometheus alerting rules, target health, error rate, queue depth, network RTT, uptime history, CPU, and memory before requesting approval.

Observed load during the incident:

```json
{
  "requests": 121,
  "errors": 0,
  "max_duration_ms": 137.886,
  "last_duration_ms": 115.207
}
```

## Loki And GitHub Evidence

Redacted Loki log excerpt captured in the investigation summary:

```text
SELECT * FROM orders WHERE user_id = ? used a sequential scan because orders.user_id had no index.
```

The credentialed run also read live GitHub API evidence through `repo.get_recent_commits` and `repo.get_rollback_targets` during the service-investigator phase.

Diagnosis produced by SENTINEL:

```text
Real /slow-query incident: Prometheus recorded 115.2ms latency and Loki logs show SELECT * FROM orders WHERE user_id = ? using a sequential scan because orders.user_id has no index. Root cause: missing SQLite index orders.user_id.
```

## Remediation

Recommendation:

```text
add_index orders.user_id
```

Approved action:

```sql
CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id);
```

Remediation result:

```text
Created idx_orders_user_id on orders(user_id); real Prometheus latency improved from 115.2ms to 1.2ms.
```

Recorded tool-call order:

```text
comms.page_oncall_engineer
comms.create_incident_channel
comms.post_to_slack
observe.check_db_slow_queries
observe.fetch_service_logs
observe.query_metrics_range
observe.get_distributed_traces
observe.fetch_apm_data
observe.fetch_alerting_rules
observe.read_dashboard_snapshot
observe.get_error_rate_timeseries
observe.read_queue_depth
observe.get_network_latency
observe.check_uptime_history
observe.get_memory_cpu_usage
observe.fetch_service_logs
repo.get_recent_commits
repo.get_rollback_targets
infra.spawn_service_investigator
observe.fetch_service_logs
repo.get_recent_commits
repo.get_rollback_targets
infra.spawn_service_investigator
observe.fetch_service_logs
repo.get_recent_commits
repo.get_rollback_targets
infra.spawn_service_investigator
comms.post_to_slack
infra.add_database_index
observe.query_metrics_range
comms.write_post_mortem
comms.create_jira_ticket
comms.update_runbook
comms.post_to_slack
```

Required provider proof counts:

```json
{
  "discord": 4,
  "generic_webhook": 1,
  "github": 4,
  "loki": 5,
  "prometheus": 9,
  "sqlite": 1
}
```

Live tool proof counts:

```json
{
  "comms.page_oncall_engineer": 1,
  "comms.post_to_slack": 3,
  "comms.write_post_mortem": 1,
  "infra.add_database_index": 1,
  "observe.check_db_slow_queries": 1,
  "observe.check_uptime_history": 1,
  "observe.fetch_alerting_rules": 1,
  "observe.fetch_apm_data": 1,
  "observe.fetch_service_logs": 2,
  "observe.get_distributed_traces": 1,
  "observe.get_error_rate_timeseries": 1,
  "observe.get_memory_cpu_usage": 1,
  "observe.get_network_latency": 1,
  "observe.query_metrics_range": 2,
  "observe.read_dashboard_snapshot": 1,
  "observe.read_queue_depth": 1,
  "repo.get_recent_commits": 3,
  "repo.get_rollback_targets": 1
}
```

## Discord Message

Discord webhook URL and channel identifiers are redacted. Message content posted by SENTINEL:

```text
payment-service /slow-query incident was caused by a real missing SQLite index on orders.user_id and mitigated by creating idx_orders_user_id.
Timeline:
- Generic Prometheus alert webhook received by SENTINEL.
- SENTINEL read real Loki app logs for /slow-query slow-query events.
- SENTINEL read real Prometheus latency: before fix 115.2ms.
- SENTINEL checked Prometheus alerts, targets, errors, queue depth, RTT, uptime, CPU/memory, plus Loki trace/APM paths.
- SENTINEL requested human approval for add_index orders.user_id.
- Authorized approver approved the exact add-index request.
- SENTINEL executed CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id).
- SENTINEL verified real Prometheus latency after fix: 1.2ms.
- SENTINEL posted the full incident timeline to Discord.
Facts:
- The app executed SELECT * FROM orders WHERE user_id = ? against SQLite.
- Loki logs showed the query using a sequential scan while the index was missing.
- Prometheus recorded /slow-query latency before fix: 115.2ms.
- Additional Prometheus/Loki checks ruled out error-rate, queue, network, uptime, and resource saturation as primary causes.
- Prometheus recorded /slow-query latency after fix: 1.2ms.
- The approved remediation created idx_orders_user_id on orders(user_id).
Action items: Keep idx_orders_user_id in the schema before enabling this query path.
```
