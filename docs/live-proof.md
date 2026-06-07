# Live Proof

Source artifact: `.sentinel/real-slow-query-summary.json`

Run date: 2026-06-07

Status: `completed`

Final state: `post_mortem`

Tool calls: `22`

Notification target: Discord webhook redacted

## Incident

SENTINEL received a real generic Prometheus alert for `payment-service` on route `/slow-query`. The alert was firing from `sentinel_slow_query_last_duration_seconds` with service label `payment-service`.

Redacted alert excerpt:

```json
{
  "alertname": "SentinelSlowQueryLatency",
  "instance": "sentinel:8000",
  "job": "sentinel-real",
  "route": "/slow-query",
  "service": "payment-service",
  "severity": "page",
  "state": "firing",
  "activeAt": "2026-06-07T08:24:53.790406478Z",
  "value": "1.56997e-01"
}
```

## Prometheus Evidence

Before remediation, Prometheus showed `/slow-query` latency of `161.6ms`.

After approved remediation, Prometheus showed `/slow-query` latency of `3.3ms`.

The live investigation also checked Prometheus alerting rules, target health, error rate, queue depth, network RTT, uptime history, CPU, and memory before requesting approval.

Observed load during the incident:

```json
{
  "requests": 120,
  "errors": 0,
  "max_duration_ms": 304.004,
  "last_duration_ms": 0.939
}
```

## Loki Evidence

Redacted Loki log excerpt captured in the investigation summary:

```text
SELECT * FROM orders WHERE user_id = ? used a sequential scan because orders.user_id had no index.
```

Diagnosis produced by SENTINEL:

```text
Real /slow-query incident: Prometheus recorded 161.6ms latency and Loki logs show SELECT * FROM orders WHERE user_id = ? using a sequential scan because orders.user_id has no index. Root cause: missing SQLite index orders.user_id.
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
Created idx_orders_user_id on orders(user_id); real Prometheus latency improved from 161.6ms to 3.3ms.
```

Recorded tool-call order:

```text
comms.create_incident_channel
comms.post_to_slack
comms.page_oncall_engineer
observe.fetch_service_logs
observe.query_metrics_range
observe.check_db_slow_queries
observe.fetch_alerting_rules
observe.read_dashboard_snapshot
observe.get_error_rate_timeseries
observe.read_queue_depth
observe.get_network_latency
observe.check_uptime_history
observe.get_memory_cpu_usage
observe.get_distributed_traces
observe.fetch_apm_data
comms.post_to_slack
infra.add_database_index
observe.query_metrics_range
comms.write_post_mortem
comms.create_jira_ticket
comms.update_runbook
comms.post_to_slack
```

Provider proof counts:

```json
{
  "discord": 4,
  "generic_webhook": 1,
  "loki": 2,
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
  "observe.fetch_service_logs": 1,
  "observe.get_error_rate_timeseries": 1,
  "observe.get_memory_cpu_usage": 1,
  "observe.get_network_latency": 1,
  "observe.query_metrics_range": 2,
  "observe.read_dashboard_snapshot": 1,
  "observe.read_queue_depth": 1
}
```

## Discord Message

Discord webhook URL and channel identifiers are redacted. Message content posted by SENTINEL:

```text
payment-service /slow-query incident was caused by a real missing SQLite index on orders.user_id and mitigated by creating idx_orders_user_id.
Timeline:
- Generic Prometheus alert webhook received by SENTINEL.
- SENTINEL read real Loki app logs for /slow-query slow-query events.
- SENTINEL read real Prometheus latency: before fix 161.6ms.
- SENTINEL checked Prometheus alerts, targets, errors, queue depth, RTT, uptime, CPU/memory, plus Loki trace/APM paths.
- SENTINEL requested human approval for add_index orders.user_id.
- Authorized approver approved the exact add-index request.
- SENTINEL executed CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id).
- SENTINEL verified real Prometheus latency after fix: 3.3ms.
- SENTINEL posted the full incident timeline to Discord.
Facts:
- The app executed SELECT * FROM orders WHERE user_id = ? against SQLite.
- Loki logs showed the query using a sequential scan while the index was missing.
- Prometheus recorded /slow-query latency before fix: 161.6ms.
- Additional Prometheus/Loki checks ruled out error-rate, queue, network, uptime, and resource saturation as primary causes.
- Prometheus recorded /slow-query latency after fix: 3.3ms.
- The approved remediation created idx_orders_user_id on orders(user_id).
Action items: Keep idx_orders_user_id in the schema before enabling this query path.
```
