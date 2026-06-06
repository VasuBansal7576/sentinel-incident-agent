# Live Proof

Source artifact: `.sentinel/real-slow-query-summary.json`

Run date: 2026-06-06

Status: `completed`

Final state: `post_mortem`

Tool calls: `13`

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
  "activeAt": "2026-06-06T14:59:03.790406478Z",
  "value": "1.51081e-01"
}
```

## Prometheus Evidence

Before remediation, Prometheus showed `/slow-query` latency of `162.6ms`.

After approved remediation, Prometheus showed `/slow-query` latency of `5.4ms`.

Observed load during the incident:

```json
{
  "requests": 129,
  "errors": 0,
  "max_duration_ms": 259.868,
  "last_duration_ms": 2.607
}
```

## Loki Evidence

Redacted Loki log excerpt captured in the investigation summary:

```text
SELECT * FROM orders WHERE user_id = ? used a sequential scan because orders.user_id had no index.
```

Diagnosis produced by SENTINEL:

```text
Real /slow-query incident: Prometheus recorded 162.6ms latency and Loki logs show SELECT * FROM orders WHERE user_id = ? using a sequential scan because orders.user_id has no index. Root cause: missing SQLite index orders.user_id.
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
Created idx_orders_user_id on orders(user_id); real Prometheus latency improved from 162.6ms to 5.4ms.
```

Provider proof counts:

```json
{
  "prometheus": 2,
  "loki": 2,
  "generic_webhook": 1,
  "discord": 4,
  "sqlite": 1
}
```

## Discord Message

Discord webhook URL and channel identifiers are redacted. Message content posted by SENTINEL:

```text
payment-service /slow-query incident was caused by a real missing SQLite index on orders.user_id and mitigated by creating idx_orders_user_id.
Timeline:
- Generic Prometheus alert webhook received by SENTINEL.
- SENTINEL read real Loki app logs for /slow-query slow-query events.
- SENTINEL read real Prometheus latency: before fix 162.6ms.
- SENTINEL requested human approval for add_index orders.user_id.
- Authorized approver approved the exact add-index request.
- SENTINEL executed CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id).
- SENTINEL verified real Prometheus latency after fix: 5.4ms.
- SENTINEL posted the full incident timeline to Discord.
Facts:
- The app executed SELECT * FROM orders WHERE user_id = ? against SQLite.
- Loki logs showed the query using a sequential scan while the index was missing.
- Prometheus recorded /slow-query latency before fix: 162.6ms.
- Prometheus recorded /slow-query latency after fix: 5.4ms.
- The approved remediation created idx_orders_user_id on orders(user_id).
Action items: Keep idx_orders_user_id in the schema before enabling this query path.
```
