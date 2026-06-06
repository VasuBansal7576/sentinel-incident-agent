# Idempotency for triggers, approvals, and remediations

SENTINEL uses idempotency keys for external triggers, approval requests, and remediation executions. Keys are derived from stable incident-system identity plus action class and target, so duplicate webhooks, Slack retries, and worker restarts resume existing work or return existing results instead of creating duplicate investigations or repeated production changes.

**Considered Options**

- Trust upstream systems not to retry duplicate messages
- Deduplicate only incident triggers
- Use idempotency keys for triggers, approvals, and remediation executions

**Consequences**

The system can tolerate retries and restarts without double-running incident workflows or remediations. The implementation must store idempotency records durably and make duplicate handling visible through audit events.
