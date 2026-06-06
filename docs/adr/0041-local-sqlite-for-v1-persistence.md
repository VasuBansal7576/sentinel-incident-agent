# Local SQLite for v1 persistence

SENTINEL v1 uses local SQLite for investigation state, audit events, idempotency keys, and scenario evaluation results. SQLite is self-hosted, transactional, easy to inspect in a demo, strong enough for the five-day production-shaped build, and avoids spending hackathon time operating Postgres while still leaving a persistence boundary that can be replaced later.

**Considered Options**

- Keep all state in process memory and traces
- Start with Postgres for production realism
- Use local SQLite behind the investigation store for v1

**Consequences**

The agent can recover from worker crashes, reject stale approvals, and show durable audit trails in a local demo. The implementation must keep storage access behind a boundary so a later deployment can move to Postgres without rewriting the incident workflow.
