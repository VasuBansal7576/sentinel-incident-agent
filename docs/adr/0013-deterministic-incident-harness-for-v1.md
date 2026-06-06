# Deterministic incident harness for v1

SENTINEL v1 keeps a controlled deterministic incident harness for repeatable demos, regression tests, and long-horizon trace review. The harness uses production-shaped contracts: schemas, retries, rate limits, typed errors, composable outputs, audit logging, and approval boundaries.

**Considered Options**

- Integrate every external production system during the five-day build
- Use simple mocks that bypass production scaffolding
- Use a controlled deterministic harness plus one real operational proof path

**Consequences**

The build can demonstrate the full investigation loop reliably while the live proof demonstrates real operational integration through Prometheus, Loki, kind, SQLite, and Discord. The docs and memo must separate deterministic long-horizon proof from live infrastructure proof without creating a real-vs-fake split.
