# Explicit store migrations

SENTINEL v1 uses explicit SQL migrations for the SQLite-backed investigation store. The application stores a schema version, applies migrations on startup, and keeps migration files in the repository instead of relying on hidden `create_all()` behavior or ad hoc table creation.

**Considered Options**

- Create tables implicitly from models at startup
- Hand-edit the SQLite schema during development
- Use explicit versioned SQL migrations from day one

**Consequences**

The persistence model remains reviewable, recoverable, and credible as durable incident state. This adds a little ceremony to the five-day build, but reviewers can inspect how investigation state, audit events, idempotency keys, approvals, and eval results are stored and evolved.
