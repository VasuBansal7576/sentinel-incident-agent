# Retain evidence, not raw source material

SENTINEL v1 retains structured evidence and audit events indefinitely in the local demo store, while raw source material remains in replay inputs or integration-owned storage and is referenced by hash or path. Investigation state does not copy raw logs, traces, Slack payloads, or other unbounded source material.

**Considered Options**

- Store all raw source material in the investigation store
- Store only final diagnosis and post-mortem text
- Retain structured evidence and audit events while referencing raw source material

**Consequences**

The demo remains inspectable and replayable without training the architecture to hoard raw incident data. Tool and deterministic harness implementations must expose stable references to source material so evidence and audit events can remain bounded while preserving provenance.
