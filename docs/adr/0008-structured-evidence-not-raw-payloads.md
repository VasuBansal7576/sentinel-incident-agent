# Structured evidence, not raw payloads

SENTINEL persists structured evidence into investigation state rather than treating raw logs, metric dumps, traces, diffs, or Slack messages as evidence. Raw source material may be retained separately, but the durable investigation narrative is built from bounded observations with source, time window, affected service, claim, and provenance.

**Considered Options**

- Store raw source material directly in investigation state
- Persist only final diagnoses and discard intermediate observations
- Persist structured evidence derived from source material

**Consequences**

Investigation state stays reviewable, resumable, and eval-friendly without losing the provenance needed to audit conclusions. The agent must extract and name evidence deliberately, which adds work during evidence collection but prevents raw payloads from overwhelming model context.
