# Audit events with payload boundaries

SENTINEL records audit events for decisions, tool interactions, state transitions, approvals, and remediation outcomes that affect an investigation. Audit events include reviewable metadata such as timestamp, actor, phase, tool name, permission class, hashes, retry count, error class, derived evidence, state transition, approval request, and remediation result, but they do not embed secret-bearing source material.

**Considered Options**

- Persist full raw payloads in the audit log for maximum replay detail
- Log only final investigation summaries
- Record audit events with hashes and references to sensitive source material

**Consequences**

Incident runs are auditable without turning the audit trail into a sensitive data dump. Debugging may require following references back to source material storage, but the durable trace remains safer to inspect and share during demos or reviews.
