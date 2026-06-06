# Structured approval commands

SENTINEL does not treat free-form Slack replies as remediation approval. Human approval must arrive as a structured approval command or equivalent interaction payload tied to an approval request ID, action ID, and authorized approver identity, while free-form replies may ask questions or request clarification.

**Considered Options**

- Interpret natural-language Slack replies as approvals
- Require structured approval commands only for high-risk actions
- Require structured approval commands for all remediation approvals

**Consequences**

Ambiguous replies such as "rollback?" or "yeah maybe" cannot trigger production-changing remediation. The Slack handler must parse approval commands separately from conversation and record rejected or ambiguous replies as audit events.
