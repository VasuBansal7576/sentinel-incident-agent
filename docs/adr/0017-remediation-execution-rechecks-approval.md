# Remediation execution rechecks approval

SENTINEL does not execute production-changing remediation directly after a human approval message. Remediation execution rechecks the approval request, approval snapshot, current target state, permission class, and duplicate execution risk before carrying out or refusing the remediation.

**Considered Options**

- Execute the remediation immediately once Slack approval arrives
- Trust the approval snapshot but skip current-state checks
- Recheck approval and current state at remediation execution time

**Consequences**

The execution path can safely skip already-satisfied or stale remediations instead of blindly mutating production. This adds a final safety gate, but it makes approved actions auditable and protects against delayed approvals, repeated clicks, and changed production state.
