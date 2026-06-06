# Remediation approval requires an authorized approver

SENTINEL accepts human approval only from an authorized approver for the specific incident. In v1, the authorized approver is the PagerDuty on-call user or incident commander mapped to the incident, and approvals from random channel members, unknown Slack users, or unmapped users are rejected.

**Considered Options**

- Accept any Slack reply in the incident channel
- Accept approvals from any recognized team member
- Accept approvals only from the incident's authorized approver

**Consequences**

Approval becomes an accountable incident decision rather than a casual channel command. The Slack interaction path must map user identity to incident authority and record rejected approval attempts as audit events.
