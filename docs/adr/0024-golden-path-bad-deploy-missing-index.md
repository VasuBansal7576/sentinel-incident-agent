# Golden path bad-deploy missing-index scenario

SENTINEL's primary demo and evaluation scenario is the payment-service bad deploy that introduces a query on `orders.user_id` without an index. The scenario starts with a PagerDuty alert for latency and errors, links the regression to a recent deployment and PR, proposes rollback or index creation, executes approved rollback safely, and generates an evidence-backed post-mortem.

**Considered Options**

- Demo several shallow incident types
- Use a generic synthetic outage with no code or deploy cause
- Center the build on one deep bad-deploy missing-index scenario

**Consequences**

The build can exercise long-horizon investigation, tool composition, subagents, approval gating, remediation execution, audit events, and post-mortem generation through one coherent story. Additional scenarios can exist for eval breadth, but the golden path remains the video and reviewer narrative spine.
