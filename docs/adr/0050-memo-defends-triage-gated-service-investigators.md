# MEMO defends triage-gated service investigators

SENTINEL's MEMO defends the decision to spawn parallel service investigators after triage instead of running one sequential investigation or spawning subagents immediately on every alert. The defense centers on multi-service incident speed, controlled fan-out, isolated service reasoning, and parent-level evidence reconciliation.

**Considered Options**

- Defend human-approved remediation as the main design decision
- Defend the broad DevOps agent concept
- Defend triage-gated parallel service investigators

**Consequences**

The MEMO's defended decision directly connects to the hackathon subagent requirement while showing a real architecture tradeoff. The written explanation should acknowledge that sequential investigation is simpler and more debuggable, then justify why triage-gated parallelism is worth it for multi-service incidents.
