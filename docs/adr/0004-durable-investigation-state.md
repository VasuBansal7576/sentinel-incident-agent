# Durable investigation state

SENTINEL preserves long-horizon investigations through durable investigation state rather than relying on live model context. After each major phase, the agent records the evidence, hypotheses, diagnoses, recommendations, approvals, and remediations needed to resume the investigation after a crash or restart.

**Considered Options**

- Trust the model context to hold the whole investigation
- Persist only raw tool outputs and recompute reasoning on restart
- Persist structured investigation state after each major phase

**Consequences**

The agent can resume from a fresh model call without losing plan coherence, but every investigation phase must define the state it contributes. Tests and evals should assert state transitions, not just final Slack messages.
