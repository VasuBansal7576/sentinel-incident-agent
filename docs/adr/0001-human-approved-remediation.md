# Human-approved remediation

SENTINEL is autonomous for investigation, diagnosis, recommendation, and documentation, but any production-changing remediation requires explicit human approval. This gives the agent enough autonomy to remove the 3am investigation burden while keeping irreversible or risky production mutations behind an accountable human decision.

**Considered Options**

- Fully autonomous remediation after high-confidence diagnosis
- Human-approved remediation after autonomous investigation
- Human-only remediation with agent-generated notes

**Consequences**

SENTINEL must model the boundary between recommendations and remediations explicitly, and every production-changing tool must be gated behind an approval path.
