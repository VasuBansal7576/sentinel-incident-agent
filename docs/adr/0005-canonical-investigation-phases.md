# Canonical investigation phases

SENTINEL uses five canonical investigation phases: triage, evidence collection, correlation, diagnosis, and response proposal. Post-mortem generation is not an investigation phase; it is a downstream documentation workflow that consumes completed investigation state.

**Considered Options**

- Let the agent choose ad hoc phases per incident
- Use a small explicit phase model for every investigation
- Include post-mortem generation as the final investigation phase

**Consequences**

Investigation state, resumability, and evals can be organized around stable phase boundaries. The model loses some flexibility in naming its own process, but the system gains a shared language for progress, failure recovery, and test assertions.
