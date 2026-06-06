# Phase controller owns workflow progress

SENTINEL uses a phase controller to own investigation phase transitions, persistence, approval boundaries, and completion criteria. The model proposes the next useful work inside the current phase, but the controller decides whether the investigation can advance from triage through evidence collection, correlation, diagnosis, and response proposal.

**Considered Options**

- Let the model own the full long-horizon plan and phase transitions
- Use a rigid workflow engine with no model discretion inside phases
- Let a phase controller govern transitions while the model chooses phase-local work

**Consequences**

The agent can complete long-horizon investigations without drifting into premature diagnosis or documentation. The controller must encode phase completion criteria, and evals should verify both model choices and controller-enforced transitions.
