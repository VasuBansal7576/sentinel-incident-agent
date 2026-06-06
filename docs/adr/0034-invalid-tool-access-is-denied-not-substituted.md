# Invalid tool access is denied, not substituted

SENTINEL rejects tool requests outside the current phase tool set or permission boundary with a typed tool access denial. The executor records an audit event and returns a concise reason to the model, but it does not silently drop the call or auto-substitute another tool.

**Considered Options**

- Silently ignore invalid tool requests
- Auto-substitute a nearby allowed tool
- Return a typed denial and require the model to choose a valid next step

**Consequences**

Guardrail behavior becomes visible in traces and evals, and unsafe or out-of-phase tool calls cannot mutate the investigation indirectly. The model may need an extra turn after a denial, but the denial preserves phase and permission boundaries.
