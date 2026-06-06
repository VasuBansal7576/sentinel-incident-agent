# Phase-filtered tool access

SENTINEL gives the model a phase tool set rather than exposing the entire tool registry in every step. The phase tool set is derived from the current phase, actor, affected-service scope, permission class, and investigation state, so the model retains autonomous tool choice inside a bounded envelope.

**Considered Options**

- Expose all registered tools to the model at all times
- Hard-code a single fixed tool sequence per phase
- Expose only a phase-filtered tool set while preserving model choice

**Consequences**

The agent avoids irrelevant or unsafe tool calls while still satisfying the requirement that tool selection is model-driven. The implementation must make tool filtering transparent in audit events and cover phase-specific tool availability in tests.
