# Provider-agnostic model client

SENTINEL v1 uses a small model client interface with OpenAI as the default provider, while keeping orchestration code provider-agnostic. The model client exposes structured-output calls for parent investigations and service investigator reports, and tests use deterministic fake model clients for phase control, tool access, and eval behavior.

**Considered Options**

- Call the OpenAI SDK directly throughout orchestration code
- Avoid live model calls entirely and script the agent
- Use a provider-agnostic model client with OpenAI as the default implementation

**Consequences**

The live model can power the demo path without making every unit or eval test depend on tokens, latency, or model variance. The implementation must keep prompt construction, structured-output parsing, and provider-specific concerns behind the model client boundary.
