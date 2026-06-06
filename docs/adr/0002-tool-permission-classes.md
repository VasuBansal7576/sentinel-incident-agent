# Tool permission classes

SENTINEL groups tools by permission class instead of treating all tool calls equally. Read-only investigation tools and internal incident updates may run autonomously, while production-changing remediations and external communications require explicit human approval.

**Considered Options**

- Let the model decide whether each tool is safe at runtime
- Hard-code every sensitive tool individually
- Classify tools by permission class and enforce the class boundary

**Consequences**

Tool registration, orchestration, tests, and demos must expose each tool's permission class clearly. This adds upfront structure, but prevents the agent from confusing investigation, internal coordination, production mutation, and external communication.
