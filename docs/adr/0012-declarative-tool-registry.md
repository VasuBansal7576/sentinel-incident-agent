# Declarative tool registry

SENTINEL uses a declarative tool registry to keep 50+ tools coherent. Each tool definition declares its namespace, permission class, input schema, output schema, retry and rate-limit policy, and output role, while the executor enforces schemas, permissions, retries, and audit logging.

**Considered Options**

- Route tool calls through a giant conditional dispatcher
- Split tools into namespace-specific hard-coded executors
- Register tools declaratively and enforce behavior through a common executor

**Consequences**

The model can select from a large tool surface without the code collapsing into hand-routed branches. Tool authors must provide complete metadata, and tests should cover registry validation as well as individual tool behavior.
