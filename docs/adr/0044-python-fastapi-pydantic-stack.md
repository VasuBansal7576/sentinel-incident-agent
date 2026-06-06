# Python FastAPI Pydantic stack

SENTINEL v1 uses Python with a small FastAPI service, Pydantic models for tool contracts and state schemas, SQLite migrations, pytest for unit, integration, and eval tests, and a simple async worker loop inside the same process. The build avoids heavy agent frameworks unless a specific feature earns its keep.

**Considered Options**

- Use a heavy agent framework for orchestration
- Build a CLI-only Python prototype
- Use a small Python service with typed schemas and explicit workflow code

**Consequences**

The code remains inspectable for reviewers while still supporting webhooks, typed tools, deterministic fixtures, persistence, and evals. The implementation must provide the orchestration, registry, and phase-control behavior explicitly instead of hiding core decisions inside a framework.
