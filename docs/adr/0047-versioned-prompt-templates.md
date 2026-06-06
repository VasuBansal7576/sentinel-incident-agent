# Versioned prompt templates

SENTINEL stores parent investigation, service investigator, repair, and post-mortem prompts as named versioned templates in the repository rather than inline strings scattered through code. Each model call records the prompt template name and version in its audit event.

**Considered Options**

- Keep prompts inline near each model call
- Store prompts externally outside the repository
- Store named versioned prompt templates in the repository

**Consequences**

Eval changes become easier to diagnose because prompt changes are visible alongside code changes and audit traces. The implementation must load prompts through a small template boundary and include prompt version metadata in model-call audit events.
