# Malformed model output fails safely

SENTINEL treats malformed structured model output as a model output failure. The phase controller retries once with a repair prompt that includes the schema violation, and if the response is still invalid, records the failure in investigation state and stops or degrades the affected phase safely rather than guessing.

**Considered Options**

- Parse malformed responses heuristically
- Retry indefinitely until structured output validates
- Retry once, then record a model output failure and degrade safely

**Consequences**

The system avoids accepting prose or malformed objects as authoritative investigation state. Some runs may end with insufficient confidence or blocked phases, but the trace remains honest and evals can verify safe behavior under model formatting failures.
