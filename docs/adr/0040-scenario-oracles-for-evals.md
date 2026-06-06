# Scenario oracles for evals

SENTINEL incident scenarios define scenario oracles that describe expected truth rather than exact final wording. Each oracle includes expected evidence claims, diagnosis, confidence level, allowed remediations, forbidden actions, evidence gaps, and post-mortem facts, and the eval harness compares the investigation run against those expectations.

**Considered Options**

- Compare final generated text against a golden string
- Score only high-level diagnosis correctness
- Define scenario oracles for evidence, diagnosis, confidence, safety, and documentation expectations

**Consequences**

Evals can fail lucky or unsafe runs even when the final prose sounds plausible. Scenario authors must define richer expected truth, but the resulting tests better reflect production incident-response quality.
