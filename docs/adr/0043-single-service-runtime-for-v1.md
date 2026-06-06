# Single service runtime for v1

SENTINEL v1 runs as a single self-hosted service process with three entry points: an HTTP webhook handler, a background investigation worker, and a CLI demo runner. The service is backed by durable state and a deterministic incident harness, rather than split into separate API, worker, scheduler, and database services during the five-day build.

**Considered Options**

- Build a CLI-only demo
- Split the runtime into separate API, worker, scheduler, and database services
- Use one deployable service process with webhook, worker, and demo entry points

**Consequences**

The build can demonstrate webhooks, async investigation, persistence, and replayable demos without spending the hackathon window on operational topology. The runtime should still keep boundaries clear in code so the service can be split later if deployment needs grow.
