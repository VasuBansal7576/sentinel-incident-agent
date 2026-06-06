# SENTINEL Submission Checklist

- [x] GitHub repo public
- [ ] Video recorded (3-5 min)
- [x] Codex traces exported
- [x] MEMO.md one page
- [x] Live proof doc
- [x] Model-driven proof
- [x] Subagent proof
- [x] Fresh demo summary (37 calls)

## Current Local Evidence

- Fresh deterministic summary: `.sentinel/recording-demo-summary.json`
- Fresh deterministic count: `37` tool calls, `26` plan steps, `completed`
- Full local native trace: `codex-traces.jsonl` with `13,834` lines
- Public-safe redacted trace: `codex-traces-redacted.jsonl`
- Live proof: `docs/live-proof.md`
- Model planner proof: `docs/model-driven-proof.md`
- Subagent proof: `docs/subagent-proof.md`
- Video plan: `docs/video-strategy.md`

## Trace Warning

`codex-traces.jsonl` is the full native trace for email submission and is intentionally ignored by git. Do not submit only `codex-traces-redacted.jsonl`; the redacted file is for public repo review convenience.
