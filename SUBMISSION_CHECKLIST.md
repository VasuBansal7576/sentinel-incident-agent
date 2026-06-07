# SENTINEL Submission Checklist

- [x] GitHub repo public
- [ ] Video recorded (3-5 min)
- [x] Codex traces exported
- [x] MEMO.md one page
- [x] Live proof doc
- [x] Model-driven proof
- [x] Subagent proof
- [x] Fresh demo summary (37 calls)
- [x] Native trace path documented for email attachment
- [x] Native trace verified over 10MB
- [x] Public redacted trace labelled as non-substitute
- [x] Live proof scope limited to Prometheus/Loki/kind/SQLite/Discord
- [x] Final video script aligned with Groq model proof

## Current Local Evidence

- Fresh deterministic summary: `.sentinel/recording-demo-summary.json`
- Fresh deterministic count: `37` tool calls, `26` plan steps, `completed`
- Native trace for email attachment: `/Users/vasu/.codex/sessions/2026/06/05/rollout-2026-06-05T22-46-23-019e98c9-362b-7813-b539-bca25c6e5745.jsonl`
- Full local native trace copy: `codex-traces.jsonl` with `13,834` lines and `28,702,265` bytes
- Public-safe redacted trace: `codex-traces-redacted.jsonl`
- Live proof: `docs/live-proof.md`
- Model planner proof: `docs/model-driven-proof.md` with Groq `llama-3.3-70b-versatile`, parsed model response, model reasoning, and eligible planner return
- Subagent proof: `docs/subagent-proof.md` with isolated context, observe/repo scoped tools, denied infra/comms tools, and parent `ServiceIncidentReport` reconciliation
- Video plan: `docs/video-strategy.md`
- Video script: `VIDEO_SCRIPT.md`

## Trace Warning

`codex-traces.jsonl` is the full native trace for email submission and is intentionally ignored by git. Do not submit only `codex-traces-redacted.jsonl`; the redacted file is for public repo review convenience.

## Email Attachment Warning

Before replying to the assignment thread, attach the native Codex JSONL and the recorded video file. The public GitHub repository and root `MEMO.md` are not enough by themselves because `problem.md` explicitly asks for four returned artifacts.
