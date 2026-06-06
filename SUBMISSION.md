# SENTINEL Submission Checklist

- **GitHub repository URL:** https://github.com/VasuBansal7576/sentinel-incident-agent
- **Video file location:** `./sentinel-walkthrough.mp4` after recording from `VIDEO_SCRIPT.md`
- **Video script:** `VIDEO_SCRIPT.md`
- **Codex traces export path:** `/Users/vasu/.codex/sessions/2026/06/05/rollout-2026-06-05T22-46-23-019e98c9-362b-7813-b539-bca25c6e5745.jsonl`
- **MEMO confirmation:** MEMO.md is present at the repository root and describes the build, cuts, future work, defended design decision, and model-driven tool-selection defense.

## Final Local Proof Commands

```bash
pytest -q
docker compose config -q
python3 -m compileall -q sentinel scripts tests
python3 scripts/run_real_slow_query_incident.py --summary-output .sentinel/real-slow-query-summary.json
```

## Submission Notes

- Deterministic proof: 26-step long-horizon investigation with 35 tool calls.
- Live proof: Prometheus metrics, Loki logs, missing-index diagnosis, human approval, `idx_orders_user_id` creation, verified latency fix, and Discord timeline.
- Local secrets and generated proof artifacts are intentionally excluded from Git by `.gitignore`.
