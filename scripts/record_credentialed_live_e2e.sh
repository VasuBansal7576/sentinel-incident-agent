#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mkdir -p .sentinel
run_id="${SENTINEL_LIVE_RUN_ID:-$(date +%s)}"
terminal_log=".sentinel/live-run-${run_id}.log"
structured_log=".sentinel/live-run-${run_id}.structured.log"

echo "SENTINEL credentialed live E2E recording"
echo "terminal_log: ${terminal_log}"
echo "structured_log: ${structured_log}"
echo "Secrets are entered in the Python prompts; getpass values are not echoed."

set +e
python3 scripts/run_credentialed_live_e2e.py --log-path "$structured_log" "$@" 2>&1 | tee "$terminal_log"
status=${PIPESTATUS[0]}
set -e

{
  echo "structured_log: ${structured_log}"
  echo "terminal_log: ${terminal_log}"
  echo "exit_status: ${status}"
} | tee -a "$terminal_log"

exit "$status"
