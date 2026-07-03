#!/bin/bash
# A.R.G.U.S. dev hook (PostToolUse: Edit|Write).
# After an edit to a *portable* Phase-1 module, run its own __main__ smoke
# test and hand a failure back to Claude so it gets fixed before moving on —
# every ARGUS module already has a standalone __main__ test block per the
# root CLAUDE.md coding standard, so this just automates what session logs
# show being run by hand after every change.
#
# Windows-locked modules (gate_keeper.py, daemon.py — see CLAUDE.local.md's
# platform-coupling table) are deliberately skipped: their __main__ blocks
# shell out to icacls/MpCmdRun, which don't exist on Linux. A failure there
# would be the platform, not the edit — exactly the false signal
# CLAUDE.local.md warns against ("a mock passing on Linux is NOT the Windows
# feature working" — the inverse holds too).

INPUT=$(cat)
FILE=$(printf '%s' "$INPUT" | jq -r '.tool_input.file_path // empty' 2>/dev/null)
[ -z "$FILE" ] && exit 0

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$PWD}"
REL="${FILE#"$PROJECT_DIR"/}"

MODULE=""
case "$REL" in
  argus/core/logger.py)                MODULE="argus.core.logger" ;;
  argus/monitors/file_watcher.py)      MODULE="argus.monitors.file_watcher" ;;
  argus/monitors/email_scanner.py)     MODULE="argus.monitors.email_scanner" ;;
  argus/analysis/feature_extractor.py) MODULE="argus.analysis.feature_extractor" ;;
  argus/core/gate_keeper.py|argus/core/daemon.py)
    echo "Note: $REL is Windows-locked (CLAUDE.local.md) — __main__ not auto-run on Linux. Verify manually on the Windows boot." >&2
    exit 0
    ;;
  *)
    exit 0
    ;;
esac

PY="$PROJECT_DIR/.venv-linux/bin/python"
[ -x "$PY" ] || PY="$PROJECT_DIR/.venv/bin/python"
[ -x "$PY" ] || PY="python3"

OUTPUT=$(cd "$PROJECT_DIR" 2>/dev/null && timeout 30 "$PY" -m "$MODULE" 2>&1)
RC=$?

if [ "$RC" -eq 0 ]; then
  echo "self-test passed: $MODULE" >&2
  exit 0
fi

TAIL=$(printf '%s\n' "$OUTPUT" | tail -30)
REASON="Editing $REL broke its own __main__ smoke test (python -m $MODULE exited $RC):
$TAIL"
jq -n --arg reason "$REASON" '{"decision": "block", "reason": $reason}'
exit 0
