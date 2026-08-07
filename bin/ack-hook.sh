#!/bin/bash
# Records a manual "reviewed, judged benign" decision for a Claude Code
# hook/config file that can't be signed (e.g. something inside a
# node_modules install, not something you authored) -- keyed by exact
# content hash, so any future edit to the file drops it back out of the
# ack-list and it re-flags on the next scan. Fail-closed by construction.
#
# Never invoked automatically by claude-hook-scan.sh -- this is a
# deliberate manual step you run after actually reviewing the file.
#
# Config (env vars, all optional):
#   CLAUDE_HOOKSCANNER_STATE  -- state directory
#                                (default: /var/log/claude-hookscanner if
#                                root, else $XDG_STATE_HOME or ~/.local/state)
set -euo pipefail

if [ "$(id -u)" = "0" ]; then
  STATE_DIR_DEFAULT="/var/log/claude-hookscanner"
else
  STATE_DIR_DEFAULT="${XDG_STATE_HOME:-$HOME/.local/state}/claude-hookscanner"
fi
STATE_DIR="${CLAUDE_HOOKSCANNER_STATE:-$STATE_DIR_DEFAULT}"
ACK_FILE="$STATE_DIR/acked.tsv"
TARGET="${1:?usage: ack-hook.sh <path> \"<note>\"}"
NOTE="${2:?usage: ack-hook.sh <path> \"<note>\"}"

[ -f "$TARGET" ] || { echo "no such file: $TARGET" >&2; exit 1; }

mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
touch "$ACK_FILE"
chmod 600 "$ACK_FILE"

hash=$(sha256sum "$TARGET" | awk '{print $1}')

if grep -q "^$hash	" "$ACK_FILE" 2>/dev/null; then
  echo "already ack'd (hash $hash) -- no change"
  exit 0
fi

printf '%s\t%s\t%s\t%s\n' "$hash" "$TARGET" "$(date -Iseconds)" "$NOTE" >> "$ACK_FILE"
echo "ack'd: $TARGET (sha256=$hash)"
