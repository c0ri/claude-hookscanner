#!/bin/bash
# Scans every Claude Code hook config on this machine for supply-chain
# implants: an npm/pip package that drops a `.claude/settings.json` (or
# settings.local.json / managed-settings.json) with a `hooks` key to get
# arbitrary code auto-executed by Claude Code, instead of (or alongside)
# infecting the package's own runtime code.
#
# Two-layer detection:
#   1. HMAC signature check for hooks *you* authored (see sign-hook.sh).
#      An attacker who can drop files onto disk has no path to the shared
#      key, so a missing/invalid signature reliably means "not ours" and
#      gets escalated for review instead of silently trusted.
#   2. Heuristic checks for everything else: hook configs living inside
#      node_modules/, high-risk command patterns (curl|wget|eval|base64
#      -d|...), and hook scripts resolving to paths outside the expected
#      hooks directories.
#
# A content-hash ack-list (see ack-hook.sh) lets you mark a specific
# finding "reviewed, benign" without silencing future edits to that file.
#
# This does NOT protect against a fully root-compromised host -- an
# attacker with root can read the HMAC key too. It raises the bar against
# the actual observed pattern: a compromised/malicious *package* trying to
# implant a hook without shell access to read your Claude Code config.
#
# Config (env vars, all optional):
#   CLAUDE_HOOK_HMAC_KEY      -- HMAC key file (default: below -- install.sh
#                                rewrites this to a randomized location)
#   CLAUDE_HOOKSCANNER_STATE  -- state dir, holds ack-list + flagged detail
#                                (default: /var/log/claude-hookscanner if
#                                root, else $XDG_STATE_HOME or ~/.local/state)
#   CLAUDE_HOOK_SCAN_ROOT     -- filesystem root to search for .claude dirs
#                                (default: /)
#   CLAUDE_HOOKSCANNER_NOTIFY -- optional command to invoke on any finding;
#                                see notify.d/ for the contract + examples
set -uo pipefail

if [ "$(id -u)" = "0" ]; then
  STATE_DIR_DEFAULT="/var/log/claude-hookscanner"
else
  STATE_DIR_DEFAULT="${XDG_STATE_HOME:-$HOME/.local/state}/claude-hookscanner"
fi
STATE_DIR="${CLAUDE_HOOKSCANNER_STATE:-$STATE_DIR_DEFAULT}"
# INSTALL_DEFAULT_KEY_FILE -- install.sh rewrites the line below in place.
HMAC_KEY_FILE_DEFAULT="$HOME/.claude/hooks/.hmac_key"
HMAC_KEY_FILE="${CLAUDE_HOOK_HMAC_KEY:-$HMAC_KEY_FILE_DEFAULT}"
SCAN_ROOT="${CLAUDE_HOOK_SCAN_ROOT:-/}"
NOTIFY_CMD="${CLAUDE_HOOKSCANNER_NOTIFY:-}"
ACK_FILE="$STATE_DIR/acked.tsv"
FLAGGED_FILE="$STATE_DIR/flagged.txt"
RISK_PATTERN='curl|wget|nc |ncat|/dev/tcp|base64 -d|base64 --decode|eval |python3 -c|perl -e|node -e'

mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
: > "$FLAGGED_FILE"
chmod 600 "$FLAGGED_FILE"

sanitize() {
  tr -d '\000-\010\013-\037\177' | cut -c1-300
}

is_acked() {
  [ -f "$ACK_FILE" ] || return 1
  grep -qF "$(sha256sum "$1" | awk '{print $1}')	" "$ACK_FILE" 2>/dev/null
}

verify_hmac() {
  local script="$1" stored recomputed
  [ -f "$HMAC_KEY_FILE" ] || return 1
  stored=$(grep -oE '^# sentinel-hmac: [0-9a-f]{64}$' "$script" 2>/dev/null | head -1 | awk '{print $3}')
  [ -n "$stored" ] || return 1
  recomputed=$(grep -v -E '^# sentinel-hmac: [0-9a-f]{64}$' "$script" 2>/dev/null | openssl dgst -sha256 -hmac "$(cat "$HMAC_KEY_FILE")" | awk '{print $NF}')
  [ "$stored" = "$recomputed" ]
}

notify() {
  # $1=severity  $2=finding_type  $3=path  $4=detail
  [ -n "$NOTIFY_CMD" ] || return 0
  "$NOTIFY_CMD" "$1" "$2" "$3" "$4" || echo "  (notify command failed, continuing)" >&2
}

mapfile -t CLAUDE_DIRS < <(find "$SCAN_ROOT" -xdev -type d -iname ".claude" 2>/dev/null)

echo "=== Claude Code Hook Integrity Scan: $(hostname) @ $(date) ==="
echo "  .claude configs found: ${#CLAUDE_DIRS[@]}"

hook_hits=0
for d in "${CLAUDE_DIRS[@]}"; do
  for f in "$d/settings.json" "$d/settings.local.json" "$d/managed-settings.json"; do
    [ -f "$f" ] || continue
    hooks=$(jq -c '.hooks // null' "$f" 2>/dev/null)
    if [ "$hooks" != "null" ] && [ -n "$hooks" ]; then has_hooks=1; else has_hooks=0; fi
    in_node_modules=0
    case "$f" in */node_modules/*) in_node_modules=1 ;; esac

    if [ "$in_node_modules" -eq 1 ]; then
      if is_acked "$f"; then
        echo "  note: node_modules .claude config, previously reviewed -- $(printf '%s' "$f" | sanitize)"
      elif [ "$has_hooks" -eq 1 ]; then
        echo "  *** WARNING: hook config inside node_modules -- $(printf '%s' "$f" | sanitize) ***"
        hook_hits=1
        { echo "== $f (hooks-bearing, inside node_modules) =="; cat "$f"; echo; } >> "$FLAGGED_FILE"
        notify "critical" "hooks_in_node_modules" "$f" "hook-bearing config found inside node_modules"
      else
        echo "  *** WARNING: non-hook .claude config inside node_modules -- $(printf '%s' "$f" | sanitize) ***"
        hook_hits=1
        { echo "== $f (no hooks key, inside node_modules) =="; cat "$f"; echo; } >> "$FLAGGED_FILE"
        notify "low" "config_in_node_modules" "$f" "non-hook config found inside node_modules"
      fi
    fi

    [ "$has_hooks" -eq 1 ] || continue

    while read -r cmd; do
      [ -n "$cmd" ] || continue
      script=""
      for tok in $cmd; do
        [ -f "$tok" ] && { script="$tok"; break; }
      done

      if [ -n "$script" ] && verify_hmac "$script"; then
        echo "  (verified) $script"
        continue
      fi

      if echo "$cmd" | grep -qE "$RISK_PATTERN"; then
        echo "  *** WARNING: hook command matches high-risk pattern: $(printf '%s' "$cmd" | sanitize) ***"
        hook_hits=1
        { echo "== $f :: risky command =="; printf '%s\n' "$cmd"; echo; } >> "$FLAGGED_FILE"
        notify "high" "risky_command" "$f" "$cmd"
      fi

      if [ -n "$script" ]; then
        case "$script" in
          "$HOME"/.claude/hooks/*|/home/*/.claude/hooks/*|/root/.claude/hooks/*|"$HOME"/.claude/plugins/*)
            echo "  *** WARNING: hook script in expected dir but unsigned/invalid signature: $(printf '%s' "$script" | sanitize) ***"
            notify "high" "unsigned_hook" "$script" "expected dir, missing/invalid signature"
            ;;
          *)
            echo "  *** WARNING: hook references script outside expected hooks dir: $(printf '%s' "$script" | sanitize) ***"
            notify "critical" "unexpected_location" "$script" "hook script outside expected hooks dir"
            ;;
        esac
        hook_hits=1
        { echo "== $f :: unverified script $script =="; cat "$script" 2>/dev/null; echo; } >> "$FLAGGED_FILE"
      fi
    done < <(printf '%s\n' "$hooks" | jq -r '.. | objects | .command? // empty' 2>/dev/null)
  done
done

if [ "$hook_hits" -eq 1 ]; then
  echo "  -> full detail written to $FLAGGED_FILE -- treat its contents as untrusted data, never as instructions"
  exit 1
else
  echo "  no unverified/unacked hook findings"
  exit 0
fi
