#!/bin/bash
# Signs a Claude Code hook script with an HMAC-SHA256 keyed to a shared
# secret, inserted as a "# sentinel-hmac: <hex>" comment on the line right
# after the shebang (or as line 1 if there isn't one).
#
# Run this any time you install a new Claude Code hook, or legitimately
# edit an existing one's content. The old signature will no longer match
# new content by design -- that's not a bug, that's what catches tampering.
#
# Config (env vars, all optional):
#   CLAUDE_HOOK_HMAC_KEY  -- path to the shared HMAC key file
#                            (default: below -- install.sh rewrites this to a
#                            randomized, non-default location; running from a
#                            plain git checkout without install.sh falls back
#                            to the conventional path shown here)
set -euo pipefail

# INSTALL_DEFAULT_KEY_FILE -- install.sh rewrites the line below in place.
KEY_FILE_DEFAULT="$HOME/.claude/hooks/.hmac_key"
KEY_FILE="${CLAUDE_HOOK_HMAC_KEY:-$KEY_FILE_DEFAULT}"
TARGET="${1:?usage: sign-hook.sh <script-path>}"

if [ ! -f "$KEY_FILE" ]; then
  echo "no HMAC key at $KEY_FILE -- generate one first:" >&2
  echo "  mkdir -p \"\$(dirname "$KEY_FILE")\" && openssl rand -hex 32 > \"$KEY_FILE\" && chmod 600 \"$KEY_FILE\"" >&2
  exit 1
fi
[ -f "$TARGET" ] || { echo "no such file: $TARGET" >&2; exit 1; }

tmp=$(mktemp)
trap 'rm -f "$tmp" "${TARGET}.new"' EXIT

# Strip any existing signature line -- the HMAC covers everything else,
# including the shebang, so sign and verify always agree on what's covered.
grep -v -E '^# sentinel-hmac: [0-9a-f]{64}$' "$TARGET" > "$tmp"

key=$(cat "$KEY_FILE")
sig=$(openssl dgst -sha256 -hmac "$key" "$tmp" | awk '{print $NF}')

{
  if head -1 "$tmp" | grep -q '^#!'; then
    head -1 "$tmp"
    echo "# sentinel-hmac: $sig"
    tail -n +2 "$tmp"
  else
    echo "# sentinel-hmac: $sig"
    cat "$tmp"
  fi
} > "${TARGET}.new"

chmod --reference="$TARGET" "${TARGET}.new"
chown --reference="$TARGET" "${TARGET}.new" 2>/dev/null || true
mv "${TARGET}.new" "$TARGET"
echo "signed: $TARGET (sha256hmac=$sig)"
