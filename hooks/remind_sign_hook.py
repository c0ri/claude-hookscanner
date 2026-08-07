#!/usr/bin/env python3
"""PostToolUse hook (matcher: Edit|Write|MultiEdit): nudges Claude to sign a
Claude Code hook script immediately after it's created or edited, instead of
relying on the next periodic claude-hook-scan.sh run to catch it.

This is a reminder, not an enforcement mechanism -- PostToolUse fires after
the write already happened and can't block or undo it. Enforcement is the
HMAC verification in claude-hook-scan.sh; this just closes the gap where a
hook sits unsigned (and unflagged as "ours") until the next scan.

Config (env vars, all optional):
  CLAUDE_HOOK_HMAC_KEY  -- path to the shared HMAC key file
                           (default: ~/.claude/hooks/.hmac_key)
"""
import hashlib
import hmac
import json
import os
import re
import sys
from pathlib import Path

HOOK_DIR_PATTERNS = [
    re.compile(r"/\.claude/hooks/"),
    re.compile(r"/\.claude/plugins/"),
]

SIG_LINE_RE = re.compile(r"^# sentinel-hmac: ([0-9a-f]{64})$")


def looks_like_hook_script(path: str) -> bool:
    if not path.endswith((".py", ".sh", ".bash")):
        return False
    return any(p.search(path) for p in HOOK_DIR_PATTERNS)


def verify_hmac(path: str, key_file: str) -> bool:
    try:
        key = Path(key_file).read_bytes().strip()
        content = Path(path).read_text()
    except OSError:
        return False

    stored = None
    kept_lines = []
    # Mirror sign-hook.sh's `grep -v -E '^# sentinel-hmac: ...$'`: the
    # signature line is removed as a whole unit, terminator included, not
    # just its text -- otherwise the recomputed HMAC covers a blank line
    # bash's grep never produced, and every correctly-signed hook fails
    # verification here.
    for line in content.splitlines(keepends=True):
        m = SIG_LINE_RE.match(line.rstrip("\n"))
        if m and stored is None:
            stored = m.group(1)
            continue
        kept_lines.append(line)

    if stored is None:
        return False

    stripped = "".join(kept_lines)
    recomputed = hmac.new(key, stripped.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(stored, recomputed)


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    file_path = data.get("tool_input", {}).get("file_path", "")
    if not file_path or not looks_like_hook_script(file_path):
        sys.exit(0)

    key_file = os.environ.get("CLAUDE_HOOK_HMAC_KEY", str(Path.home() / ".claude/hooks/.hmac_key"))

    if not os.path.isfile(key_file):
        # No key provisioned on this machine -- nothing to nudge about.
        sys.exit(0)

    if verify_hmac(file_path, key_file):
        sys.exit(0)

    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": (
                f"You just wrote/edited a Claude Code hook script at {file_path}, "
                "which doesn't carry a valid HMAC signature. If this is a hook you "
                "authored intentionally, sign it now so the integrity scanner "
                f"recognizes it: sign-hook.sh {file_path}"
            ),
        }
    }))
    sys.exit(0)


if __name__ == "__main__":
    main()
