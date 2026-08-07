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
                           (default: below -- install.sh rewrites this to a
                           randomized, non-default location)
  CLAUDE_HOOK_NOTIFY    -- optional command to invoke when an unsigned hook
                           is found, in addition to the in-session nudge.
                           Called as: notify <severity> <finding_type>
                           <path> <detail> -- same four-argument shape as
                           claude-hook-scan.sh's CLAUDE_HOOKSCANNER_NOTIFY,
                           see notify.d/ for the contract + examples. Fires
                           with finding_type="unsigned_hook". Best-effort:
                           a failing/slow notifier never blocks or delays
                           the tool result beyond a short timeout.
"""
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HOOK_DIR_PATTERNS = [
    re.compile(r"/\.claude/hooks/"),
    re.compile(r"/\.claude/plugins/"),
]

SIG_LINE_RE = re.compile(r"^# sentinel-hmac: ([0-9a-f]{64})$")

# INSTALL_DEFAULT_KEY_FILE -- install.sh rewrites the line below in place.
KEY_FILE_DEFAULT = str(Path.home() / ".claude/hooks/.hmac_key")


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

    key_file = os.environ.get("CLAUDE_HOOK_HMAC_KEY", KEY_FILE_DEFAULT)

    if not os.path.isfile(key_file):
        # No key provisioned on this machine -- nothing to nudge about.
        sys.exit(0)

    if verify_hmac(file_path, key_file):
        sys.exit(0)

    notify_cmd = os.environ.get("CLAUDE_HOOK_NOTIFY", "")
    if notify_cmd:
        try:
            subprocess.run(
                [notify_cmd, "high", "unsigned_hook", file_path,
                 "written via Claude Code PostToolUse, HMAC signature missing or invalid"],
                timeout=8, capture_output=True,
            )
        except Exception:
            pass  # best-effort -- never let a slow/failing notifier block the tool result

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
