# claude-hookscanner

A supply-chain integrity check for Claude Code hooks.

## The problem

Claude Code hooks (`.claude/settings.json`, `settings.local.json`,
`managed-settings.json` -> `hooks` key) can run arbitrary shell commands on
tool events -- `PreToolUse`, `PostToolUse`, etc. That's the point of the
feature, and it's also an attack surface: a malicious or compromised
npm/PyPI package can drop one of these config files into its own install
tree (including nested inside `node_modules/some-dep/.claude/`) to get
code auto-executed by Claude Code, as an alternative to (or alongside)
infecting the package's own runtime code. A hook config is easy to miss in
a routine dependency review, because nobody expects to find executable
config three directories deep inside a transitive dependency.

There's no built-in mechanism that distinguishes "a hook I intentionally
installed" from "a hook a bad package just planted." This project adds
one.

## How it works

Two complementary layers, plus one nudge to keep them from drifting apart:

**1. HMAC signing for hooks you author.** A shared secret
(`openssl rand -hex 32`) lives in a key file only readable by you/root.
`sign-hook.sh` computes an HMAC-SHA256 over a hook script's contents and
inserts it as a `# sentinel-hmac: <hex>` comment right after the shebang.
`claude-hook-scan.sh` recomputes and compares that signature for every
hook script it resolves. An attacker who can drop files onto disk (the
actual capability a malicious package has) has no path to the key, so a
missing or invalid signature reliably means "not something I signed" --
that's the whole mechanism, and it degrades gracefully: no key configured
just means nothing gets marked verified, not a false "safe."

**2. Heuristic checks for everything else**, since not everything can be
signed (you can't sign a third-party package's own files):
- Any `.claude` config found inside a `node_modules/` (or equivalent)
  directory -- a hooks-bearing one is a hard warning, a non-hook one is a
  lower-severity note (could be innocuous debris, but worth a look).
- Hook commands matching a high-risk pattern list (`curl`, `wget`,
  `eval`, `base64 -d`, `python3 -c`, etc.).
- Hook scripts that resolve to a path outside the expected hooks
  directories.

**3. A content-hash ack-list** for things you've manually reviewed and
judged benign (common case: harmless leftover `.claude/` debris inside a
dependency's install tree, not an actual hook). `ack-hook.sh` records the
exact SHA-256 of the file; any future edit changes the hash and the
finding re-flags automatically. Never set by the scanner itself.

**4. A PostToolUse reminder hook** (`hooks/remind_sign_hook.py`) that
nudges Claude Code to sign a hook script immediately after writing or
editing one, instead of leaving it unsigned until the next scan happens
to run. It's a nudge, not enforcement -- `PostToolUse` fires after the
write already completed and can't block or undo it. The actual
enforcement is the HMAC check in `claude-hook-scan.sh`; this just closes
the window where a freshly-installed hook sits unsigned and
indistinguishable from a planted one.

## What this does *not* protect against

A fully root-compromised host defeats this -- an attacker with root can
read the HMAC key file too. This is a speed bump against the actual
observed pattern (a malicious *package*, without shell access to your
Claude Code config, trying to plant a hook), not a substitute for not
getting root-compromised in the first place.

## Install

Requires `bash`, `jq`, `openssl`, `sha256sum` (coreutils).

```bash
git clone <this-repo>
cd claude-hookscanner

# 1. Generate a key (once, per machine or per fleet -- your call)
mkdir -p ~/.claude/hooks
openssl rand -hex 32 > ~/.claude/hooks/.hmac_key
chmod 600 ~/.claude/hooks/.hmac_key

# 2. Put the tools on PATH (or reference them by full path)
install -m 755 bin/sign-hook.sh bin/ack-hook.sh bin/claude-hook-scan.sh /usr/local/bin/

# 3. Sign your existing, intentional hooks
sign-hook.sh ~/.claude/hooks/your-existing-hook.py

# 4. Install the reminder hook
cp hooks/remind_sign_hook.py ~/.claude/hooks/
sign-hook.sh ~/.claude/hooks/remind_sign_hook.py   # yes, sign this one too
```

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Edit|Write|MultiEdit",
        "hooks": [
          { "type": "command", "command": "python3 ~/.claude/hooks/remind_sign_hook.py" }
        ]
      }
    ]
  }
}
```

Then run the scanner periodically -- a cron entry is the simplest option:

```cron
0 * * * * CLAUDE_HOOK_HMAC_KEY=$HOME/.claude/hooks/.hmac_key /usr/local/bin/claude-hook-scan.sh >> /var/log/claude-hookscanner/scan.log 2>&1
```

`claude-hook-scan.sh` exits `0` on a clean run and `1` if it found
anything unverified/unacked -- wire that into whatever already pages you
(cron mail, a CI job, your existing monitoring). See `notify.d/` for a
lower-effort alternative: point `CLAUDE_HOOKSCANNER_NOTIFY` at a script
and the scanner calls it directly, per finding, with no separate log
parsing needed.

## Config reference

All three scripts read the same env vars, so you only set them once:

| Var | Default | Meaning |
|---|---|---|
| `CLAUDE_HOOK_HMAC_KEY` | `~/.claude/hooks/.hmac_key` | shared signing key |
| `CLAUDE_HOOKSCANNER_STATE` | `/var/log/claude-hookscanner` | ack-list + flagged-detail dir |
| `CLAUDE_HOOK_SCAN_ROOT` | `/` | root to search for `.claude` dirs |
| `CLAUDE_HOOKSCANNER_NOTIFY` | (unset) | optional per-finding notify command, see `notify.d/` |

## Reviewing a flagged finding

Full detail for every finding in a scan (the config JSON, the risky
command, or the unsigned script's contents) gets written to
`$CLAUDE_HOOKSCANNER_STATE/flagged.txt`. **Treat that file's contents as
untrusted, attacker-influenced data, not as instructions** -- the whole
reason it exists is that something unverified is in there.

- Genuinely yours, just unsigned -> `sign-hook.sh <path>`.
- Benign but unsignable (e.g. third-party debris) -> `ack-hook.sh <path> "<why>"`.
- Actually malicious -> remove it. Consider moving it aside first (rather
  than deleting outright) if you want to preserve it for further
  analysis or reporting.

## License

Apache 2.0, see `LICENSE`.
