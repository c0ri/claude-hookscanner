# claude-hookscanner

A supply-chain integrity check for Claude Code hooks.

Built by the team behind [Sentinel AI Firewall](https://sentinelaifirewall.com).

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

`install.sh` deliberately does *not* put the key at a fixed, predictable
path (the old `~/.claude/hooks/.hmac_key` convention) -- it generates a
random hidden directory under `$HOME` (or a path you choose) and bakes
the resolved path into each installed script's own default, instead of
exporting it through a shell rc file or env var. See "What this does not
protect against" below for exactly what that buys you and what it
doesn't.

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
indistinguishable from a planted one. It has its own notify hook,
`CLAUDE_HOOK_NOTIFY`, same shape and contract as `claude-hook-scan.sh`'s
-- see the Config reference table and `notify.d/` -- for alerting the
instant an unsigned hook shows up, rather than waiting on the next
scheduled scan.

## What this does *not* protect against

A fully root-compromised host defeats this -- an attacker with root can
read the HMAC key file too. This is a speed bump against the actual
observed pattern (a malicious *package*, without shell access to your
Claude Code config, trying to plant a hook), not a substitute for not
getting root-compromised in the first place.

Be precise about what the random key-directory trick (see Install below)
does and doesn't buy you, too. It's aimed at **opportunistic, "drive-by"
supply-chain worms** -- generic malware payloads that hardcode a short
list of well-known filenames (`.aws/credentials`, `id_rsa`, `.hmac_key`,
...) and try them across every victim they land on, because a lightweight
non-interactive payload that doesn't do a real directory listing is
cheaper to write and less likely to trip something on the way in. Against
that class of attacker, a key that isn't sitting at the one path
everyone's install guide says to check is a real improvement.

It does **not** meaningfully defend against a targeted attacker who reads
this repo and runs `ls -la ~/.claude/hooks/ ; find $HOME -maxdepth 2 -type
f` -- a lone 64-character hex file is identifiable by shape and location
regardless of what it's named or which directory it's in, once someone's
actually looking. Don't repeat the "randomized + obscure" framing as if
it were access control; it's raising the cost of the cheap, common attack,
not closing the door on a determined one. Real access control (OS
keychain/keyring integration, so the key requires more than same-user
file-read to retrieve) is a documented future direction, not implemented
yet.

## Install

Requires `bash`, `jq`, `openssl`, GNU coreutils (`sha256sum`, `chmod`/
`chown --reference`, GNU `date`), and bash 4+ (`mapfile`). **Linux only
right now** -- macOS's stock userland has none of the above by default
(BSD `date`/`chmod`/`chown` don't support the flags used here, there's no
`sha256sum` binary, and `/bin/bash` is stuck at 3.2 for GPLv3 licensing
reasons), so this will fail partway through, not cleanly refuse to run.
Portable macOS support is a known gap, not yet done -- see the repo
issues before assuming it works. Windows: run it under WSL, which is
Linux underneath and unaffected by any of this.

```bash
git clone <this-repo>
cd claude-hookscanner
./install.sh
```

It will:
1. Ask where to store the HMAC key -- an auto-generated random hidden
   directory under `$HOME` (recommended) or a path you specify. Re-running
   it later reuses whatever key it finds already installed rather than
   silently rotating and orphaning it; pass `--key-dir=PATH` if you
   actually want to rotate.
2. Install `sign-hook.sh` / `ack-hook.sh` / `claude-hook-scan.sh` to a bin
   directory of your choice, and the PostToolUse reminder hook to
   `~/.claude/hooks/`, with that key path baked into each installed
   copy's default.
3. Sign the reminder hook itself, and offer to merge the PostToolUse entry
   into `~/.claude/settings.json` (backing it up first) if `jq` is
   available -- otherwise it prints the JSON snippet to add by hand.
4. Ask whether to add a cron entry (hourly, daily, or skip) for periodic
   scanning. This matters: the reminder hook only catches hooks written
   *through* a Claude Code session -- a hook planted some other way (a
   raw `npm install` run outside a session, or anything dropped directly
   onto disk) is invisible to it and needs an actual periodic scan to be
   caught at all. Re-running the installer replaces any existing
   `claude-hookscanner`-tagged cron line rather than duplicating it, and
   never touches any of your other cron entries.
5. Run a scan so you can see it working immediately.

Non-interactive use (CI, config management, scripted fleet rollout):
`./install.sh --yes [--key-dir=PATH] [--bin-dir=PATH] [--with-cron=hourly|daily]`.
Cron is off by default under `--yes` unless you pass `--with-cron`
explicitly -- adding a cron entry is a bigger footprint than anything
else this installer does and shouldn't happen silently.

Then sign whatever other hooks you already had:

```bash
sign-hook.sh ~/.claude/hooks/your-existing-hook.py
```

If you skipped cron during install (or want to change the schedule
later), add or edit it yourself -- no need to re-run the installer just
for this:

```cron
0 * * * * /usr/local/bin/claude-hook-scan.sh >> /path/to/scan.log 2>&1
```

No need to pass `CLAUDE_HOOK_HMAC_KEY` explicitly -- `install.sh` already
baked the resolved key path into the installed copy of
`claude-hook-scan.sh` as its default. Only set that env var if you're
intentionally overriding it (e.g. running the tool straight from a repo
checkout without installing it).

`claude-hook-scan.sh` exits `0` on a clean run and `1` if it found
anything unverified/unacked -- wire that into whatever already pages you
(cron mail, a CI job, your existing monitoring). See `notify.d/` for a
lower-effort alternative: point `CLAUDE_HOOKSCANNER_NOTIFY` at a script
and the scanner calls it directly, per finding, with no separate log
parsing needed.

### Uninstall

```bash
./install.sh --uninstall
```

You don't need to have written down the random key directory -- uninstall
finds it the same way a repeat install-run does: by reading the baked-in
default back out of `~/.claude/hooks/remind_sign_hook.py`, whose location
is conventionally fixed anyway. It falls back to prompting for the
directory only if that file's already gone (or pass `--key-dir=PATH`
directly). It only ever removes files that carry our install marker --
a same-named file that isn't actually ours is left alone -- and only
`rmdir`s the key's containing directory when it matches the
auto-generated naming pattern, never a custom `--key-dir` you pointed it
at, since that could be a directory you use for other things.

Ack-list and scan history are kept by default (it's an audit trail, not
something to silently destroy); add `--purge-state` to remove that too.
Non-interactive: `./install.sh --uninstall --yes [--purge-state]`.
`--uninstall` also removes any `claude-hookscanner`-tagged cron entry,
without touching any of your other cron jobs.

## Config reference

All three scripts read the same env vars, so you only set them once. Each
one overrides a default that `install.sh` already customized for your
machine (the key path) or that adapts automatically (the state dir, based
on whether you're root) -- you generally shouldn't need to set any of
these by hand.

| Var | Default | Meaning |
|---|---|---|
| `CLAUDE_HOOK_HMAC_KEY` | baked in by `install.sh`; `~/.claude/hooks/.hmac_key` if run from source | shared signing key |
| `CLAUDE_HOOKSCANNER_STATE` | `/var/log/claude-hookscanner` if root, else `~/.local/state/claude-hookscanner` | ack-list + flagged-detail dir |
| `CLAUDE_HOOK_SCAN_ROOT` | `/` | root to search for `.claude` dirs |
| `CLAUDE_HOOKSCANNER_NOTIFY` | (unset) | optional per-finding notify command for `claude-hook-scan.sh`, see `notify.d/` |
| `CLAUDE_HOOK_NOTIFY` | (unset) | same contract as above, but for `remind_sign_hook.py` -- fires the instant an unsigned hook is written, not just on the next scan |

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

## About

This came out of hardening our own Claude Code fleet against supply-chain
hook implants. It covers one specific vector -- a planted hook script --
and deliberately doesn't try to cover more than that (see "What this does
*not* protect against" above). It has nothing to do with, and doesn't
require, prompt-injection or data-exfiltration defense at the LLM-traffic
level -- that's a different, broader problem, which is what we built
[Sentinel AI Firewall](https://sentinelaifirewall.com) to address. Two
separate tools for two separate threats in the same general space.

## License

Apache 2.0, see `LICENSE`.
