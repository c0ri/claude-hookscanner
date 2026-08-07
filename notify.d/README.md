# Notification extension point

Two independent hooks share the same four-argument contract:

- `claude-hook-scan.sh` calls whatever you set `CLAUDE_HOOKSCANNER_NOTIFY`
  to, once per finding during a scan.
- `hooks/remind_sign_hook.py` calls whatever you set `CLAUDE_HOOK_NOTIFY`
  to, immediately when it catches an unsigned hook on write -- `PostToolUse`
  fires in real time, so this is the faster of the two to hear about a
  problem from, at the cost of only covering hooks written through a
  Claude Code session (a hook planted some other way still needs a scan).

Either way, the notifier command is called with:

```
$1  severity       low | high | critical
$2  finding_type   config_in_node_modules | hooks_in_node_modules |
                   risky_command | unsigned_hook | unexpected_location
$3  path           the file the finding is about
$4  detail         free-text detail (a command string, or a fixed reason)
```

It's a plain command, not a shape-specific webhook client -- wire it to
whatever you already use for alerting. Two starting points are included
here:

- `webhook-example.sh` -- POSTs a JSON payload to a generic HTTP endpoint.
- `slack-example.sh` -- posts to a Slack incoming webhook URL.

Treat `$3`/`$4` as untrusted, attacker-influenced strings when building
your own notifier (a malicious hook's command line is exactly the kind of
content this scanner exists to flag) -- don't `eval` them, and escape them
for whatever transport you're using (HTML, JSON, shell).

For the scanner, set the env var before running it:

```bash
export CLAUDE_HOOKSCANNER_NOTIFY=/path/to/your/notifier.sh
claude-hook-scan.sh
```

For the reminder hook, set it on the hook's own `command` line in
`~/.claude/settings.json` instead of (or in addition to) exporting it in
your shell -- the hook process inherits whatever environment the Claude
Code process itself was started with, which won't necessarily match a
variable you `export` in a shell session afterward, so putting it
directly on the command line guarantees it takes effect regardless of how
Claude Code was launched:

```json
{ "type": "command", "command": "CLAUDE_HOOK_NOTIFY=/path/to/your/notifier.sh python3 ~/.claude/hooks/remind_sign_hook.py" }
```

If a notifier command fails, the caller continues regardless -- the scan
still exits non-zero on any finding, and the reminder hook still emits its
in-session nudge. Notification delivery is best-effort, it should never be
the reason a real finding gets silently dropped or the primary flow gets
blocked/delayed.
