# Notification extension point

`claude-hook-scan.sh` will call whatever you set `CLAUDE_HOOKSCANNER_NOTIFY`
to, once per finding, with four positional arguments:

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

Set the env var before running the scanner:

```bash
export CLAUDE_HOOKSCANNER_NOTIFY=/path/to/your/notifier.sh
claude-hook-scan.sh
```

If a notifier command fails, the scan continues and still exits non-zero
on any finding -- notification delivery is best-effort, it should never be
the reason a real finding gets silently dropped from cron/CI output.
