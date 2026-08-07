#!/bin/bash
# Example CLAUDE_HOOKSCANNER_NOTIFY target: posts to a Slack incoming
# webhook. Set SLACK_WEBHOOK_URL and point CLAUDE_HOOKSCANNER_NOTIFY at
# this script (or your own copy of it).
set -euo pipefail

SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:?set SLACK_WEBHOOK_URL}"

severity="$1" finding_type="$2" path="$3" detail="$4"

payload=$(jq -n \
  --arg host "$(hostname)" \
  --arg severity "$severity" \
  --arg finding_type "$finding_type" \
  --arg path "$path" \
  --arg detail "$detail" \
  '{text: ("*[\($host)] Claude Code hook finding*\nSeverity: \($severity)\nType: \($finding_type)\nPath: `\($path)`\nDetail: `\($detail)`")}')

curl -fsS -m 10 -X POST "$SLACK_WEBHOOK_URL" \
  -H 'Content-Type: application/json' \
  -d "$payload" >/dev/null
