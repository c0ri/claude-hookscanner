#!/bin/bash
# Example CLAUDE_HOOKSCANNER_NOTIFY target: POSTs a JSON payload to a
# generic HTTP endpoint. Copy this, point WEBHOOK_URL at your own
# ingestion endpoint (PagerDuty, a custom receiver, etc.), and set
# CLAUDE_HOOKSCANNER_NOTIFY to the copy's path.
set -euo pipefail

WEBHOOK_URL="${CLAUDE_HOOKSCANNER_WEBHOOK_URL:?set CLAUDE_HOOKSCANNER_WEBHOOK_URL}"

severity="$1" finding_type="$2" path="$3" detail="$4"

payload=$(jq -n \
  --arg host "$(hostname)" \
  --arg severity "$severity" \
  --arg finding_type "$finding_type" \
  --arg path "$path" \
  --arg detail "$detail" \
  '{host:$host, severity:$severity, finding_type:$finding_type, path:$path, detail:$detail}')

curl -fsS -m 10 -X POST "$WEBHOOK_URL" \
  -H 'Content-Type: application/json' \
  -d "$payload" >/dev/null
