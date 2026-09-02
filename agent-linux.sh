#!/usr/bin/env bash
# ==============================================================================
# ShadowXLab · Splunk Standalone Real-Time Linux Forwarder Agent
# ==============================================================================
# Sends auth logs and system metrics via Splunk HEC to http://localhost:8000/services/collector/event
# ==============================================================================

SERVER_URL="${1:-http://localhost:8000/services/collector/event}"
HEC_TOKEN="sxl-splunk-hec-token-2026"
HOST_NAME=$(hostname)

echo "============================================================"
echo "  SHADOWXLAB SPLUNK LINUX REAL-TIME AGENT"
echo "============================================================"
echo "  Target Server:  $SERVER_URL"
echo "  Host Identity:  $HOST_NAME"
echo "============================================================"

send_event() {
    local msg="$1"
    local sourcetype="${2:-linux_secure}"
    local payload="{\"event\": \"$msg\", \"host\": \"$HOST_NAME\", \"sourcetype\": \"$sourcetype\"}"
    curl -s -X POST "$SERVER_URL" \
        -H "Authorization: Splunk $HEC_TOKEN" \
        -H "Content-Type: application/json" \
        -d "$payload" > /dev/null
    echo "[✓ $(date +'%T')] Sent: $msg"
}

send_event "Agent Initialized on Linux Host $HOST_NAME" "sxl:agent:heartbeat"

# Loop sending metrics every 5 seconds
while true; do
    LOAD=$(uptime | awk -F'load average:' '{ print $2 }')
    send_event "Host=$HOST_NAME UptimeLoad=$LOAD ActiveUsers=$(who | wc -l)" "linux:system:metric"
    sleep 5
done
