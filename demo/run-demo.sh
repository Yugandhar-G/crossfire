#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "========================================="
echo "  CROSSFIRE DEMO"
echo "  MCP Security Proxy"
echo "========================================="
echo ""

# Start dashboard server
echo "[1/2] Starting Crossfire dashboard on http://localhost:9999 ..."
cd "$PROJECT_DIR"
python3 -m uvicorn server.main:app --host 0.0.0.0 --port 9999 &
DASHBOARD_PID=$!
sleep 2

# Open browser
if command -v open &> /dev/null; then
    open "http://localhost:9999"
elif command -v xdg-open &> /dev/null; then
    xdg-open "http://localhost:9999"
fi

echo "[2/2] Dashboard running! PID: $DASHBOARD_PID"
echo ""
echo "========================================="
echo "  DEMO SCRIPT (3 minutes)"
echo "========================================="
echo ""
echo "ACT 1: 'What your AI does behind your back'"
echo "  - Open Claude Desktop with the poisoned weather server"
echo "  - Ask: 'What is the weather in San Francisco?'"
echo "  - Watch the dashboard: attack chain appears!"
echo ""
echo "ACT 2: 'One command to see everything'"
echo "  - Show: crossfire install (already done)"
echo "  - Point to live traffic in dashboard"
echo "  - Show threat detection + Gemini analysis"
echo ""
echo "ACT 3: 'Block the attack'"
echo "  - Toggle Guardian to BLOCK mode"
echo "  - Same query - attack is blocked!"
echo ""
echo "Press Ctrl+C to stop the demo."
echo ""

wait $DASHBOARD_PID
