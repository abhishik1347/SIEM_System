#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

mkdir -p logs

PYTHON_BIN="${PYTHON_BIN:-}"

if [[ -z "$PYTHON_BIN" ]]; then
  if [[ -x ".venv/bin/python" ]]; then
    PYTHON_BIN=".venv/bin/python"
  else
    PYTHON_BIN="python3"
  fi
fi

SIEM_SERVER_HOST="${SIEM_SERVER_HOST:-0.0.0.0}"
SIEM_SERVER_PORT="${SIEM_SERVER_PORT:-5000}"
SIEM_DASH_HOST="${SIEM_DASH_HOST:-0.0.0.0}"
SIEM_DASH_PORT="${SIEM_DASH_PORT:-8501}"

nohup env SIEM_SERVER_HOST="$SIEM_SERVER_HOST" SIEM_SERVER_PORT="$SIEM_SERVER_PORT" \
  "$PYTHON_BIN" cloud/server.py > logs/api.out 2>&1 &
API_PID=$!

nohup "$PYTHON_BIN" -m streamlit run cloud/dashboard/app.py \
  --server.address "$SIEM_DASH_HOST" \
  --server.port "$SIEM_DASH_PORT" > logs/dashboard.out 2>&1 &
DASH_PID=$!

# Quick check: if Streamlit fails immediately (common: module missing), surface it.
sleep 1
if ! kill -0 "$DASH_PID" 2>/dev/null; then
  echo "[SIEM] ERROR: Dashboard failed to start. Last 80 log lines:" >&2
  tail -n 80 logs/dashboard.out >&2 || true
  echo "[SIEM] Stopping API as well." >&2
  kill "$API_PID" 2>/dev/null || true
  exit 1
fi

echo "$API_PID" > logs/api.pid
echo "$DASH_PID" > logs/dashboard.pid

echo "[SIEM] Started in background."
echo "[SIEM] API PID: $API_PID (logs/api.out)"
echo "[SIEM] Dashboard PID: $DASH_PID (logs/dashboard.out)"
echo "[SIEM] Stop with: kill $(cat logs/api.pid) $(cat logs/dashboard.pid)"
