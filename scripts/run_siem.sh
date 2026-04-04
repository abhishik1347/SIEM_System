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

PYTHON_BIN="${PYTHON_BIN:-}"
STREAMLIT_BIN="${STREAMLIT_BIN:-}"

if [[ -z "$PYTHON_BIN" ]]; then
  if [[ -x ".venv/bin/python" ]]; then
    PYTHON_BIN=".venv/bin/python"
  else
    PYTHON_BIN="python3"
  fi
fi

if [[ -z "$STREAMLIT_BIN" ]]; then
  if [[ -x ".venv/bin/streamlit" ]]; then
    STREAMLIT_BIN=".venv/bin/streamlit"
  else
    STREAMLIT_BIN="streamlit"
  fi
fi

SIEM_SERVER_HOST="${SIEM_SERVER_HOST:-0.0.0.0}"
SIEM_SERVER_PORT="${SIEM_SERVER_PORT:-5000}"
SIEM_DASH_HOST="${SIEM_DASH_HOST:-0.0.0.0}"
SIEM_DASH_PORT="${SIEM_DASH_PORT:-8501}"

echo "[SIEM] Starting Flask API on ${SIEM_SERVER_HOST}:${SIEM_SERVER_PORT}"
SIEM_SERVER_HOST="$SIEM_SERVER_HOST" SIEM_SERVER_PORT="$SIEM_SERVER_PORT" \
  "$PYTHON_BIN" cloud/server.py &
API_PID=$!

echo "[SIEM] Starting Streamlit on ${SIEM_DASH_HOST}:${SIEM_DASH_PORT}"
"$STREAMLIT_BIN" run cloud/dashboard/app.py \
  --server.address "$SIEM_DASH_HOST" \
  --server.port "$SIEM_DASH_PORT" &
DASH_PID=$!

echo "[SIEM] PIDs: api=${API_PID} dashboard=${DASH_PID}"

tidy_shutdown() {
  echo "[SIEM] Stopping..."
  kill "$DASH_PID" 2>/dev/null || true
  kill "$API_PID" 2>/dev/null || true
  wait "$DASH_PID" 2>/dev/null || true
  wait "$API_PID" 2>/dev/null || true
}

trap tidy_shutdown INT TERM

# Wait for either process to exit, then stop the other.
set +e
wait -n "$API_PID" "$DASH_PID"
EXIT_CODE=$?
set -e

tidy_shutdown
exit "$EXIT_CODE"
