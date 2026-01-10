#!/bin/bash
# Stop phase4 test server
#
# This script stops the phase4 server started by start-phase4.sh
# Uses the PID file to identify the correct process

set -e

PORT="${PORT:-8080}"
PID_FILE="/tmp/phase4-interop-${PORT}.pid"

echo "=== Stopping phase4 test server ==="
echo "Port: ${PORT}"
echo "PID file: ${PID_FILE}"

if [ -f "${PID_FILE}" ]; then
    PID=$(cat "${PID_FILE}")
    echo "Found PID: ${PID}"
    
    if ps -p "${PID}" > /dev/null 2>&1; then
        echo "Stopping process ${PID}..."
        
        # First try graceful shutdown
        kill "${PID}" 2>/dev/null || true
        
        # Wait up to 10 seconds for graceful shutdown
        for i in {1..10}; do
            if ! ps -p "${PID}" > /dev/null 2>&1; then
                echo "✓ Server stopped gracefully"
                rm -f "${PID_FILE}"
                exit 0
            fi
            sleep 1
            echo -n "."
        done
        
        echo ""
        echo "Process didn't stop gracefully, sending SIGKILL..."
        kill -9 "${PID}" 2>/dev/null || true
        sleep 1
        
        if ! ps -p "${PID}" > /dev/null 2>&1; then
            echo "✓ Server stopped (forced)"
        else
            echo "WARNING: Failed to stop process ${PID}"
        fi
    else
        echo "Process ${PID} not running (stale PID file)"
    fi
    
    rm -f "${PID_FILE}"
else
    echo "No PID file found at ${PID_FILE}"
    echo "Checking for orphaned processes on port ${PORT}..."
fi

# Clean up any orphaned processes on the port
if lsof -ti:${PORT} >/dev/null 2>&1; then
    echo "Found orphaned process on port ${PORT}, killing..."
    lsof -ti:${PORT} | xargs kill -9 2>/dev/null || true
    sleep 1
fi

# Also clean up the stop monitor port
STOP_PORT=$((PORT + 1000))
if lsof -ti:${STOP_PORT} >/dev/null 2>&1; then
    echo "Found orphaned process on stop port ${STOP_PORT}, killing..."
    lsof -ti:${STOP_PORT} | xargs kill -9 2>/dev/null || true
fi

echo "✓ Cleanup complete"
