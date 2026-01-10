#!/bin/bash
# Start phase4 test server for interop testing
#
# This script:
# - Ensures certificates and truststore are set up
# - Rebuilds phase4-test if needed (to pick up truststore changes)
# - Starts the phase4 server on port 8080 (default) or 9090
# - Writes PID to file for clean shutdown
#
# The truststore (interop-truststore.jks) is configured in phase4's
# application.properties and contains the go-as4-ca certificate, allowing
# phase4 to trust signatures from go-as4.
#
# Usage:
#   ./start-phase4.sh           # Start in foreground on port 8080
#   ./start-phase4.sh -d        # Start in background (daemon mode)
#   ./start-phase4.sh --daemon  # Start in background (daemon mode)
#   PORT=9090 ./start-phase4.sh # Start on port 9090

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHASE4_DIR="${PHASE4_DIR:-/home/leifj/work/siros.org/eDelivery/phase4}"
PHASE4_TEST_DIR="${PHASE4_DIR}/phase4-test"
PORT="${PORT:-8080}"
DAEMON_MODE=false

# PID file location
PID_FILE="/tmp/phase4-interop-${PORT}.pid"
LOG_FILE="/tmp/phase4-interop-${PORT}.log"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--daemon)
            DAEMON_MODE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [-d|--daemon]"
            exit 1
            ;;
    esac
done

echo "=== Starting phase4 test server ==="
echo "Phase4 directory: ${PHASE4_DIR}"
echo "Port: ${PORT}"
echo "PID file: ${PID_FILE}"
echo "Daemon mode: ${DAEMON_MODE}"

# Check if phase4 directory exists
if [ ! -d "${PHASE4_TEST_DIR}" ]; then
    echo "ERROR: phase4-test directory not found: ${PHASE4_TEST_DIR}"
    echo "Set PHASE4_DIR environment variable to point to phase4 repository"
    exit 1
fi

# Stop any existing server using our PID file
"${SCRIPT_DIR}/stop-phase4.sh" 2>/dev/null || true

# Generate certificates and truststore (unless SKIP_CERT_SETUP is set)
if [ "${SKIP_CERT_SETUP}" != "1" ]; then
    echo ""
    echo "Setting up certificates..."
    "${SCRIPT_DIR}/setup-certs.sh"
else
    echo ""
    echo "Skipping certificate setup (SKIP_CERT_SETUP=1)"
fi

# Also clean up any orphaned processes on our ports
echo ""
echo "Checking for orphaned processes..."
if lsof -ti:${PORT} >/dev/null 2>&1; then
    echo "Killing orphaned process on port ${PORT}..."
    lsof -ti:${PORT} | xargs kill -9 2>/dev/null || true
    sleep 2
fi

# Also kill the stop monitor port (port + 1000)
STOP_PORT=$((PORT + 1000))
if lsof -ti:${STOP_PORT} >/dev/null 2>&1; then
    echo "Killing orphaned process on stop port ${STOP_PORT}..."
    lsof -ti:${STOP_PORT} | xargs kill -9 2>/dev/null || true
    sleep 1
fi

# Rebuild phase4-test to pick up truststore changes
echo ""
echo "Rebuilding phase4-test..."
cd "${PHASE4_DIR}"
mvn clean install -pl phase4-test -am -DskipTests -q

# Determine which runner to use based on port
if [ "${PORT}" = "8080" ]; then
    MAIN_CLASS="com.helger.phase4.server.standalone.RunInJettyAS4TEST8080"
else
    MAIN_CLASS="com.helger.phase4.server.standalone.RunInJettyAS4TEST9090"
fi

echo ""
echo "Starting phase4 server..."
echo "Using main class: ${MAIN_CLASS}"
cd "${PHASE4_TEST_DIR}"

if [ "${DAEMON_MODE}" = true ]; then
    # Start in background
    echo "Starting in daemon mode..."
    echo "Log file: ${LOG_FILE}"
    
    nohup mvn exec:java \
        -Dexec.mainClass="${MAIN_CLASS}" \
        -Dexec.classpathScope=test \
        > "${LOG_FILE}" 2>&1 &
    
    # Store the PID
    echo $! > "${PID_FILE}"
    echo "Server PID: $(cat ${PID_FILE})"
    
    # Wait for server to start
    echo ""
    echo "Waiting for server to start..."
    for i in {1..30}; do
        if curl -s -o /dev/null -w "%{http_code}" "http://localhost:${PORT}/" 2>/dev/null | grep -q "403\|200"; then
            echo "✓ Server started successfully on port ${PORT}"
            echo ""
            echo "To view logs: tail -f ${LOG_FILE}"
            echo "To stop server: ${SCRIPT_DIR}/stop-phase4.sh"
            exit 0
        fi
        sleep 1
        echo -n "."
    done
    
    echo ""
    echo "ERROR: Server failed to start within 30 seconds"
    echo "Check logs: ${LOG_FILE}"
    cat "${LOG_FILE}" | tail -50
    exit 1
else
    # Run in foreground
    echo ""
    echo "Server starting in foreground... (Ctrl+C to stop)"
    echo "========================================"
    
    # Write PID file for the Maven process
    # Note: In foreground mode, we use a trap to clean up the PID file
    trap "rm -f ${PID_FILE}" EXIT
    
    mvn exec:java \
        -Dexec.mainClass="${MAIN_CLASS}" \
        -Dexec.classpathScope=test &
    
    # Store the background PID and wait
    echo $! > "${PID_FILE}"
    wait $!
fi
