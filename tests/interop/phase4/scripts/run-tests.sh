#!/bin/bash
# Run phase4 interoperability tests
#
# This script:
# 1. Generates fresh certificates and configures truststores
# 2. Starts phase4 server in daemon mode
# 3. Runs go-as4 interoperability tests (including TC02/TC03)
# 4. Stops phase4 server
# 5. Reports results
#
# Test Categories:
#   - Basic: Basic message exchange tests
#   - TC02: EU AS4 2.0 ENTSOG single payload with signing + encryption
#   - TC03: EU AS4 2.0 OOTS two-payload with signing + encryption

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
GO_AS4_ROOT="${PROJECT_ROOT}"
CERTS_DIR="${SCRIPT_DIR}/../certs"

export PORT="${PORT:-8080}"
export FORCE_REGEN="${FORCE_REGEN:-1}"  # Always regenerate certs by default
export PHASE4_URL="${PHASE4_URL:-http://localhost:${PORT}/as4}"
export INTEROP_CERTS_DIR="${CERTS_DIR}"

# Test selection (default: all)
TEST_FILTER="${1:-}"

echo "============================================"
echo "  Phase4 Interoperability Test Runner"
echo "============================================"
echo ""
echo "Project root: ${PROJECT_ROOT}"
echo "Port: ${PORT}"
echo "Phase4 URL: ${PHASE4_URL}"
echo "Certs directory: ${CERTS_DIR}"
echo ""

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    "${SCRIPT_DIR}/stop-phase4.sh" || true
}

# Set up trap to ensure cleanup on exit
trap cleanup EXIT

# Step 1: Generate fresh certificates and update phase4 truststore
echo "=== Step 1: Generating certificates and configuring truststores ==="
"${SCRIPT_DIR}/setup-certs.sh"
echo ""

# Step 2: Stop any existing server (just in case)
echo "=== Step 2: Stopping any existing server ==="
"${SCRIPT_DIR}/stop-phase4.sh" || true
echo ""

# Step 3: Start phase4 server (skip cert setup, we already did it)
echo "=== Step 3: Starting phase4 server ==="
SKIP_CERT_SETUP=1 PORT="${PORT}" "${SCRIPT_DIR}/start-phase4.sh" -d
echo ""

# Give server a moment to fully initialize
sleep 3

# Step 4: Run go-as4 interop tests
echo "=== Step 4: Running go-as4 interoperability tests ==="
echo ""

cd "${GO_AS4_ROOT}"

# Determine which tests to run
TEST_RUN_ARGS=""
if [ -n "${TEST_FILTER}" ]; then
    case "${TEST_FILTER}" in
        tc02|TC02)
            TEST_RUN_ARGS="-run TC02"
            echo "Running TC02 tests only..."
            ;;
        tc03|TC03)
            TEST_RUN_ARGS="-run TC03"
            echo "Running TC03 tests only..."
            ;;
        tc02-tc03|TC02-TC03|encryption)
            TEST_RUN_ARGS="-run TC0[23]"
            echo "Running TC02/TC03 encryption tests..."
            ;;
        local)
            TEST_RUN_ARGS="-run Local"
            echo "Running local-only tests (no phase4 required)..."
            ;;
        *)
            TEST_RUN_ARGS="-run ${TEST_FILTER}"
            echo "Running tests matching: ${TEST_FILTER}"
            ;;
    esac
fi

echo "Test arguments: ${TEST_RUN_ARGS:-<all tests>}"
echo ""

TEST_EXIT_CODE=0
go test -v ./tests/interop/phase4/cmd/... ${TEST_RUN_ARGS} 2>&1 || TEST_EXIT_CODE=$?

echo ""
echo "============================================"
if [ ${TEST_EXIT_CODE} -eq 0 ]; then
    echo "  ✓ All tests passed!"
else
    echo "  ✗ Some tests failed (exit code: ${TEST_EXIT_CODE})"
fi
echo "============================================"

exit ${TEST_EXIT_CODE}
