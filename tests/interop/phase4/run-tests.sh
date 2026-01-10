#!/bin/bash
# go-as4 ↔ phase4 Interoperability Test Suite
#
# This script runs interoperability tests between go-as4 and phase4.
#
# Prerequisites:
# - Go 1.21+
# - Java 21+ (for phase4)
# - Maven 3.9+ (for building phase4)
#
# Usage:
#   ./run-tests.sh              # Run all tests
#   ./run-tests.sh client       # Run only client tests (go-as4 → phase4)
#   ./run-tests.sh server       # Run only server tests (phase4 → go-as4)
#   ./run-tests.sh docker       # Run using Docker Compose

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed"
        exit 1
    fi
    log_info "Go version: $(go version)"
    
    if [ "$1" != "client" ]; then
        if ! command -v java &> /dev/null; then
            log_warn "Java not installed - phase4 tests will be skipped"
        else
            log_info "Java version: $(java -version 2>&1 | head -1)"
        fi
    fi
}

# Build go-as4 test binary
build_go_test() {
    log_info "Building go-as4 interop test..."
    cd "$SCRIPT_DIR"
    go build -o interop-test ./main.go
    log_info "Build complete: interop-test"
}

# Build phase4 test server
build_phase4() {
    if [ ! -d "phase4-config" ]; then
        log_warn "phase4-config directory not found, skipping phase4 build"
        return 1
    fi
    
    log_info "Building phase4 test server..."
    cd "$SCRIPT_DIR/phase4-config"
    mvn package -DskipTests -q
    log_info "phase4 build complete"
    cd "$SCRIPT_DIR"
}

# Start phase4 server in background
start_phase4() {
    if [ ! -f "phase4-config/target/phase4-test-server-1.0.0-SNAPSHOT.jar" ]; then
        log_warn "phase4 JAR not found, attempting to build..."
        if ! build_phase4; then
            log_error "Failed to build phase4"
            return 1
        fi
    fi
    
    log_info "Starting phase4 test server..."
    java -jar phase4-config/target/phase4-test-server-1.0.0-SNAPSHOT.jar --port 8080 &
    PHASE4_PID=$!
    echo $PHASE4_PID > .phase4.pid
    
    # Wait for server to start
    log_info "Waiting for phase4 to start..."
    for i in {1..30}; do
        if curl -s http://localhost:8080/as4 > /dev/null 2>&1; then
            log_info "phase4 started successfully (PID: $PHASE4_PID)"
            return 0
        fi
        sleep 1
    done
    
    log_error "phase4 failed to start within 30 seconds"
    kill $PHASE4_PID 2>/dev/null || true
    return 1
}

# Stop phase4 server
stop_phase4() {
    if [ -f ".phase4.pid" ]; then
        PID=$(cat .phase4.pid)
        log_info "Stopping phase4 (PID: $PID)..."
        kill $PID 2>/dev/null || true
        rm -f .phase4.pid
    fi
}

# Run client tests (go-as4 → phase4)
run_client_tests() {
    log_info "Running client tests (go-as4 → phase4)..."
    
    if ! curl -s http://localhost:8080/as4 > /dev/null 2>&1; then
        log_warn "phase4 not running at http://localhost:8080/as4"
        log_warn "Attempting to start phase4..."
        if ! start_phase4; then
            log_error "Cannot run client tests without phase4"
            return 1
        fi
        STARTED_PHASE4=true
    fi
    
    ./interop-test -mode=client -phase4-url=http://localhost:8080/as4 -verbose
    RESULT=$?
    
    if [ "$STARTED_PHASE4" = true ]; then
        stop_phase4
    fi
    
    return $RESULT
}

# Run server tests (phase4 → go-as4)
run_server_tests() {
    log_info "Running server tests (phase4 → go-as4)..."
    
    # Start go-as4 server in background
    ./interop-test -mode=server -go-server-addr=:9090 &
    GO_PID=$!
    
    # Wait for server
    sleep 2
    
    # Here we would trigger phase4 client to send to go-as4
    # For now, just verify server starts
    if curl -s -X POST http://localhost:9090/as4 -d "" > /dev/null 2>&1; then
        log_info "go-as4 server responding"
    fi
    
    # Stop server
    kill $GO_PID 2>/dev/null || true
}

# Run Docker-based tests
run_docker_tests() {
    log_info "Running Docker-based interop tests..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "docker-compose is not installed"
        exit 1
    fi
    
    # Use docker compose or docker-compose
    COMPOSE_CMD="docker compose"
    if ! docker compose version &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    fi
    
    log_info "Building containers..."
    $COMPOSE_CMD build
    
    log_info "Starting test environment..."
    $COMPOSE_CMD up --abort-on-container-exit --exit-code-from test-runner
    RESULT=$?
    
    log_info "Cleaning up..."
    $COMPOSE_CMD down
    
    return $RESULT
}

# Main
main() {
    MODE="${1:-all}"
    
    log_info "=================================================="
    log_info "go-as4 ↔ phase4 Interoperability Test Suite"
    log_info "=================================================="
    log_info "Mode: $MODE"
    
    check_prerequisites "$MODE"
    
    # Build go-as4 test (always needed)
    build_go_test
    
    case "$MODE" in
        client)
            run_client_tests
            ;;
        server)
            run_server_tests
            ;;
        docker)
            run_docker_tests
            ;;
        all)
            # Try to start phase4 and run all tests
            if start_phase4; then
                trap stop_phase4 EXIT
                ./interop-test -mode=all -phase4-url=http://localhost:8080/as4 -go-server-addr=:9090 -verbose
            else
                log_warn "Could not start phase4, running go-as4 server tests only"
                run_server_tests
            fi
            ;;
        *)
            log_error "Unknown mode: $MODE"
            echo "Usage: $0 [client|server|docker|all]"
            exit 1
            ;;
    esac
}

main "$@"
