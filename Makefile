.PHONY: all test build clean install lint fmt benchmark coverage security-scan docker-build docker-test

# Default target
all: test build

# Run tests with race detection and coverage
test:
	go test -v -race -coverprofile=coverage.out ./...

# Run tests with verbose output
test-verbose:
	go test -v -race -cover ./...

# Run benchmarks
benchmark:
	go test -bench=. -benchmem ./...

# Generate coverage report
coverage:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Test coverage summary (per ADR-002, target >70%)
test-coverage:
	@echo "=== Test Coverage Summary (target: >70%) ==="
	@go test -cover ./pkg/... 2>&1 | grep -E "^(ok|FAIL|\?)" | sort
	@echo ""
	@go test -coverprofile=/tmp/cov.out ./pkg/... 2>/dev/null
	@go tool cover -func=/tmp/cov.out | tail -1

# Build library
build:
	go build -v ./...

# Build example
example:
	mkdir -p bin
	cd examples/basic && go build -o ../../bin/as4-example

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html
	rm -f *.test
	go clean -testcache

# Install dependencies
install:
	go mod download
	go mod tidy

# Update dependencies
update-deps:
	go get -u ./...
	go mod tidy

# Lint code
lint:
	@which golangci-lint > /dev/null 2>&1 || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...
	go vet ./...

# Format code
fmt:
	gofmt -s -w .
	@which goimports > /dev/null 2>&1 || (echo "Installing goimports..." && go install golang.org/x/tools/cmd/goimports@latest)
	goimports -w .

# Security scan
security-scan:
	@which gosec > /dev/null 2>&1 || (echo "Installing gosec..." && go install github.com/securego/gosec/v2/cmd/gosec@latest)
	gosec -quiet ./...

# Check for vulnerabilities
vuln-check:
	@which govulncheck > /dev/null 2>&1 || (echo "Installing govulncheck..." && go install golang.org/x/vuln/cmd/govulncheck@latest)
	govulncheck ./...

# Generate documentation
docs:
	godoc -http=:6060

# Run example
run-example: example
	./bin/as4-example

# Docker build
docker-build:
	docker build -t go-as4:latest .

# Run tests in Docker
docker-test:
	docker build -f Dockerfile.test -t go-as4:test .
	docker run --rm go-as4:test

# =============================================================================
# Interoperability Testing with phase4
# =============================================================================

INTEROP_DIR := tests/interop/phase4
INTEROP_TEST_BIN := bin/interop-test

# Build the interop test binary
interop-build:
	@echo "Building interop-test binary..."
	@mkdir -p bin
	go build -o $(INTEROP_TEST_BIN) ./$(INTEROP_DIR)/cmd/
	@echo "Built $(INTEROP_TEST_BIN)"

# Generate test certificates for interop testing
interop-certs:
	@echo "Generating test certificates..."
	@mkdir -p $(INTEROP_DIR)/certs
	@if [ ! -f $(INTEROP_DIR)/certs/test.key ]; then \
		openssl genrsa -out $(INTEROP_DIR)/certs/test.key 2048; \
		openssl req -new -x509 -key $(INTEROP_DIR)/certs/test.key \
			-out $(INTEROP_DIR)/certs/test.crt -days 365 \
			-subj "/CN=go-as4-test/O=SIROS Interop Test/C=SE"; \
		echo "Generated test certificates in $(INTEROP_DIR)/certs/"; \
	else \
		echo "Certificates already exist in $(INTEROP_DIR)/certs/"; \
	fi

# Build phase4 Docker image
phase4-build:
	@echo "Building phase4 Docker image..."
	docker build -t phase4-test:latest -f $(INTEROP_DIR)/Dockerfile.phase4 $(INTEROP_DIR)

# Build go-as4 Docker image for interop testing
interop-docker-build:
	@echo "Building go-as4 interop Docker image..."
	docker build -t go-as4-interop:latest -f $(INTEROP_DIR)/Dockerfile.go-as4 .

# Start phase4 server
phase4-up: phase4-build
	@echo "Starting phase4 server..."
	docker run -d --name phase4-test \
		-p 8080:8080 \
		-v $(PWD)/$(INTEROP_DIR)/certs:/app/certs:ro \
		phase4-test:latest
	@echo "Waiting for phase4 to be ready..."
	@sleep 10
	@echo "phase4 server running at http://localhost:8080/as4"

# Stop phase4 server
phase4-down:
	@echo "Stopping phase4 server..."
	-docker stop phase4-test 2>/dev/null
	-docker rm phase4-test 2>/dev/null
	@echo "phase4 server stopped"

# Run interop tests against phase4 (client mode - go-as4 sends to phase4)
interop-test-client: interop-build
	@echo "Running interop tests (go-as4 → phase4)..."
	$(INTEROP_TEST_BIN) -mode=client -phase4-url=http://localhost:8080/as4 -verbose

# Run interop tests in server mode (go-as4 receives from phase4)
interop-test-server: interop-build
	@echo "Running interop tests (go-as4 server mode)..."
	$(INTEROP_TEST_BIN) -mode=server -go-server-addr=:9090 -verbose

# Run all interop tests (both directions)
interop-test-all: interop-build
	@echo "Running all interop tests..."
	$(INTEROP_TEST_BIN) -mode=all -phase4-url=http://localhost:8080/as4 -go-server-addr=:9090 -verbose

# Full interop test cycle: build, start phase4, run tests, cleanup
interop-test: interop-build interop-certs phase4-build
	@echo "=============================================="
	@echo "Starting full interop test cycle..."
	@echo "=============================================="
	@# Clean up any existing containers
	-docker stop phase4-test 2>/dev/null
	-docker rm phase4-test 2>/dev/null
	@# Start phase4
	@echo "Starting phase4 server..."
	docker run -d --name phase4-test \
		-p 8080:8080 \
		-v $(PWD)/$(INTEROP_DIR)/certs:/app/certs:ro \
		phase4-test:latest
	@echo "Waiting for phase4 to start (30s)..."
	@sleep 30
	@# Run tests
	@echo "Running interop tests..."
	-$(INTEROP_TEST_BIN) -mode=client -phase4-url=http://localhost:8080/as4 -verbose; \
		TEST_EXIT=$$?; \
		echo "Stopping phase4 server..."; \
		docker stop phase4-test; \
		docker rm phase4-test; \
		exit $$TEST_EXIT

# Run interop tests using docker-compose (recommended)
interop-compose-up:
	@echo "Starting interop test environment with docker-compose..."
	cd $(INTEROP_DIR) && docker-compose up -d phase4 go-as4
	@echo "Services started. Wait for health checks..."

interop-compose-test: interop-compose-up
	@echo "Running interop tests via docker-compose..."
	cd $(INTEROP_DIR) && docker-compose run --rm test-runner
	@echo "Tests complete"

interop-compose-down:
	@echo "Stopping interop test environment..."
	cd $(INTEROP_DIR) && docker-compose down -v
	@echo "Environment stopped"

# Clean up interop test artifacts
interop-clean:
	@echo "Cleaning interop test artifacts..."
	-rm -f $(INTEROP_TEST_BIN)
	-rm -rf $(INTEROP_DIR)/certs
	-rm -rf $(INTEROP_DIR)/results
	-docker stop phase4-test 2>/dev/null
	-docker rm phase4-test 2>/dev/null
	-docker rmi phase4-test:latest 2>/dev/null
	-docker rmi go-as4-interop:latest 2>/dev/null
	@echo "Cleanup complete"

# Quick interop test against running go-as4 server (self-test)
interop-self-test: interop-build
	@echo "Running self-test (go-as4 client → go-as4 server)..."
	@echo "Starting go-as4 server in background..."
	$(INTEROP_TEST_BIN) -mode=server -go-server-addr=:9090 -verbose &
	@sleep 3
	@echo "Running client tests..."
	-$(INTEROP_TEST_BIN) -mode=client -phase4-url=http://localhost:9090/as4 -verbose; \
		TEST_EXIT=$$?; \
		pkill -f "interop-test.*-mode=server" 2>/dev/null; \
		exit $$TEST_EXIT

.PHONY: interop-build interop-certs interop-test interop-test-client interop-test-server interop-test-all
.PHONY: phase4-build phase4-up phase4-down interop-docker-build
.PHONY: interop-compose-up interop-compose-test interop-compose-down interop-clean interop-self-test

# CI pipeline
ci: install lint test coverage security-scan vuln-check

.PHONY: help
help:
	@echo "Available targets:"
	@echo ""
	@echo "  Build & Test:"
	@echo "    all            - Run tests and build (default)"
	@echo "    test           - Run tests with race detection and coverage"
	@echo "    test-verbose   - Run tests with verbose output"
	@echo "    benchmark      - Run benchmarks"
	@echo "    coverage       - Generate HTML coverage report"
	@echo "    build          - Build the library"
	@echo "    example        - Build the example application"
	@echo "    run-example    - Build and run the example"
	@echo "    clean          - Remove build artifacts"
	@echo ""
	@echo "  Dependencies:"
	@echo "    install        - Download and tidy dependencies"
	@echo "    update-deps    - Update all dependencies"
	@echo ""
	@echo "  Code Quality:"
	@echo "    lint           - Run linters (golangci-lint, go vet)"
	@echo "    fmt            - Format code (gofmt, goimports)"
	@echo "    security-scan  - Run security scanner (gosec)"
	@echo "    vuln-check     - Check for known vulnerabilities"
	@echo ""
	@echo "  Docker:"
	@echo "    docker-build   - Build Docker image"
	@echo "    docker-test    - Run tests in Docker"
	@echo ""
	@echo "  Interoperability Testing (phase4):"
	@echo "    interop-build        - Build the interop test binary"
	@echo "    interop-certs        - Generate test certificates"
	@echo "    interop-test         - Full interop cycle: build phase4, run tests, cleanup"
	@echo "    interop-self-test    - Quick self-test (go-as4 client → go-as4 server)"
	@echo "    interop-test-client  - Run client tests against phase4"
	@echo "    interop-test-server  - Start go-as4 in server mode"
	@echo "    phase4-build         - Build phase4 Docker image"
	@echo "    phase4-up            - Start phase4 Docker container"
	@echo "    phase4-down          - Stop phase4 Docker container"
	@echo "    interop-compose-up   - Start full environment with docker-compose"
	@echo "    interop-compose-test - Run tests via docker-compose"
	@echo "    interop-compose-down - Stop docker-compose environment"
	@echo "    interop-clean        - Clean up interop test artifacts"
	@echo ""
	@echo "  Other:"
	@echo "    docs           - Start local documentation server"
	@echo "    ci             - Run full CI pipeline"
	@echo "    help           - Show this help message"
