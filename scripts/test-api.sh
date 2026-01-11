#!/bin/bash
# AS4 Server API Test Script
# Usage: ./scripts/test-api.sh [base_url] [jwt_token]
#
# This script exercises the AS4 server APIs with curl commands.
# It can be used for manual testing or as a reference for API usage.
#
# Prerequisites:
#   - Server running (make dev-up or make run-server)
#   - MongoDB running (for full functionality)
#
# For development mode (no JWT required):
#   export DEV_MODE=true
#   ./scripts/test-api.sh
#
# For production mode:
#   ./scripts/test-api.sh http://localhost:8080 "$JWT_TOKEN"

set -euo pipefail

# Configuration
BASE_URL="${1:-http://localhost:8080}"
JWT_TOKEN="${2:-}"
TENANT_ID="${TENANT_ID:-test-tenant}"
VERBOSE="${VERBOSE:-false}"
DEV_MODE="${DEV_MODE:-true}"  # Default to dev mode for easier testing

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Curl wrapper with optional verbose output
do_curl() {
    local method="$1"
    local endpoint="$2"
    shift 2
    local curl_opts=("-s" "-w" "\n%{http_code}")
    
    if [ "$VERBOSE" = "true" ]; then
        curl_opts+=("-v")
    fi
    
    # Add authentication header
    if [ -n "$JWT_TOKEN" ]; then
        curl_opts+=("-H" "Authorization: Bearer $JWT_TOKEN")
    elif [ "$DEV_MODE" = "true" ]; then
        # Use dev mode header for testing without JWT
        curl_opts+=("-H" "X-Dev-Tenant: $TENANT_ID")
    fi
    
    response=$(curl "${curl_opts[@]}" -X "$method" "${BASE_URL}${endpoint}" "$@")
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    echo "$body"
    return 0
}

# Test result tracking
TESTS_PASSED=0
TESTS_FAILED=0check_status() {
    local expected="$1"
    local actual="$2"
    local test_name="$3"
    
    if [ "$actual" = "$expected" ]; then
        log_success "$test_name (HTTP $actual)"
        ((TESTS_PASSED++))
    else
        log_error "$test_name - Expected HTTP $expected, got $actual"
        ((TESTS_FAILED++))
    fi
}

# ==============================================================================
# Health & Info Endpoints (unauthenticated)
# ==============================================================================

test_health() {
    log_info "Testing health endpoint..."
    
    response=$(curl -s -w "\n%{http_code}" "${BASE_URL}/health")
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    check_status "200" "$http_code" "GET /health"
    
    if echo "$body" | grep -q "ok\|healthy"; then
        log_success "Health response contains expected status"
    fi
    
    echo "$body" | jq . 2>/dev/null || echo "$body"
}

# ==============================================================================
# JMAP Session Discovery (/.well-known/jmap)
# ==============================================================================

test_jmap_session() {
    log_info "Testing JMAP session discovery..."
    
    response=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer $JWT_TOKEN" \
        "${BASE_URL}/.well-known/jmap")
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ -n "$JWT_TOKEN" ]; then
        check_status "200" "$http_code" "GET /.well-known/jmap"
        echo "$body" | jq . 2>/dev/null || echo "$body"
    else
        log_warn "Skipping JMAP session test (no JWT token provided)"
    fi
}

# ==============================================================================
# JMAP Method Invocations
# ==============================================================================

test_jmap_message_get() {
    log_info "Testing JMAP AS4Message/get..."
    
    payload=$(cat <<EOF
{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:as4"],
    "methodCalls": [
        ["AS4Message/get", {
            "accountId": "$TENANT_ID",
            "ids": null
        }, "call-0"]
    ]
}
EOF
)
    
    response=$(curl -s -w "\n%{http_code}" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $JWT_TOKEN" \
        -d "$payload" \
        "${BASE_URL}/jmap")
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ -n "$JWT_TOKEN" ]; then
        check_status "200" "$http_code" "POST /jmap (AS4Message/get)"
        echo "$body" | jq . 2>/dev/null || echo "$body"
    else
        log_warn "Skipping JMAP test (no JWT token provided)"
    fi
}

test_jmap_message_query() {
    log_info "Testing JMAP AS4Message/query..."
    
    payload=$(cat <<EOF
{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:as4"],
    "methodCalls": [
        ["AS4Message/query", {
            "accountId": "$TENANT_ID",
            "filter": {
                "mailboxId": "inbox"
            },
            "sort": [{"property": "receivedAt", "isAscending": false}],
            "position": 0,
            "limit": 10
        }, "query-0"]
    ]
}
EOF
)
    
    response=$(curl -s -w "\n%{http_code}" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $JWT_TOKEN" \
        -d "$payload" \
        "${BASE_URL}/jmap")
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ -n "$JWT_TOKEN" ]; then
        check_status "200" "$http_code" "POST /jmap (AS4Message/query)"
        echo "$body" | jq . 2>/dev/null || echo "$body"
    else
        log_warn "Skipping JMAP test (no JWT token provided)"
    fi
}

test_jmap_message_changes() {
    log_info "Testing JMAP AS4Message/changes..."
    
    payload=$(cat <<EOF
{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:as4"],
    "methodCalls": [
        ["AS4Message/changes", {
            "accountId": "$TENANT_ID",
            "sinceState": "0"
        }, "changes-0"]
    ]
}
EOF
)
    
    response=$(curl -s -w "\n%{http_code}" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $JWT_TOKEN" \
        -d "$payload" \
        "${BASE_URL}/jmap")
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ -n "$JWT_TOKEN" ]; then
        check_status "200" "$http_code" "POST /jmap (AS4Message/changes)"
        echo "$body" | jq . 2>/dev/null || echo "$body"
    else
        log_warn "Skipping JMAP test (no JWT token provided)"
    fi
}

test_jmap_mailbox_get() {
    log_info "Testing JMAP AS4Mailbox/get..."
    
    payload=$(cat <<EOF
{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:as4"],
    "methodCalls": [
        ["AS4Mailbox/get", {
            "accountId": "$TENANT_ID",
            "ids": null
        }, "mailbox-0"]
    ]
}
EOF
)
    
    response=$(curl -s -w "\n%{http_code}" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $JWT_TOKEN" \
        -d "$payload" \
        "${BASE_URL}/jmap")
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ -n "$JWT_TOKEN" ]; then
        check_status "200" "$http_code" "POST /jmap (AS4Mailbox/get)"
        echo "$body" | jq . 2>/dev/null || echo "$body"
    else
        log_warn "Skipping JMAP test (no JWT token provided)"
    fi
}

test_jmap_participant_get() {
    log_info "Testing JMAP AS4Participant/get..."
    
    payload=$(cat <<EOF
{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:as4"],
    "methodCalls": [
        ["AS4Participant/get", {
            "accountId": "$TENANT_ID",
            "ids": null
        }, "participant-0"]
    ]
}
EOF
)
    
    response=$(curl -s -w "\n%{http_code}" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $JWT_TOKEN" \
        -d "$payload" \
        "${BASE_URL}/jmap")
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ -n "$JWT_TOKEN" ]; then
        check_status "200" "$http_code" "POST /jmap (AS4Participant/get)"
        echo "$body" | jq . 2>/dev/null || echo "$body"
    else
        log_warn "Skipping JMAP test (no JWT token provided)"
    fi
}

test_jmap_message_set() {
    log_info "Testing JMAP AS4Message/set (create)..."
    
    # Base64 encode a simple payload
    PAYLOAD_CONTENT=$(echo -n "Hello, AS4 World!" | base64)
    
    payload=$(cat <<EOF
{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:as4"],
    "methodCalls": [
        ["AS4Message/set", {
            "accountId": "$TENANT_ID",
            "ifInState": null,
            "create": {
                "msg-1": {
                    "toParticipantId": "test-recipient",
                    "service": "urn:oasis:names:tc:ebcore:partyid-type:iso6523:0088",
                    "action": "TestAction",
                    "conversationId": "test-conv-001",
                    "payloads": [{
                        "contentType": "text/plain",
                        "content": "$PAYLOAD_CONTENT"
                    }]
                }
            }
        }, "set-0"]
    ]
}
EOF
)
    
    response=$(curl -s -w "\n%{http_code}" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $JWT_TOKEN" \
        -d "$payload" \
        "${BASE_URL}/jmap")
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ -n "$JWT_TOKEN" ]; then
        check_status "200" "$http_code" "POST /jmap (AS4Message/set create)"
        echo "$body" | jq . 2>/dev/null || echo "$body"
    else
        log_warn "Skipping JMAP test (no JWT token provided)"
    fi
}

test_jmap_queryChanges() {
    log_info "Testing JMAP AS4Message/queryChanges..."
    
    payload=$(cat <<EOF
{
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:as4"],
    "methodCalls": [
        ["AS4Message/queryChanges", {
            "accountId": "$TENANT_ID",
            "filter": {
                "mailboxId": "inbox"
            },
            "sort": [{"property": "receivedAt", "isAscending": false}],
            "sinceQueryState": "0"
        }, "qc-0"]
    ]
}
EOF
)
    
    response=$(curl -s -w "\n%{http_code}" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $JWT_TOKEN" \
        -d "$payload" \
        "${BASE_URL}/jmap")
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ -n "$JWT_TOKEN" ]; then
        check_status "200" "$http_code" "POST /jmap (AS4Message/queryChanges)"
        echo "$body" | jq . 2>/dev/null || echo "$body"
    else
        log_warn "Skipping JMAP test (no JWT token provided)"
    fi
}

# ==============================================================================
# REST API Tests
# ==============================================================================

test_rest_get_tenant() {
    log_info "Testing REST GET tenant..."
    
    response=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer $JWT_TOKEN" \
        "${BASE_URL}/api/tenants/${TENANT_ID}")
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ -n "$JWT_TOKEN" ]; then
        # 200 or 404 are both valid responses
        if [ "$http_code" = "200" ] || [ "$http_code" = "404" ]; then
            log_success "GET /api/tenants/{id} (HTTP $http_code)"
            ((TESTS_PASSED++))
        else
            log_error "GET /api/tenants/{id} - Unexpected HTTP $http_code"
            ((TESTS_FAILED++))
        fi
        echo "$body" | jq . 2>/dev/null || echo "$body"
    else
        log_warn "Skipping REST test (no JWT token provided)"
    fi
}

test_rest_list_messages() {
    log_info "Testing REST GET messages..."
    
    response=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer $JWT_TOKEN" \
        "${BASE_URL}/api/tenants/${TENANT_ID}/messages")
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ -n "$JWT_TOKEN" ]; then
        if [ "$http_code" = "200" ] || [ "$http_code" = "404" ]; then
            log_success "GET /api/tenants/{id}/messages (HTTP $http_code)"
            ((TESTS_PASSED++))
        else
            log_error "GET /api/tenants/{id}/messages - Unexpected HTTP $http_code"
            ((TESTS_FAILED++))
        fi
        echo "$body" | jq . 2>/dev/null || echo "$body"
    else
        log_warn "Skipping REST test (no JWT token provided)"
    fi
}

test_rest_list_participants() {
    log_info "Testing REST GET participants..."
    
    response=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer $JWT_TOKEN" \
        "${BASE_URL}/api/tenants/${TENANT_ID}/participants")
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ -n "$JWT_TOKEN" ]; then
        if [ "$http_code" = "200" ] || [ "$http_code" = "404" ]; then
            log_success "GET /api/tenants/{id}/participants (HTTP $http_code)"
            ((TESTS_PASSED++))
        else
            log_error "GET /api/tenants/{id}/participants - Unexpected HTTP $http_code"
            ((TESTS_FAILED++))
        fi
        echo "$body" | jq . 2>/dev/null || echo "$body"
    else
        log_warn "Skipping REST test (no JWT token provided)"
    fi
}

# ==============================================================================
# AS4 Endpoint Test (requires proper AS4 message)
# ==============================================================================

test_as4_endpoint() {
    log_info "Testing AS4 endpoint (ping)..."
    
    # Simple health check - AS4 endpoint should respond (may return error for invalid message)
    response=$(curl -s -w "\n%{http_code}" \
        -X POST \
        -H "Content-Type: multipart/related; type=\"application/soap+xml\"; boundary=test" \
        "${BASE_URL}/as4")
    http_code=$(echo "$response" | tail -n1)
    
    # Any response from the AS4 endpoint indicates it's listening
    log_info "AS4 endpoint responded with HTTP $http_code"
    ((TESTS_PASSED++))
}

# ==============================================================================
# Main
# ==============================================================================

print_usage() {
    cat <<EOF
AS4 Server API Test Script

Usage: $0 [base_url] [jwt_token]

Arguments:
    base_url   - Server URL (default: http://localhost:8080)
    jwt_token  - JWT bearer token for authenticated endpoints

Environment Variables:
    TENANT_ID  - Tenant ID to use in tests (default: test-tenant)
    VERBOSE    - Set to 'true' for verbose curl output

Examples:
    # Basic health check only
    $0 http://localhost:8080

    # Full test with JWT token
    $0 http://localhost:8080 "eyJhbGciOiJSUzI1NiIs..."

    # Test specific tenant
    TENANT_ID=my-tenant $0 http://localhost:8080 "\$JWT"

Individual curl commands for reference:

    # Health check
    curl -s http://localhost:8080/health | jq .

    # JMAP session (requires auth)
    curl -s -H "Authorization: Bearer \$JWT" \\
        http://localhost:8080/.well-known/jmap | jq .

    # JMAP method call
    curl -s -X POST \\
        -H "Content-Type: application/json" \\
        -H "Authorization: Bearer \$JWT" \\
        -d '{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:as4"],
             "methodCalls":[["AS4Message/get",{"accountId":"tenant","ids":null},"c0"]]}' \\
        http://localhost:8080/jmap | jq .

EOF
}

main() {
    echo ""
    echo "=============================================="
    echo "AS4 Server API Tests"
    echo "=============================================="
    echo "Base URL:  $BASE_URL"
    echo "Tenant ID: $TENANT_ID"
    if [ -n "$JWT_TOKEN" ]; then
        echo "Auth:      JWT token provided"
    else
        echo "Auth:      No JWT token (unauthenticated tests only)"
    fi
    echo "=============================================="
    echo ""

    # Unauthenticated tests
    test_health
    test_as4_endpoint

    # Authenticated tests (JMAP)
    if [ -n "$JWT_TOKEN" ]; then
        echo ""
        echo "--- JMAP API Tests ---"
        test_jmap_session
        test_jmap_mailbox_get
        test_jmap_message_get
        test_jmap_message_query
        test_jmap_message_changes
        test_jmap_queryChanges
        test_jmap_participant_get
        test_jmap_message_set
        
        echo ""
        echo "--- REST API Tests ---"
        test_rest_get_tenant
        test_rest_list_messages
        test_rest_list_participants
    fi

    # Summary
    echo ""
    echo "=============================================="
    echo "Test Summary"
    echo "=============================================="
    echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Failed: ${RED}$TESTS_FAILED${NC}"
    
    if [ "$TESTS_FAILED" -gt 0 ]; then
        exit 1
    fi
}

# Handle help flag
if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    print_usage
    exit 0
fi

main "$@"
