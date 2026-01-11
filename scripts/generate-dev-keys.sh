#!/bin/bash
# Generate development signing keys for AS4 server
#
# Usage: ./scripts/generate-dev-keys.sh [tenant-id]
#
# This creates RSA key pairs for local development and testing.
# DO NOT use these keys in production!

set -euo pipefail

TENANT_ID="${1:-test-tenant}"
KEY_DIR="${KEY_DIR:-./keys/${TENANT_ID}}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

# Create key directory
mkdir -p "$KEY_DIR"

log_info "Generating keys for tenant: $TENANT_ID"
log_info "Output directory: $KEY_DIR"

# Check if keys already exist
if [ -f "$KEY_DIR/default.key" ]; then
    log_warn "Keys already exist. To regenerate, remove:"
    log_warn "  rm -rf $KEY_DIR"
    exit 0
fi

# Generate RSA private key (2048-bit for dev, 4096 recommended for production)
log_info "Generating RSA private key..."
openssl genrsa -out "$KEY_DIR/default.key" 2048 2>/dev/null

# Generate self-signed certificate
log_info "Generating self-signed certificate..."
openssl req -new -x509 -key "$KEY_DIR/default.key" \
    -out "$KEY_DIR/default.crt" \
    -days 365 \
    -subj "/CN=${TENANT_ID}/O=AS4 Development/C=SE" \
    2>/dev/null

# Extract public key
log_info "Extracting public key..."
openssl rsa -in "$KEY_DIR/default.key" -pubout -out "$KEY_DIR/default.pub" 2>/dev/null

# Show certificate details
log_info "Certificate generated:"
openssl x509 -in "$KEY_DIR/default.crt" -noout -subject -dates

echo ""
log_info "Keys generated successfully!"
echo ""
echo "Files created:"
echo "  $KEY_DIR/default.key  - Private key (keep secret!)"
echo "  $KEY_DIR/default.crt  - X.509 certificate"
echo "  $KEY_DIR/default.pub  - Public key"
echo ""
log_warn "These are DEVELOPMENT keys only - do not use in production!"
