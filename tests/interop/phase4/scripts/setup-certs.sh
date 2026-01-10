#!/bin/bash
# Generate test certificates for go-as4 ↔ phase4 interop testing
#
# This script generates:
# - A CA certificate and key
# - A leaf certificate signed by the CA
# - Exports the CA to a Java truststore for phase4

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/../certs"
PHASE4_KEYS_DIR="${PHASE4_DIR:-/home/leifj/work/siros.org/eDelivery/phase4}/phase4-test/src/main/resources/keys"

# Certificate parameters
CA_CN="go-as4-test-ca"
LEAF_CN="go-as4-test"
DAYS_CA=3650
DAYS_LEAF=365
KEY_SIZE=2048

# Truststore parameters
TRUSTSTORE_FILE="interop-truststore.jks"
TRUSTSTORE_PASSWORD="test123"

echo "=== go-as4 Certificate Generation ==="
echo "Certs directory: ${CERTS_DIR}"
echo "Phase4 keys directory: ${PHASE4_KEYS_DIR}"

# Create directories
mkdir -p "${CERTS_DIR}"

# Generate CA key and certificate
echo ""
echo "Generating CA certificate..."
openssl genrsa -out "${CERTS_DIR}/go-as4-ca.key" ${KEY_SIZE} 2>/dev/null

openssl req -x509 -new -nodes \
    -key "${CERTS_DIR}/go-as4-ca.key" \
    -sha256 -days ${DAYS_CA} \
    -out "${CERTS_DIR}/go-as4-ca.crt" \
    -subj "/C=SE/O=go-as4 Interop Test CA/CN=${CA_CN}" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

echo "✓ CA certificate generated: ${CERTS_DIR}/go-as4-ca.crt"

# Generate leaf key (PKCS#8) and convert to PKCS#1 (RSA traditional format) for Go compatibility
echo ""
echo "Generating leaf certificate..."
openssl genrsa -out "${CERTS_DIR}/go-as4-test.key.tmp" ${KEY_SIZE} 2>/dev/null
# Convert to traditional RSA format (PKCS#1) - Go's x509.ParsePKCS1PrivateKey expects this
openssl rsa -in "${CERTS_DIR}/go-as4-test.key.tmp" -out "${CERTS_DIR}/go-as4-test.key" -traditional 2>/dev/null
rm -f "${CERTS_DIR}/go-as4-test.key.tmp"

# Create CSR for leaf
openssl req -new \
    -key "${CERTS_DIR}/go-as4-test.key" \
    -out "${CERTS_DIR}/go-as4-test.csr" \
    -subj "/C=SE/O=go-as4 Interop Test/CN=${LEAF_CN}"

# Create extensions file for leaf certificate
cat > "${CERTS_DIR}/leaf-ext.cnf" << EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth,serverAuth
EOF

# Sign leaf certificate with CA
openssl x509 -req \
    -in "${CERTS_DIR}/go-as4-test.csr" \
    -CA "${CERTS_DIR}/go-as4-ca.crt" \
    -CAkey "${CERTS_DIR}/go-as4-ca.key" \
    -CAcreateserial \
    -out "${CERTS_DIR}/go-as4-test.crt" \
    -days ${DAYS_LEAF} \
    -sha256 \
    -extfile "${CERTS_DIR}/leaf-ext.cnf" 2>/dev/null

echo "✓ Leaf certificate generated: ${CERTS_DIR}/go-as4-test.crt"

# Create certificate chain
cat "${CERTS_DIR}/go-as4-test.crt" "${CERTS_DIR}/go-as4-ca.crt" > "${CERTS_DIR}/go-as4-chain.crt"
echo "✓ Certificate chain: ${CERTS_DIR}/go-as4-chain.crt"

# Clean up temporary files
rm -f "${CERTS_DIR}/go-as4-test.csr" "${CERTS_DIR}/leaf-ext.cnf" "${CERTS_DIR}/go-as4-ca.srl"

# Verify certificates
echo ""
echo "Verifying certificate chain..."
openssl verify -CAfile "${CERTS_DIR}/go-as4-ca.crt" "${CERTS_DIR}/go-as4-test.crt"

# Display certificate info
echo ""
echo "CA Certificate:"
openssl x509 -in "${CERTS_DIR}/go-as4-ca.crt" -noout -subject -issuer -dates | sed 's/^/  /'

echo ""
echo "Leaf Certificate:"
openssl x509 -in "${CERTS_DIR}/go-as4-test.crt" -noout -subject -issuer -dates | sed 's/^/  /'

# Create Java truststore for phase4
if [ -d "${PHASE4_KEYS_DIR}" ]; then
    echo ""
    echo "Creating Java truststore for phase4..."
    
    # Remove existing truststore
    rm -f "${PHASE4_KEYS_DIR}/${TRUSTSTORE_FILE}"
    
    # Import CA certificate into truststore
    keytool -import -trustcacerts -noprompt \
        -alias "go-as4-ca" \
        -file "${CERTS_DIR}/go-as4-ca.crt" \
        -keystore "${PHASE4_KEYS_DIR}/${TRUSTSTORE_FILE}" \
        -storepass "${TRUSTSTORE_PASSWORD}" \
        -storetype JKS
    
    echo "✓ Truststore created: ${PHASE4_KEYS_DIR}/${TRUSTSTORE_FILE}"
    
    # List truststore contents
    echo ""
    echo "Truststore contents:"
    keytool -list -keystore "${PHASE4_KEYS_DIR}/${TRUSTSTORE_FILE}" -storepass "${TRUSTSTORE_PASSWORD}" | grep -E "^(Keystore|go-as4)" | sed 's/^/  /'
else
    echo ""
    echo "⚠ Phase4 keys directory not found: ${PHASE4_KEYS_DIR}"
    echo "  Set PHASE4_DIR environment variable or create truststore manually"
fi

# Also copy certificates to go-as4 root certs/ directory (where the test runs from)
GO_AS4_ROOT="${SCRIPT_DIR}/../../../.."
GO_AS4_CERTS="${GO_AS4_ROOT}/certs"
if [ -d "${GO_AS4_ROOT}" ]; then
    echo ""
    echo "Copying certificates to go-as4 root certs/ directory..."
    mkdir -p "${GO_AS4_CERTS}"
    cp "${CERTS_DIR}/go-as4-ca.crt" "${GO_AS4_CERTS}/"
    cp "${CERTS_DIR}/go-as4-ca.key" "${GO_AS4_CERTS}/" 2>/dev/null || true
    cp "${CERTS_DIR}/go-as4-test.crt" "${GO_AS4_CERTS}/"
    cp "${CERTS_DIR}/go-as4-test.key" "${GO_AS4_CERTS}/"
    cp "${CERTS_DIR}/go-as4-chain.crt" "${GO_AS4_CERTS}/"
    echo "✓ Certificates copied to: ${GO_AS4_CERTS}"
fi

echo ""
echo "=== Certificate generation complete ==="
