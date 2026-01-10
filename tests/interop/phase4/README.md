# go-as4 ↔ phase4 Interoperability Test Framework

This test framework validates AS4 message exchange interoperability between go-as4 and [phase4](https://github.com/phax/phase4), a well-established Java AS4 implementation by Philip Helger.

## Overview

The test framework validates:
- **Client tests**: go-as4 sending AS4 messages to phase4 server
- **Server tests**: go-as4 receiving AS4 messages from phase4 client
- **Security**: RSA-SHA-256 signature creation and verification
- **Message types**: UserMessage, Receipt (SignalMessage)
- **Attachments**: MIME multipart/related handling

## Reference Specifications

- [OASIS AS4 Profile v1.0](https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/csprd03/AS4-profile-v1.0-csprd03.html)
- [Peppol AS4 Specification](https://docs.peppol.eu/edelivery/as4/specification/)
- [Swedish DIGG SDK Transport Profile](https://www.digg.se/saker-digital-kommunikation/sdk-for-accesspunktsoperatorer/tekniska-specifikationer-for-accesspunkt/transportprofil-as4)

## Quick Start

### Prerequisites

- Go 1.21+
- Java 21+ (for phase4 server)
- Maven 3.9+ (for building phase4)

### Running Tests

```bash
# Run all tests (requires phase4 server)
./run-tests.sh

# Run only client tests (go-as4 → phase4)
./run-tests.sh client

# Run only server tests (phase4 → go-as4)
./run-tests.sh server

# Run using Docker Compose
./run-tests.sh docker
```

### Manual Testing

```bash
# Build the test binary
go build -o interop-test ./main.go

# Run with phase4 server at custom URL
./interop-test -phase4-url=http://localhost:8080/as4 -mode=client -verbose
```

## Test Cases

### Client Tests (go-as4 → phase4)

| Test | Description | Status |
|------|-------------|--------|
| Basic UserMessage | Unsigned SOAP message with ebMS3 headers | ⚠️ May require signing |
| Signed UserMessage | RSA-SHA-256 signed message with BinarySecurityToken | ✓ Primary test |
| UserMessage with Payload | Signed message with XML payload in SOAP Body | ✓ |
| UserMessage with Attachment | MIME multipart/related with external attachment | ⚠️ Depends on P-Mode |
| Receipt Validation | Verify receipt references original message | ✓ |

### EU AS4 2.0 Encryption Tests (TC02/TC03)

These tests validate EU eDelivery AS4 2.0 Common Usage Profile encryption:

| Test | Description | Status |
|------|-------------|--------|
| TC02 - ENTSOG Single Payload | Signed + X25519/HKDF/AES-128-GCM encrypted single payload | ✓ Local, ⚠️ Interop |
| TC03 - OOTS Two Payloads | Signed + encrypted two-payload message | ✓ Local, ⚠️ Interop |
| TC02 Local | Local encrypt/decrypt round-trip validation | ✓ |
| TC03 Local | Local two-payload encrypt/decrypt validation | ✓ |

**Interoperability Status**:
- ✅ **Certificate trust**: phase4 successfully validates go-as4 signatures (using CA-signed certs)
- ✅ **Message format**: phase4 parses SOAP/ebMS structure correctly
- ⚠️ **Encryption**: phase4's WSS4J requires `RecipientKeyInfo` in `AgreementMethod`
  - Error: `AgreementMethod does not contain xenc:RecipientKeyInfo`
  - This indicates phase4 expects the recipient's public key reference in the XML structure
  - go-as4's EncryptedKey structure may need to include `xenc:RecipientKeyInfo`

### Running TC02/TC03 Tests

```bash
# Run all tests including TC02/TC03
./scripts/run-tests.sh

# Run only TC02/TC03 encryption tests
./scripts/run-tests.sh tc02-tc03

# Run only TC02
./scripts/run-tests.sh tc02

# Run only local tests (no phase4 required)
./scripts/run-tests.sh local
```

### Server Tests (phase4 → go-as4)

| Test | Description | Status |
|------|-------------|--------|
| Server Start | go-as4 HTTP server listening | ✓ |
| Receive UserMessage | Accept and parse AS4 UserMessage | ✓ |
| Verify Signature | Validate RSA-SHA-256 signatures | ✓ |
| Generate Receipt | Return signed AS4 Receipt | ✓ |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Test Framework                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐                    ┌──────────────┐       │
│  │   go-as4     │   AS4 Messages    │   phase4     │       │
│  │   Client     │ ─────────────────▶│   Server     │       │
│  │              │                    │              │       │
│  │   Server     │ ◀─────────────────│   Client     │       │
│  └──────────────┘   AS4 Messages    └──────────────┘       │
│                                                             │
│  Security: RSA-SHA-256 (PKCS#1 v1.5)                       │
│  Transport: HTTP/HTTPS                                      │
│  Encoding: SOAP 1.2, MIME multipart/related                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Security Configuration

Both implementations are configured to use compatible security settings:

### Signature Configuration
- **Signature Algorithm**: RSA-SHA-256 (http://www.w3.org/2001/04/xmldsig-more#rsa-sha256)
- **Digest Algorithm**: SHA-256 (http://www.w3.org/2001/04/xmlenc#sha256)
- **Canonicalization**: Exclusive C14N (http://www.w3.org/2001/10/xml-exc-c14n#)
- **Key Transport**: X.509 BinarySecurityToken

### EU AS4 2.0 Encryption Configuration (TC02/TC03)
- **Key Agreement**: X25519 (ECDH-ES)
- **Key Derivation**: HKDF-SHA256
- **Key Wrap**: AES-128-KW
- **Content Encryption**: AES-128-GCM

### Certificate and Truststore Setup

The test framework uses CA-signed certificates for proper trust validation:

```bash
# Generate certificates and configure phase4 truststore
./scripts/setup-certs.sh

# Generated files:
certs/go-as4-ca.crt            # CA certificate (added to phase4 truststore)
certs/go-as4-ca.key            # CA private key
certs/go-as4-test.crt          # Leaf certificate (used for signing)
certs/go-as4-test.key          # Leaf private key (RSA 2048-bit)
certs/go-as4-chain.crt         # Full certificate chain

# Phase4 truststore (created by setup-certs.sh):
$PHASE4_DIR/phase4-test/src/main/resources/keys/interop-truststore.jks
```

The truststore is configured in phase4's `application.properties`:
```properties
org.apache.wss4j.crypto.merlin.truststore.file=keys/interop-truststore.jks
org.apache.wss4j.crypto.merlin.truststore.password=test123
org.apache.wss4j.crypto.merlin.truststore.type=jks
```

## P-Mode Configuration

### go-as4 P-Mode

```go
PMode{
    MEP:     MEPOneWay,
    Binding: MEPBindingPush,
    Agreement: "urn:oasis:names:tc:ebcore:partyid-type:unregistered",
    Security: SecurityConfig{
        SignAlgorithm:    "RSA-SHA-256",
        DigestAlgorithm:  "SHA-256",
        TokenReference:   "BinarySecurityToken",
    },
}
```

### phase4 P-Mode

```java
PModeLegSecurity security = new PModeLegSecurity();
security.setX509SignatureAlgorithm(ECryptoAlgorithmSign.RSA_SHA_256);
security.setX509SignatureHashFunction(ECryptoAlgorithmSignDigest.DIGEST_SHA_256);
security.setSendReceipt(true);
security.setSendReceiptReplyPattern(EPModeSendReceiptReplyPattern.RESPONSE);
```

## Known Limitations

1. **Encryption**: Not yet tested - focus is on signature interoperability
2. **Pull Mode**: Only Push mode (one-way) is currently tested
3. **Two-Way MEP**: Not yet implemented in test framework
4. **Compression**: GZIP compression not tested

## Troubleshooting

### Signature Verification Fails

1. Check certificate trust configuration
2. Verify canonicalization algorithm matches
3. Ensure SignedInfo references correct elements

### Receipt Not Received

1. Verify P-Mode requires receipt
2. Check HTTP response status code
3. Examine SOAP Fault details if present

### Connection Refused

1. Verify server is running on expected port
2. Check firewall/network configuration
3. Ensure TLS configuration matches (if using HTTPS)

## Files

```
tests/interop/phase4/
├── main.go                  # Main test runner
├── run-tests.sh             # Test execution script
├── docker-compose.yml       # Docker test environment
├── Dockerfile.go-as4        # go-as4 container
├── Dockerfile.phase4        # phase4 container
├── README.md                # This file
├── server/
│   └── server.go            # go-as4 HTTP server
├── phase4-config/
│   ├── pom.xml              # phase4 Maven build
│   └── src/main/java/
│       └── Phase4TestServer.java
└── certs/                   # Test certificates (generated)
```

## Contributing

When adding new test cases:

1. Add test function in `main.go`
2. Update test results tracking
3. Document in this README
4. Ensure both directions are tested if applicable

## License

Same license as go-as4 project.
