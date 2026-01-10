# Security Implementation

This document describes the security features and hardening implemented in the go-as4 library.

## Overview

The go-as4 library implements comprehensive security measures to protect AS4 message exchanges, including:

1. **Pluggable Certificate Validation** - Flexible certificate validation supporting both traditional PKI and modern trust frameworks
2. **Cryptographic Input Validation** - Comprehensive validation of all cryptographic inputs to prevent weak keys and attacks
3. **Secure Random Generation** - Explicit use of cryptographically secure randomness throughout
4. **Size Limits and DoS Protection** - Configurable limits to prevent resource exhaustion attacks

## Certificate Validation

### Architecture

Certificate validation is implemented through a pluggable interface (`CertificateValidator`) that allows different trust models:

```go
type CertificateValidator interface {
    ValidateCertificate(cert *x509.Certificate, chain []*x509.Certificate, purpose string) error
    ValidateCertificateChain(cert *x509.Certificate, intermediates []*x509.Certificate, purpose string) error
}
```

### Implementations

#### 1. Default PKI Validator (`DefaultCertificateValidator`)

Traditional X.509 PKI validation with:
- CA trust pool verification
- Certificate expiration checking
- Key usage validation
- Basic constraints verification

**Usage:**
```go
validator := security.NewDefaultCertificateValidator(caCertPool)
signer.WithCertificateValidator(validator)
```

#### 2. AuthZEN Trust Framework (`AuthZENTrustValidator`)

Modern decentralized trust based on [draft-johansson-authzen-trust](https://datatracker.ietf.org/doc/draft-johansson-authzen-trust/):

- REST API-based trust decisions via Policy Decision Point (PDP)
- Supports multiple trust registries (ETSI, OpenID Federation, ledgers)
- Name-to-key binding validation
- Purpose-specific trust decisions
- Decentralized trust management

**See [docs/AUTHZEN.md](docs/AUTHZEN.md) for complete specification and examples.**

**Usage:**
```go
// Default action is "signing" - appropriate for AS4 XML signatures
validator := security.NewAuthZENTrustValidator("https://trust-pdp.example.com/evaluation")
signer.WithCertificateValidator(validator)

// For other use cases, configure the action:
validator.WithDefaultAction("tls-server")  // TLS server certificates
validator.WithDefaultAction("encryption")   // Encryption certificates
```

**Protocol Example:**

Request to PDP (for AS4 signing):
```json
{
  "type": "authzen",
  "request": {
    "subject": {"type": "key", "id": "party@example.com"},
    "resource": {"type": "x5c", "id": "party@example.com", "key": ["<base64-cert>"]},
    "action": {"name": "signing"}
  }
}
```

Response from PDP:
```json
{
  "decision": true
}
```

### Integration

Certificate validation is integrated into XML signature verification:

```go
// Create signer with certificate validation
signer, _ := security.NewXMLSigner(privateKey, cert)
signer.WithCertificateValidator(validator)

// Verification automatically validates certificates
valid, err := signer.VerifyEnvelope(signedXML)
```

## Input Validation

### Cryptographic Key Validation

All cryptographic keys are validated before use:

#### Ed25519 Keys
```go
// Validates public key size and detects weak keys (all-zero)
ValidateEd25519PublicKey(publicKey ed25519.PublicKey) error

// Validates private key size and detects weak keys
ValidateEd25519PrivateKey(privateKey ed25519.PrivateKey) error
```

#### X25519 Keys
```go
// Validates and detects small-order points
ValidateX25519PublicKey(publicKey *[32]byte) error

// Validates private key
ValidateX25519PrivateKey(privateKey *[32]byte) error
```

**Small-Order Point Protection:**

The library detects and rejects the following weak Curve25519 points:
- Point at infinity (all zeros)
- Order 2 point: `0xecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f`
- Order 4 points
- Order 8 points

#### AES Keys
```go
// Validates AES key size (16, 24, or 32 bytes) and detects weak keys
ValidateAESKey(key []byte) error
```

#### Other Validations
```go
// Validates nonce size
ValidateNonce(nonce []byte, expectedSize int) error

// Validates ECDH shared secret (detects all-zero failures)
ValidateSharedSecret(secret *[32]byte) error
```

### Data Size Validation

Configurable limits prevent DoS attacks:

```go
const (
    MaxMessageSize      = 10 * 1024 * 1024  // 10 MB
    MaxAttachmentSize   = 100 * 1024 * 1024 // 100 MB
    MaxXMLDepth         = 100
    MaxCertificateSize  = 64 * 1024         // 64 KB
)

// Validates input size and prevents null byte injection
SanitizeInputSize(data []byte, maxSize int, context string) error
ValidateInputData(data []byte, maxSize int, context string) error
```

### Integration

Input validation is integrated throughout the encryption and signing operations:

```go
// Encryption automatically validates all inputs
func (e *AESEncryptor) Encrypt(plaintext []byte) (ciphertext, ephemeralPublicKey, nonce []byte, err error) {
    // Validates recipient public key
    if err := ValidateX25519PublicKey(&e.recipientPublicKey); err != nil {
        return nil, nil, nil, fmt.Errorf("invalid recipient public key: %w", err)
    }
    
    // Validates plaintext size
    if err := SanitizeInputSize(plaintext, MaxMessageSize, "plaintext"); err != nil {
        return nil, nil, nil, err
    }
    // ... encryption continues
}
```

## Secure Random Generation

All cryptographic randomness uses `crypto/rand.Reader` explicitly:

```go
// Ed25519 key generation
pub, priv, err := ed25519.GenerateKey(rand.Reader)

// Ephemeral key generation
if _, err := rand.Read(ephemeralPrivate[:]); err != nil {
    return nil, nil, nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
}

// Nonce generation
if _, err := io.ReadFull(rand.Reader, nonceData); err != nil {
    return nil, nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
}
```

## Key Wrapping (AES-KW RFC 3394)

AES Key Wrap is implemented with full validation:

```go
// Validates both KEK and key to wrap
func WrapKey(kek, keyToWrap []byte) ([]byte, error) {
    if err := ValidateAESKey(kek); err != nil {
        return nil, fmt.Errorf("invalid KEK: %w", err)
    }
    if err := ValidateAESKey(keyToWrap); err != nil {
        return nil, fmt.Errorf("invalid key to wrap: %w", err)
    }
    // ... wrapping continues
}

// Validates unwrapped key
func UnwrapKey(kek, wrappedKey []byte) ([]byte, error) {
    // ... unwrapping ...
    if err := ValidateAESKey(plainKey); err != nil {
        return nil, fmt.Errorf("invalid unwrapped key: %w", err)
    }
    return plainKey, nil
}
```

## Security Best Practices

### When Using This Library

1. **Always configure certificate validation**
   ```go
   validator := security.NewDefaultCertificateValidator(caCertPool)
   signer.WithCertificateValidator(validator)
   ```

2. **Use appropriate trust levels for AuthZEN**
   ```go
   // Require high trust level for signing operations
   validator := security.NewAuthZENTrustValidator(trustStore, 80)
   ```

3. **Configure size limits appropriately**
   ```go
   // Adjust MaxMessageSize based on your use case
   const MaxMessageSize = 5 * 1024 * 1024 // 5 MB for smaller messages
   ```

4. **Monitor for validation failures**
   ```go
   if err := validator.ValidateCertificate(cert, chain, "signing"); err != nil {
       // Log security event
       log.Error("Certificate validation failed", "error", err)
       return err
   }
   ```

## Known Limitations

1. **Certificate Revocation**: The current implementation does not check OCSP or CRL. This should be added for production use.

2. **Nonce Tracking**: GCM nonce reuse prevention is not yet implemented. Callers must ensure nonces are never reused.

3. **Rate Limiting**: No rate limiting is implemented. Applications should implement this at the transport layer.

4. **Audit Logging**: Security events are not automatically logged. Applications should implement audit logging.

## Security Issues Addressed

This implementation addresses the following security vulnerabilities identified in the security audit:

### CRITICAL (Fixed)
- ✅ Missing certificate validation in `VerifySOAPMessage()` - Now validates certificates when validator is configured
- ✅ Weak random seed (nil reader) - All key generation uses explicit `rand.Reader`
- ✅ Missing input validation - Comprehensive validation for all cryptographic inputs

### HIGH (Partially Fixed)
- ⚠️ No TLS certificate verification configuration - Applications must configure TLS at transport layer
- ⏳ No protection against nonce reuse - Needs implementation
- ⚠️ Error information leakage - Errors are descriptive but don't leak sensitive data
- ⏳ No rate limiting - Must be implemented at application layer

### MEDIUM (Partially Fixed)
- ✅ Missing size validation - DoS protection implemented with configurable limits
- ⚠️ Potential timing attacks - Constant-time operations used where possible
- ⏳ No certificate revocation checking - OCSP/CRL support needed
- ⚠️ Weak ID generation - Uses crypto/rand but could use UUIDs
- ⚠️ Potential canonicalization attacks - Uses standard C14N, needs review

### LOW (Open)
- ⏳ Incomplete security configuration - Applications should review all settings
- ⏳ Missing audit logging - Applications should implement
- ⏳ No key rotation mechanism - Applications should implement
- ⏳ TODO/placeholder security code - Under active development

## Future Enhancements

1. **OCSP/CRL Support**: Add certificate revocation checking
2. **Nonce Management**: Implement nonce tracking for GCM
3. **Rate Limiting**: Add configurable rate limiting
4. **Audit Logging**: Implement security event logging framework
5. **Key Rotation**: Add key rotation support
6. **Timing Attack Protection**: Review and harden timing-sensitive operations

## References

- [AuthZEN Trust Framework](https://datatracker.ietf.org/doc/draft-johansson-authzen-trust/)
- [RFC 3394 - Advanced Encryption Standard (AES) Key Wrap Algorithm](https://www.rfc-editor.org/rfc/rfc3394)
- [RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://www.rfc-editor.org/rfc/rfc5869)
- [Curve25519: new Diffie-Hellman speed records](https://cr.yp.to/ecdh.html)
- [AS4 Profile 2.0 Specification](https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/845480153/eDelivery+AS4+-+2.0)
