# ADR 0006: Ed25519 XML Signature Support for eDelivery AS4 2.0

## Status

Accepted

## Context

The eDelivery AS4 Profile version 2.0 mandates Ed25519 (EdDSA) as the signature algorithm for the Common Usage Profile. This is a significant change from previous versions which used RSA-based signatures.

### Requirements from eDelivery AS4 2.0 Profile

From Section 3.2.6.2.2 (Message Signing):
- `PMode[].Security.X509.Signature.Algorithm` **MUST** be set to `http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519`
- `PMode[].Security.X509.Signature.HashFunction` **MUST** be set to `http://www.w3.org/2001/04/xmlenc#sha256`

### Interoperability Event Requirements

The December 2025 eDelivery AS4 2.0 Interoperability Event requires:
- Signing certificate with Ed25519 key type
- Signature algorithm: `http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519`
- Element/body-part digest: `http://www.w3.org/2001/04/xmlenc#sha256`

### Technical Background

Ed25519 is defined in:
- RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
- RFC 8410: Algorithm Identifiers for Ed25519, Ed448, X25519, and X448 for Use in the Internet X.509 Public Key Infrastructure
- RFC 9231: Additional XML Security Uniform Resource Identifiers (URIs)

The algorithm URI `http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519` is specified in RFC 9231.

### Current State

- go-as4 currently uses RSA-SHA256 signatures via `signedxml` library
- `signedxml` does not currently support Ed25519 signatures
- Ed25519 key handling exists in Go's standard library (`crypto/ed25519`)

## Decision

We will implement Ed25519 XML signature support in two phases:

### Phase 1: signedxml Library Enhancement

Add Ed25519 signature algorithm support to the `signedxml` library:
1. Register the algorithm URI `http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519`
2. Implement signing using Go's `crypto/ed25519` package
3. Implement verification using the same package
4. Note: Ed25519 is a "pure" signature scheme - it hashes internally, so the digest algorithm in SignedInfo applies only to the references, not to the signature computation itself

### Phase 2: go-as4 Integration

Create an Ed25519 signer in `pkg/security`:
1. Implement the `Signer` interface for Ed25519 keys
2. Support loading Ed25519 private keys from PKCS#8 format
3. Support X.509 certificates with Ed25519 public keys
4. Create WS-Security headers per AS4 specification

## Algorithm Details

### Ed25519 Signature Computation

Unlike RSA signatures where the SignedInfo is hashed and then signed, Ed25519 uses "PureEdDSA":
1. Canonicalize the SignedInfo element using Exclusive C14N
2. Sign the canonicalized bytes directly with Ed25519 (no pre-hashing)

The algorithm identifier in `ds:SignatureMethod`:
```xml
<ds:SignatureMethod Algorithm="http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519"/>
```

### Certificate Requirements

Per the eDelivery AS4 2.0 specification:
- The signing certificate MUST have an Ed25519 public key
- The certificate MAY be signed by an issuer using RSA, ECDSA, or EdDSA
- X.509 certificates with Ed25519 keys use OID 1.3.101.112

## Consequences

### Positive

- Full compliance with eDelivery AS4 2.0 Common Usage Profile
- Participation in EU interoperability events
- Modern, efficient cryptography (Ed25519 is faster than RSA)
- Smaller key sizes (32 bytes vs 3072+ bits for RSA)
- No need to choose hash algorithm (Ed25519 uses SHA-512 internally)

### Negative

- Requires updating the signedxml library
- Ed25519 certificates are less common than RSA certificates
- Some legacy systems may not support Ed25519

### Neutral

- Alternative ECC option (ECDSA with secp256r1) available as fallback per Section 4.7

## Related ADRs

- ADR 0007: X25519 Key Agreement for Message Encryption (companion ADR for encryption)

## References

- [eDelivery AS4 Profile version 2.0](https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/eDelivery+AS4+-+2.0)
- [eDelivery AS4 2.0 Interoperability Event Technical Guidance](https://ec.europa.eu/digital-building-blocks/sites/spaces/EDELCOMMUNITY/pages/909706852/eDelivery+AS4+2.0+Interoperability+Event+technical+guidance)
- [RFC 8032 - EdDSA](https://www.rfc-editor.org/rfc/rfc8032.html)
- [RFC 8410 - Algorithm Identifiers for Ed25519](https://www.rfc-editor.org/rfc/rfc8410.html)
- [RFC 9231 - Additional XML Security URIs](https://www.rfc-editor.org/rfc/rfc9231.html)
