# ADR 0007: X25519 Key Agreement for AS4 Message Encryption

## Status

Accepted

## Context

The eDelivery AS4 Profile version 2.0 mandates X25519 key agreement for message encryption in the Common Usage Profile. This replaces the traditional RSA key transport mechanism.

### Requirements from eDelivery AS4 2.0 Profile

From Section 3.2.6.2.3 (Message Encryption):
- Key agreement method: `http://www.w3.org/2021/04/xmldsig-more#x25519` **MUST** be used
- Key derivation function: `http://www.w3.org/2021/04/xmldsig-more#hkdf` **MUST** be used
- Key wrapping algorithm: `http://www.w3.org/2001/04/xmlenc#kw-aes128` **MUST** be used
- Content encryption algorithm: `http://www.w3.org/2009/xmlenc11#aes128-gcm` **MUST** be used
- HKDF PRF: `http://www.w3.org/2001/04/xmldsig-more#hmac-sha256`
- Key length: 16 bytes (128 bits)

### Interoperability Event Requirements

The December 2025 eDelivery AS4 2.0 Interoperability Event requires:
- Encryption/key-exchange certificate with X25519 key type
- Key agreement method: `http://www.w3.org/2021/04/xmldsig-more#x25519`
- Key derivation function: `http://www.w3.org/2021/04/xmldsig-more#hkdf`
- Key wrapping algorithm: `http://www.w3.org/2001/04/xmlenc#kw-aes128`
- Payload symmetrical encryption: `http://www.w3.org/2009/xmlenc11#aes128-gcm`

### Technical Background

X25519 is an Elliptic Curve Diffie-Hellman (ECDH) function using Curve25519:
- RFC 7748: Elliptic Curves for Security
- RFC 8410: Algorithm Identifiers for X25519 in X.509 certificates
- RFC 9231: XML Security URIs for X25519

The encryption workflow is "ephemeral-static" key agreement:
1. Sender generates ephemeral X25519 key pair
2. Sender performs ECDH with recipient's static X25519 public key
3. Shared secret is derived using HKDF
4. Derived key wraps a random AES key
5. AES key encrypts the payload using AES-128-GCM

### Current State

- go-as4 has partial X25519 encryption support
- Current implementation may need updates for HKDF with HKDFParams
- X25519 key handling exists in Go's `crypto/ecdh` and `golang.org/x/crypto/curve25519`

## Decision

We will implement full X25519 key agreement encryption support:

### Key Components

1. **xenc:AgreementMethod** with Algorithm `http://www.w3.org/2021/04/xmldsig-more#x25519`

2. **xenc11:KeyDerivationMethod** with Algorithm `http://www.w3.org/2021/04/xmldsig-more#hkdf`
   - dsig-more:HKDFParams containing:
     - PRF: `http://www.w3.org/2001/04/xmldsig-more#hmac-sha256`
     - Salt: Random 32-byte value (base64 encoded)
     - Info: Application-specific or random (base64 encoded)
     - KeyLength: 16

3. **xenc:OriginatorKeyInfo** containing:
   - dsig11:DEREncodedKeyValue with ephemeral X25519 public key (OID 1.3.101.110)

4. **xenc:RecipientKeyInfo** containing:
   - wsse:SecurityTokenReference pointing to recipient's X25519 certificate

### XML Structure Example

```xml
<xenc:AgreementMethod Algorithm="http://www.w3.org/2021/04/xmldsig-more#x25519">
    <xenc11:KeyDerivationMethod Algorithm="http://www.w3.org/2021/04/xmldsig-more#hkdf">
        <dsig-more:HKDFParams>
            <dsig-more:PRF Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/>
            <dsig-more:Salt>...</dsig-more:Salt>
            <dsig-more:Info>...</dsig-more:Info>
            <dsig-more:KeyLength>16</dsig-more:KeyLength>
        </dsig-more:HKDFParams>
    </xenc11:KeyDerivationMethod>
    <xenc:OriginatorKeyInfo>
        <dsig11:DEREncodedKeyValue>...</dsig11:DEREncodedKeyValue>
    </xenc:OriginatorKeyInfo>
    <xenc:RecipientKeyInfo>
        <wsse:SecurityTokenReference>...</wsse:SecurityTokenReference>
    </xenc:RecipientKeyInfo>
</xenc:AgreementMethod>
```

### Implementation Details

1. **Key Generation**:
   - Use `crypto/ecdh` with `ecdh.X25519()` curve
   - Generate ephemeral keys per message

2. **HKDF Key Derivation**:
   - Use `golang.org/x/crypto/hkdf`
   - Salt SHOULD be random (per specification recommendation)
   - Info MAY be empty or application-specific

3. **DER Encoding for X25519 Public Keys**:
   - OID: 1.3.101.110
   - ASN.1 structure per RFC 8410 (no parameters field)

4. **Certificate Handling**:
   - X25519 certificates cannot be self-signed (X25519 cannot sign)
   - Must be signed by Ed25519, ECDSA, or RSA key

## Consequences

### Positive

- Full compliance with eDelivery AS4 2.0 Common Usage Profile
- Perfect Forward Secrecy (ephemeral sender keys)
- Modern, efficient cryptography
- Smaller key sizes than RSA

### Negative

- More complex than RSA key transport
- X25519 certificates require separate issuing key
- Requires understanding of ECDH and HKDF

### Neutral

- Alternative ECC option (ECDH-ES with secp256r1) available as fallback per Section 4.7

## Related ADRs

- ADR 0006: Ed25519 XML Signature Support (companion ADR for signing)

## References

- [eDelivery AS4 Profile version 2.0](https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/eDelivery+AS4+-+2.0)
- [RFC 7748 - Elliptic Curves for Security](https://www.rfc-editor.org/rfc/rfc7748.html)
- [RFC 8410 - Algorithm Identifiers for X25519](https://www.rfc-editor.org/rfc/rfc8410.html)
- [RFC 9231 - Additional XML Security URIs](https://www.rfc-editor.org/rfc/rfc9231.html)
- [RFC 9231bis - HKDF Parameters](https://datatracker.ietf.org/doc/draft-eastlake-rfc9231bis-xmlsec-uris/)
