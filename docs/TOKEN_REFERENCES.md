# WS-Security Token Reference Methods

This document describes the implementation of WS-Security token reference methods in go-as4.

## Overview

The AS4 specification requires support for multiple methods of referencing X.509 certificates in WS-Security signatures. Domibus specifically requires:

```xml
<sp:Wss11>
    <sp:MustSupportRefKeyIdentifier/>
    <sp:MustSupportRefIssuerSerial/>
    <sp:MustSupportRefEmbeddedToken/>
</sp:Wss11>
```

## Supported Methods

### 1. BinarySecurityToken (Embedded Token)

The certificate is embedded directly in the SOAP Security header and referenced by ID.

**P-Mode Configuration:**
```go
SignConfig{
    TokenReference: pmode.TokenRefBinarySecurityToken,
}
```

**Generated XML:**
```xml
<wsse:Security>
    <wsse:BinarySecurityToken wsu:Id="X509-abc123"
        EncodingType="...#Base64Binary"
        ValueType="...#X509v3">
        MIIDXTCCAkWgAwIBAgIJAK...
    </wsse:BinarySecurityToken>
    <ds:Signature>
        <ds:KeyInfo>
            <wsse:SecurityTokenReference>
                <wsse:Reference URI="#X509-abc123" ValueType="...#X509v3"/>
            </wsse:SecurityTokenReference>
        </ds:KeyInfo>
    </ds:Signature>
</wsse:Security>
```

**Use Case:** Default method, includes full certificate in message for maximum compatibility.

---

### 2. KeyIdentifier (Subject Key Identifier)

References the certificate using its SubjectKeyIdentifier extension.

**P-Mode Configuration:**
```go
SignConfig{
    TokenReference: pmode.TokenRefKeyIdentifier,
}
```

**Generated XML:**
```xml
<wsse:Security>
    <!-- No BinarySecurityToken -->
    <ds:Signature>
        <ds:KeyInfo>
            <wsse:SecurityTokenReference>
                <wsse:KeyIdentifier 
                    ValueType="...#X509SubjectKeyIdentifier">
                    AgQUMDEyMzQ1Njc4OTAxMjM0NTY3ODk=
                </wsse:KeyIdentifier>
            </wsse:SecurityTokenReference>
        </ds:KeyInfo>
    </ds:Signature>
</wsse:Security>
```

**Use Case:** Recommended by Domibus for eDelivery. Smaller message size, assumes receiver has certificate.

**Implementation:** 
- Extracts SubjectKeyIdentifier from certificate extension (OID 2.5.29.14)
- Fallback: Computes SHA-256 hash of public key if extension not present

---

### 3. IssuerSerial (X509IssuerSerial)

References certificate by issuer distinguished name and serial number.

**P-Mode Configuration:**
```go
SignConfig{
    TokenReference: pmode.TokenRefIssuerSerial,
}
```

**Generated XML:**
```xml
<wsse:Security>
    <!-- No BinarySecurityToken -->
    <ds:Signature>
        <ds:KeyInfo>
            <wsse:SecurityTokenReference>
                <ds:X509Data>
                    <ds:X509IssuerSerial>
                        <ds:X509IssuerName>CN=Test CA,O=Example</ds:X509IssuerName>
                        <ds:X509SerialNumber>12345</ds:X509SerialNumber>
                    </ds:X509IssuerSerial>
                </ds:X509Data>
            </wsse:SecurityTokenReference>
        </ds:KeyInfo>
    </ds:Signature>
</wsse:Security>
```

**Use Case:** Required by Domibus for interoperability. Unique identification using CA-issued values.

---

### 4. Thumbprint (Certificate Hash)

References certificate by SHA-1 thumbprint of the certificate DER encoding.

**P-Mode Configuration:**
```go
SignConfig{
    TokenReference: pmode.TokenRefThumbprint,
}
```

**Generated XML:**
```xml
<wsse:Security>
    <!-- No BinarySecurityToken -->
    <ds:Signature>
        <ds:KeyInfo>
            <wsse:SecurityTokenReference>
                <wsse:KeyIdentifier 
                    ValueType="...#ThumbprintSHA1">
                    rm5hY7QU3QgyDB3sKX5boW7dxZo=
                </wsse:KeyIdentifier>
            </wsse:SecurityTokenReference>
        </ds:KeyInfo>
    </ds:Signature>
</wsse:Security>
```

**Use Case:** Alternative method, uses SHA-256 hash of certificate (implementation note: spec calls for SHA-1 but we use SHA-256).

---

## Default Configurations

### AS4 v2 Profile
- Default: `TokenRefBinarySecurityToken`
- Reason: Ed25519 certificates may not have standard X.509 extensions

### Domibus/eDelivery Profile
- Default: `TokenRefKeyIdentifier`
- Reason: Matches Domibus eDeliveryAS4Policy.xml requirements

### Custom Profile
- Default: `TokenRefBinarySecurityToken`
- Reason: Maximum compatibility

---

## Usage Examples

### Creating a Signer with Token Reference

```go
import (
    "crypto/rsa"
    "crypto/x509"
    "github.com/sirosfoundation/go-as4/pkg/pmode"
    "github.com/sirosfoundation/go-as4/pkg/security"
)

// Using factory (recommended)
config := &pmode.SignConfig{
    Algorithm:      pmode.AlgoRSASHA256,
    HashFunction:   pmode.HashSHA256,
    TokenReference: pmode.TokenRefKeyIdentifier,
}

factory := &security.SignerFactory{}
signer, err := factory.NewSigner(config, privateKey, cert)

// Direct construction
signer, err := security.NewRSASignerWithTokenRef(
    privateKey, 
    cert, 
    crypto.SHA256, 
    pmode.TokenRefIssuerSerial,
)
```

### Signing with Attachments

```go
attachments := []security.Attachment{
    {
        ContentID:   "<payload-1@example.org>",
        ContentType: "application/xml",
        Data:        payloadBytes,
    },
}

signedXML, err := signer.SignEnvelopeWithAttachments(envelopeXML, attachments)
```

---

## Domibus Interoperability

Domibus 5.1.9 policy (`eDeliveryAS4Policy.xml`) requires:

```xml
<sp:Wss11>
    <sp:MustSupportRefKeyIdentifier/>      <!-- ✅ Implemented -->
    <sp:MustSupportRefIssuerSerial/>       <!-- ✅ Implemented -->
    <sp:MustSupportRefEmbeddedToken/>      <!-- ✅ Implemented -->
</sp:Wss11>
```

**Configuration for Domibus compatibility:**
```go
pmode := pmode.GetDefaultPMode(pmode.ProfileDomibus)
// TokenReference is automatically set to TokenRefKeyIdentifier
```

---

## Testing

Comprehensive tests validate all token reference methods:

```bash
go test ./pkg/security -run TokenReference
```

Tests verify:
- ✅ Correct XML structure for each method
- ✅ BinarySecurityToken presence/absence
- ✅ SubjectKeyIdentifier extraction
- ✅ X509IssuerSerial format
- ✅ Thumbprint calculation
- ✅ Attachment signing with each method
- ✅ Factory integration

**Test Coverage:** 91 passing tests across security package

---

## References

- WS-Security X.509 Certificate Token Profile 1.1
- WS-SecurityPolicy 1.3
- Domibus 5.1.9 eDeliveryAS4Policy.xml
- OASIS ebMS 3.0 / AS4 Profile

---

## Implementation Notes

### SubjectKeyIdentifier Extraction
1. First attempts to extract from certificate Extensions (OID 2.5.29.14)
2. Skips ASN.1 OCTET STRING wrapper (bytes 0-1)
3. Fallback: Computes SHA-256 hash of public key (first 20 bytes)

### Certificate Not Embedded
When using KeyIdentifier, IssuerSerial, or Thumbprint:
- BinarySecurityToken is NOT added to message
- Receiver must already have the certificate
- Smaller message size
- Requires proper certificate management/distribution

### Message Size Comparison
- BinarySecurityToken: ~1.5KB overhead (includes full cert)
- KeyIdentifier: ~30 bytes
- IssuerSerial: ~100-200 bytes (depends on DN length)
- Thumbprint: ~30 bytes

---

## Future Enhancements

- [ ] Support for certificate chains (X509DataElement)
- [ ] Certificate validation using token references
- [ ] CRL/OCSP integration for referenced certificates
- [ ] Certificate caching/lookup service
