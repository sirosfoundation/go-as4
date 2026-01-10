# ADR 0008: Algorithm URIs and Namespace Prefixes for eDelivery AS4 2.0

## Status

Accepted

## Context

The eDelivery AS4 2.0 profile introduces several new XML namespaces and algorithm URIs that must be correctly used in WS-Security headers. These are defined in RFC 9231 and the draft RFC 9231bis.

## Decision

### Algorithm URIs

The following algorithm URIs are mandated by eDelivery AS4 2.0:

#### Signature Algorithms
| Algorithm | URI |
|-----------|-----|
| Ed25519 (EdDSA) | `http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519` |
| ECDSA-SHA256 (Alternative) | `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256` |

#### Digest Algorithms
| Algorithm | URI |
|-----------|-----|
| SHA-256 | `http://www.w3.org/2001/04/xmlenc#sha256` |

#### Key Agreement Algorithms
| Algorithm | URI |
|-----------|-----|
| X25519 | `http://www.w3.org/2021/04/xmldsig-more#x25519` |
| ECDH-ES (Alternative) | `http://www.w3.org/2009/xmlenc11#ECDH-ES` |

#### Key Derivation Functions
| Algorithm | URI |
|-----------|-----|
| HKDF | `http://www.w3.org/2021/04/xmldsig-more#hkdf` |

#### HMAC Algorithms (for HKDF PRF)
| Algorithm | URI |
|-----------|-----|
| HMAC-SHA256 | `http://www.w3.org/2001/04/xmldsig-more#hmac-sha256` |

#### Key Wrapping Algorithms
| Algorithm | URI |
|-----------|-----|
| AES-128 Key Wrap | `http://www.w3.org/2001/04/xmlenc#kw-aes128` |

#### Content Encryption Algorithms
| Algorithm | URI |
|-----------|-----|
| AES-128-GCM | `http://www.w3.org/2009/xmlenc11#aes128-gcm` |

#### Canonicalization Algorithms
| Algorithm | URI |
|-----------|-----|
| Exclusive C14N | `http://www.w3.org/2001/10/xml-exc-c14n#` |

### XML Namespaces

The following namespaces must be declared in WS-Security headers:

```go
const (
    // XML Digital Signature namespaces
    NSXMLDSig      = "http://www.w3.org/2000/09/xmldsig#"
    NSXMLDSig11    = "http://www.w3.org/2009/xmldsig11#"
    NSXMLDSigMore  = "http://www.w3.org/2021/04/xmldsig-more#"
    
    // XML Encryption namespaces
    NSXMLEnc       = "http://www.w3.org/2001/04/xmlenc#"
    NSXMLEnc11     = "http://www.w3.org/2009/xmlenc11#"
    
    // WS-Security namespaces
    NSWSSE         = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    NSWSSE11       = "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd"
    NSWSU          = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    
    // Exclusive C14N namespace
    NSExcC14N      = "http://www.w3.org/2001/10/xml-exc-c14n#"
)
```

### Namespace Prefixes

Standard prefixes used in eDelivery AS4 2.0:

| Prefix | Namespace |
|--------|-----------|
| `ds` | `http://www.w3.org/2000/09/xmldsig#` |
| `dsig11` | `http://www.w3.org/2009/xmldsig11#` |
| `dsig-more` | `http://www.w3.org/2021/04/xmldsig-more#` |
| `xenc` | `http://www.w3.org/2001/04/xmlenc#` |
| `xenc11` | `http://www.w3.org/2009/xmlenc11#` |
| `wsse` | WS-Security 1.0 |
| `wsse11` | WS-Security 1.1 |
| `wsu` | WS-Security Utility |
| `ec` | Exclusive C14N |
| `env` | SOAP 1.2 Envelope |

### HKDFParams Element Structure

Per RFC 9231bis, the HKDF parameters are encoded as:

```xml
<dsig-more:HKDFParams xmlns:dsig-more="http://www.w3.org/2021/04/xmldsig-more#">
    <dsig-more:PRF Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/>
    <dsig-more:Salt>base64-encoded-random-salt</dsig-more:Salt>
    <dsig-more:Info>base64-encoded-info</dsig-more:Info>
    <dsig-more:KeyLength>16</dsig-more:KeyLength>
</dsig-more:HKDFParams>
```

### DEREncodedKeyValue for X25519

Per RFC 8410 and XML Signature 1.1:

```xml
<dsig11:DEREncodedKeyValue xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">
    base64-encoded-DER-public-key
</dsig11:DEREncodedKeyValue>
```

The DER encoding contains:
- Algorithm OID: 1.3.101.110 (X25519)
- No parameters (MUST be absent per RFC 8410)
- 32-byte public key value

## Consequences

### Positive
- Clear reference for all algorithm identifiers
- Consistent namespace usage across the codebase
- Compliance with RFC 9231 and RFC 9231bis

### Negative
- Several new namespaces to manage
- dsig-more namespace is relatively new (2021)

## References

- [RFC 9231 - Additional XML Security URIs](https://www.rfc-editor.org/rfc/rfc9231.html)
- [RFC 9231bis - Updates to XML Security URIs](https://datatracker.ietf.org/doc/draft-eastlake-rfc9231bis-xmlsec-uris/)
- [XML Signature 1.1](https://www.w3.org/TR/xmldsig-core1/)
- [XML Encryption 1.1](https://www.w3.org/TR/xmlenc-core1/)
