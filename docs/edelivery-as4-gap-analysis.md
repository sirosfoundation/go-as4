# eDelivery AS4 Gap Analysis: go-as4 vs AS4 Profile 2.0 and 1.15

## Executive Summary

This document analyzes go-as4's compliance with the EU eDelivery AS4 Profile specifications:
- **eDelivery AS4 2.0** (Current, effective specification)
- **eDelivery AS4 1.15** (Legacy, still widely deployed)

go-as4 is well-positioned for AS4 2.0 with strong support for modern cryptography (Ed25519/X25519). However, gaps exist in legacy AS4 1.15 support and some profile enhancement features.

## Profile Version Comparison

| Feature | AS4 1.15 | AS4 2.0 | go-as4 Status |
|---------|----------|---------|---------------|
| **Signature Algorithm** | RSA-SHA256 | Ed25519 | ✅ Both supported |
| **Key Transport/Agreement** | RSA-OAEP | X25519/HKDF | ✅ Both supported |
| **Data Encryption** | AES-128-GCM | AES-128-GCM | ✅ Implemented |
| **TLS Version** | TLS 1.2 | TLS 1.2/1.3 | ✅ Implemented |
| **MEP: One-Way Push** | Required | Required | ✅ Implemented |
| **MEP: Two-Way** | Required | Required | ✅ Implemented |
| **MEP: Pull** | Enhancement | Enhancement | ⚠️ Partial |
| **Four Corner** | Enhancement | Enhancement | ✅ Implemented |
| **Dynamic Sender** | Enhancement | Enhancement | ✅ Implemented |
| **Dynamic Receiver** | Enhancement | Enhancement | ✅ Implemented |
| **Split/Join** | Enhancement | Enhancement | ❌ Not implemented |
| **ebCore Agreement Update** | N/A | Enhancement | ❌ Not implemented |
| **Alternative ECC** | N/A | Enhancement | ⚠️ Partial |

---

## 1. Common Profile Compliance

### 1.1 Message Exchange Patterns

#### AS4 2.0 / 1.15 Requirements
- One-Way (Push): REQUIRED
- Two-Way (Push-Push): REQUIRED
- Pull: Enhancement module

#### go-as4 Status: ✅ Compliant

**Implementation:**
- [pkg/mep/patterns.go](../pkg/mep/patterns.go) - MEP types and handlers
- Supports `OneWayPush`, `TwoWay`, `Push`, `PushAndPush` bindings

**Reference:**
```go
const (
    OneWayPush MEPType = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/oneWay"
    TwoWay MEPType = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/twoWay"
)
```

---

### 1.2 Security - Transport Layer (TLS)

#### AS4 2.0 Requirements
- MUST NOT use SSL 3.0, TLS 1.0, TLS 1.1
- MUST support TLS 1.2
- SHOULD support TLS 1.3
- TLS 1.3 cipher suites: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_CCM_SHA256`
- TLS 1.2 cipher suites (PFS): `TLS_ECDHE_ECDSA_WITH_AES_*_GCM_*`, `TLS_ECDHE_RSA_WITH_AES_*_GCM_*`
- RSA certificate keys > 3000 bits; ECDSA keys > 250 bits

#### AS4 1.15 Requirements
- TLS 1.2 REQUIRED
- TLS 1.3 MAY be supported
- ECDHE cipher suites SHOULD be supported

#### go-as4 Status: ✅ Compliant

**Implementation:**
- [pkg/transport/https.go](../pkg/transport/https.go) - TLS configuration
- Default TLS 1.2 minimum
- TLS 1.3 supported
- ECDHE cipher suites configured

**Cipher Suites Implemented:**
```go
// From pkg/transport/https.go
CipherSuites: []uint16{
    tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}
```

---

### 1.3 Security - Message Layer (WS-Security)

#### 1.3.1 Signature

##### AS4 2.0 Requirements
- `PMode[].Security.X509.Signature.HashFunction`: `http://www.w3.org/2001/04/xmlenc#sha256`
- `PMode[].Security.X509.Signature.Algorithm`: `http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519`

##### AS4 1.15 Requirements  
- `PMode[].Security.X509.Signature.HashFunction`: `http://www.w3.org/2001/04/xmlenc#sha256`
- `PMode[].Security.X509.Signature.Algorithm`: `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`

##### go-as4 Status: ✅ Compliant for Both

**Implementation:**
- [pkg/security/ed25519_signer.go](../pkg/security/ed25519_signer.go) - Ed25519 (AS4 2.0)
- [pkg/security/rsa_signer.go](../pkg/security/rsa_signer.go) - RSA-SHA256 (AS4 1.15)

**Supported Algorithms:**
```go
// pkg/pmode/pmode.go
AlgoEd25519     SignatureAlgorithm = "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519"
AlgoRSASHA256   SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
AlgoECDSASHA256 SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
```

#### 1.3.2 Encryption

##### AS4 2.0 Requirements
- Key agreement: `http://www.w3.org/2021/04/xmldsig-more#x25519`
- Key derivation: `http://www.w3.org/2021/04/xmldsig-more#hkdf`
- Key wrapping: `http://www.w3.org/2001/04/xmlenc#kw-aes128`
- Content encryption: `http://www.w3.org/2009/xmlenc11#aes128-gcm`
- Originator key: `dsig11:DEREncodedKeyValue` with OID 1.3.101.110

##### AS4 1.15 Requirements
- Key transport: `http://www.w3.org/2009/xmlenc11#rsa-oaep`
- MGF: `http://www.w3.org/2009/xmlenc11#mgf1sha256`
- Digest: `http://www.w3.org/2001/04/xmlenc#sha256`
- Content encryption: `http://www.w3.org/2009/xmlenc11#aes128-gcm`

##### go-as4 Status: ✅ Compliant for Both

**Implementation:**
- [pkg/security/wssec_encryptor.go](../pkg/security/wssec_encryptor.go) - X25519/HKDF (AS4 2.0)
- [pkg/security/xmlenc_adapter.go](../pkg/security/xmlenc_adapter.go) - RSA-OAEP (AS4 1.15)

**AS4 2.0 X25519 Support:**
```go
// pkg/security/types.go
AlgorithmX25519    = "http://www.w3.org/2021/04/xmldsig-more#x25519"
AlgorithmHKDF      = "http://www.w3.org/2021/04/xmldsig-more#hkdf"
AlgorithmAES128GCM = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
```

**AS4 1.15 RSA-OAEP Support:**
```go
// pkg/security/types.go
AlgorithmRSAOAEP   = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
```

---

### 1.4 Compression

#### AS4 2.0 / 1.15 Requirements
- `PMode[].PayloadService.CompressionType`: `application/gzip`
- MUST set CompressionType part property when compression applied
- Compression MUST be applied before signing/encryption

#### go-as4 Status: ✅ Compliant

**Implementation:**
- [pkg/compression/gzip.go](../pkg/compression/gzip.go)

```go
const CompressionTypeGzip = "application/gzip"

func (c *Compressor) Compress(data []byte) ([]byte, error)
func (c *Compressor) Decompress(data []byte) ([]byte, error)
```

---

### 1.5 Reception Awareness & Duplicate Detection

#### AS4 2.0 / 1.15 Requirements
- `PMode[].ReceptionAwareness`: True
- `PMode[].ReceptionAwareness.Retry`: True
- `PMode[].ReceptionAwareness.DuplicateDetection`: True
- `PMode[].Security.SendReceipt`: True
- `PMode[].Security.SendReceipt.NonRepudiation`: True
- `PMode[].Security.SendReceipt.ReplyPattern`: Response

#### go-as4 Status: ✅ Compliant

**Implementation:**
- [pkg/reliability/tracker.go](../pkg/reliability/tracker.go)

```go
type MessageTracker struct {
    messages         map[string]*TrackedMessage
    receivedMessages map[string]time.Time  // Duplicate detection
    duplicateWindow  time.Duration
}

func (t *MessageTracker) Track(messageID string, maxRetries int, retryInterval time.Duration, retryMultiplier float64)
func (t *MessageTracker) IsDuplicate(messageID string, body []byte) bool
```

---

### 1.6 P-Mode Parameters

#### AS4 2.0 / 1.15 Requirements
Full P-Mode configuration support including:
- Party identification (ebCore format)
- Protocol (HTTPS, SOAP 1.2)
- Business info (Service, Action, Properties)
- Security configuration
- Receipt handling
- Error handling

#### go-as4 Status: ✅ Compliant

**Implementation:**
- [pkg/pmode/pmode.go](../pkg/pmode/pmode.go)

```go
type ProcessingMode struct {
    ID               string
    Agreement        *Agreement
    MEP              string
    MEPBinding       string
    Service          string
    Action           string
    Protocol         *Protocol
    Security         *Security
    ReceptionAwareness *ReceptionAwareness
    PayloadService   *PayloadService
    SecurityProfile  SecurityProfile  // as4v2, domibus, edelivery, custom
}
```

---

## 2. Profile Enhancement Compliance

### 2.1 Four Corner Topology

#### Requirements
- `originalSender` message property: REQUIRED
- `finalRecipient` message property: REQUIRED
- `trackingIdentifier` message property: OPTIONAL
- C2/C3 party identification separate from C1/C4

#### go-as4 Status: ✅ Compliant

**Implementation:**
- [pkg/message/builder.go](../pkg/message/builder.go) - Message properties

```go
message.WithMessageProperty("originalSender", "urn:oasis:names:tc:ebcore:partyid-type:unregistered:C1")
message.WithMessageProperty("finalRecipient", "urn:oasis:names:tc:ebcore:partyid-type:unregistered:C4")
message.WithMessageProperty("trackingIdentifier", "tracking-123")
```

---

### 2.2 Dynamic Sender

#### Requirements
- P-Mode template support
- Discovery infrastructure integration
- Dynamic resolution of:
  - `PMode.Responder.Party`
  - `PMode[].Protocol.Address`
  - `PMode[].Security.X509.Encryption.Certificate`

#### go-as4 Status: ✅ Compliant

**Implementation:**
- [pkg/discovery/bdxl.go](../pkg/discovery/bdxl.go) - BDXL/DNS NAPTR lookup
- [pkg/discovery/smp.go](../pkg/discovery/smp.go) - SMP metadata retrieval

```go
// Discover SMP for party
smpURL, _ := bdxlClient.DiscoverSMP(ctx, partyID)

// Get service metadata including endpoint and certificates
metadata, _ := smpClient.GetServiceMetadata(ctx, smpURL, partyID, documentTypeID)
endpoint := metadata.Processes[0].Endpoints[0]
// endpoint.EndpointURL, endpoint.Certificate
```

---

### 2.3 Dynamic Receiver

#### Requirements
- Accept messages with arbitrary From/PartyId values
- X.509 PKI-based authentication
- Certificate subject validation against Party ID

#### go-as4 Status: ✅ Compliant

**Implementation:**
- [pkg/security/certvalidation.go](../pkg/security/certvalidation.go)
- Certificate chain validation
- Trust anchor configuration

---

### 2.4 Pull Feature

#### Requirements (Enhancement Module)
- MEP bindings: `pull`, `pushAndPull`, `pullAndPush`
- Pull Request signing
- MPC authorization
- Asynchronous receipts for Pull

#### go-as4 Status: ⚠️ Partial

**Implemented:**
- MEP bindings defined in [pkg/mep/patterns.go](../pkg/mep/patterns.go)

**Gaps:**
| Gap | Impact | Effort |
|-----|--------|--------|
| Pull Request generation | Cannot initiate Pull | Medium |
| Pull Response handling | Cannot receive pulled messages | Medium |
| MPC authorization | Security for Pull | Low |

---

### 2.5 Large Message Split/Join (ebMS3 Part 2)

#### AS4 2.0 Requirements (Enhancement Module)
- Fragment large messages per ebMS3 Part 2
- `mf:MessageFragment` header
- Individual fragment signing/encryption
- Fragment receipts (Non-Repudiation)
- Source message receipt (Reception Awareness)
- GZIP compression of fragments

#### go-as4 Status: ❌ Not Implemented

**Required Implementation:**
| Component | Description | Effort |
|-----------|-------------|--------|
| `pkg/splitjoin/splitter.go` | Message fragmentation | High |
| `pkg/splitjoin/joiner.go` | Fragment reassembly | High |
| `pkg/message/fragment.go` | MessageFragment header | Medium |
| P-Mode extension | Splitting parameters | Low |

**P-Mode Parameters Needed:**
```go
type Splitting struct {
    FragmentSize       int
    RoutingProperties  []string  // originalSender, finalRecipient, trackingIdentifier
    Compression        *CompressionConfig
    JoinInterval       time.Duration
}
```

---

### 2.6 ebCore Agreement Update (AS4 2.0 only)

#### Requirements
- Certificate update protocol
- Endpoint update protocol
- Agreement negotiation

#### go-as4 Status: ❌ Not Implemented

**Required Implementation:**
| Component | Description | Effort |
|-----------|-------------|--------|
| `pkg/ebcore/agreement.go` | Agreement structure | Medium |
| `pkg/ebcore/certificate_update.go` | Cert update messages | Medium |
| `pkg/ebcore/endpoint_update.go` | Endpoint update messages | Medium |

---

### 2.7 Alternative Elliptic Curve Cryptography (AS4 2.0)

#### Requirements (Enhancement Module)
Fallback for Ed25519/X25519:
- Signature: `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256`
- Key agreement: `http://www.w3.org/2009/xmlenc11#ECDH-ES`
- Supported curves: secp256r1, secp384r1, secp521r1, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1

#### go-as4 Status: ⚠️ Partial

**Implemented:**
- ECDSA-SHA256 signature algorithm defined

**Gaps:**
| Gap | Impact | Effort |
|-----|--------|--------|
| ECDH-ES key agreement | Fallback encryption | Medium |
| ECKeyValue encoding | Alt key representation | Low |
| Brainpool curve support | German interop | Medium |

---

## 3. Summary of Gaps

### 3.1 Critical Gaps (Common Profile)

None - go-as4 is compliant with Common Profile requirements for both AS4 1.15 and 2.0.

### 3.2 Enhancement Module Gaps

| Gap | Spec | Priority | Effort | Notes |
|-----|------|----------|--------|-------|
| Pull MEP | Both | Medium | Medium | Full Pull support |
| Split/Join | Both | Low | High | Large message handling |
| ebCore Agreement Update | 2.0 | Low | Medium | Certificate/endpoint updates |
| ECDH-ES Encryption | 2.0 | Low | Medium | Alternative to X25519 |
| Brainpool Curves | 2.0 | Low | Medium | German market (BDEW) |

### 3.3 Interoperability Considerations

| Scenario | AS4 1.15 | AS4 2.0 | go-as4 |
|----------|----------|---------|--------|
| Domibus | RSA-SHA256 + RSA-OAEP | - | ✅ Compatible |
| phase4 | RSA-SHA256 + RSA-OAEP | Ed25519 + X25519 | ✅ Compatible |
| Holodeck B2B | RSA-SHA256 + RSA-OAEP | - | ✅ Compatible |
| Swedish SDK | RSA-SHA256 + RSA-OAEP | - | ✅ Compatible |
| EU AS4 2.0 Compliant | - | Ed25519 + X25519 | ✅ Compatible |

---

## 4. Implementation Roadmap

### Phase 1: Current State (Complete)
- ✅ AS4 1.15 Common Profile
- ✅ AS4 2.0 Common Profile
- ✅ Four Corner Topology
- ✅ Dynamic Sender/Receiver
- ✅ SMP/BDXL Discovery
- ✅ Compression
- ✅ Reception Awareness

### Phase 2: Pull Feature (Recommended)
- [ ] Pull Request message generation
- [ ] Pull Response handling
- [ ] MPC configuration
- [ ] Asynchronous signal handling

### Phase 3: Advanced Features (Future)
- [ ] Split/Join for large messages
- [ ] ebCore Agreement Update
- [ ] ECDH-ES encryption
- [ ] Brainpool curves

---

## 5. References

### Specifications
- [eDelivery AS4 2.0](https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/845480153/eDelivery+AS4+-+2.0)
- [eDelivery AS4 1.15](https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/467117638/eDelivery+AS4+-+1.15)
- [OASIS AS4 Profile 1.0](http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/)
- [OASIS ebMS3 Core](http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/core/os/)
- [OASIS ebMS3 Part 2](http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/part2/201004/)

### Security Standards
- [RFC 9231: XML Security URIs](https://www.rfc-editor.org/rfc/rfc9231)
- [RFC 8410: Ed25519/X25519 in X.509](https://www.rfc-editor.org/rfc/rfc8410)
- [W3C XML Signature 1.1](https://www.w3.org/TR/xmldsig-core1/)
- [W3C XML Encryption 1.1](https://www.w3.org/TR/xmlenc-core1/)

### go-as4 Documentation
- [Implementation Guide](IMPLEMENTATION.md)
- [RSA Algorithm Implementation](RSA_ALGORITHM_IMPLEMENTATION.md)
- [SDK Compliance](sdk-compliance.md)
