# Swedish SDK (Säker Digital Kommunikation) Compliance Analysis

## Overview

This document analyzes how `go-as4` can be used to build an accesspoint (AP) for the Swedish government's eDelivery federation "Säker Digital Kommunikation" (SDK). It identifies gaps in the current implementation and provides a roadmap for full compliance.

**SDK Version:** v1.2 (Transport Profile AS4 v1.2, effective 2024-11-18)  
**go-as4 Version:** Current development head  
**Document Date:** June 2025

## Table of Contents

1. [Federation Overview](#federation-overview)
2. [Technical Requirements Summary](#technical-requirements-summary)
3. [Current go-as4 Capabilities](#current-go-as4-capabilities)
4. [Gap Analysis](#gap-analysis)
5. [Implementation Plan](#implementation-plan)
6. [Example Configuration](#example-configuration)

---

## Federation Overview

Säker Digital Kommunikation (SDK) is Sweden's national eDelivery infrastructure managed by DIGG (Myndigheten för digital förvaltning). It enables secure message exchange between public sector organizations, businesses, and citizens.

### Key Characteristics

- **AS4 Profile:** Based on CEF eDelivery AS4 Profile 1.15
- **Discovery:** OASIS SMP 1.0 with BDXL DNS NAPTR lookup
- **Participant ID Scheme:** `iso6523-actorid-upis` (e.g., `0203:sdk-qa.digg.se`)
- **Transport Profile ID:** `digg-transport-as4-v1_2`
- **PKI:** Federation-specific certificates issued by DIGG's PKIAP (PKI för Accesspunkter)

### Environments

| Environment | SML Zone | Purpose |
|------------|----------|---------|
| Production | `edelivery.tech.ec.europa.eu` | Live traffic |
| QA | `acc.edelivery.tech.ec.europa.eu` | Testing |

---

## Technical Requirements Summary

### P-Mode Parameters (from AS4 Transport Profile v1.2)

| Parameter | Required Value |
|-----------|---------------|
| `PMode.MEP` | `http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/oneWay` |
| `PMode.MEPBinding` | `http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/push` |
| `PMode.Protocol.SOAPVersion` | 1.2 |
| `PMode.Protocol.Address.TransportProfile` | `digg-transport-as4-v1_2` |
| `PMode.Initiator/Responder.Party.type` | `urn:fdc:digg.se:edelivery:transportprofile:as4:partytype:ap` |
| `PMode.Initiator/Responder.Role` | `urn:fdc:digg.se:edelivery:transportprofile:as4:role:ap` |
| `PMode.BusinessInfo.Service.type` | `urn:fdc:digg.se:edelivery:process` |
| `PMode.Security.WSSVersion` | 1.1 |

### Message Properties (Required)

| Property | Type | Description |
|----------|------|-------------|
| `originalSender` | `urn:fdc:digg.se:edelivery:transportprofile:as4:partytype:participant` | Original message sender |
| `finalRecipient` | `urn:fdc:digg.se:edelivery:transportprofile:as4:partytype:participant` | Final message recipient |

### Security Requirements

#### Signing (Non-Repudiation of Origin)
- **Standard:** WS-Security 1.1, XML Signature
- **Algorithm:** RSA with SHA-256 minimum (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`)
- **Canonicalization:** Exclusive XML Canonicalization (`http://www.w3.org/2001/10/xml-exc-c14n#`)
- **Token Reference:** BinarySecurityToken

**Signed Elements:**
1. SOAP Body (empty but signed)
2. eb:Messaging header
3. wsu:Timestamp
4. MIME attachments (when present)

#### Encryption (Message Confidentiality)
- **Standard:** WS-Security 1.1, XML Encryption
- **Key Transport:** RSA-OAEP with MGF1 and SHA-256
- **Content Encryption:** AES-128-GCM
- **Encrypted:** MIME attachment payloads only (not SOAP envelope)

#### TLS Requirements
- **Grade:** SSL Labs A rating required
- **Port:** 443
- **Authentication:** One-way TLS (AP authenticates to sender) by default
- **mTLS:** Optional, can be configured bilaterally
- **Certificate:** Publicly trusted CA (e.g., Let's Encrypt)

#### PKI for Accesspoints (PKIAP)
- **CA:** DIGG-operated federation CA
- **Certificate Types:**
  - Signing certificate (for XML Signature)
  - Encryption certificate (for XML Encryption)
- **Revocation:** OCSP and CRL checking required
- **Publishing:** Certificates must be published in SMP

### Certificate Publishing in SMP

Certificates are published using SMP Extensions:

```xml
<Extension>
  <ExtensionID>urn:fdc:digg.se:edelivery:certpub</ExtensionID>
  <ExtensionName>CertificatePub</ExtensionName>
  <ExtensionAgencyID>DIGG</ExtensionAgencyID>
  <ExtensionAgencyName>Myndigheten för digital förvaltning</ExtensionAgencyName>
  <ExtensionAgencyURI>https://www.digg.se</ExtensionAgencyURI>
  <ExtensionVersionID>1.0</ExtensionVersionID>
  <!-- Certificate types -->
  <!-- urn:fdc:digg.se:edelivery:certpub:signing-cert -->
  <!-- urn:fdc:digg.se:edelivery:certpub:encryption-cert -->
</Extension>
```

### Message Envelope Format

SDK uses **XHE (XML Header Envelope)** as the business document wrapper:

```xml
<XHE xmlns="oasis:names:specification:ubl:schema:xsd:eDeliveryXHE-1">
  <XHEVersionID>1.0</XHEVersionID>
  <Header>
    <ID>...</ID>
    <CreationDateTime>...</CreationDateTime>
    <FromParty>...</FromParty>
    <ToParty>...</ToParty>
  </Header>
  <Payloads>
    <Payload>
      <!-- Business document -->
    </Payload>
  </Payloads>
</XHE>
```

### Operational Requirements

| Requirement | Specification |
|-------------|---------------|
| Message Size | Minimum 100 MB capacity |
| Compression | GZIP for payloads required |
| Availability | 99.5% uptime |
| Response Time | < 60 seconds for non-receipt errors |
| Retry Policy | Exponential backoff with configurable limits |
| Logging | Required fields: AP IDs, certificates, timestamps, participant IDs, Message ID, Conversation ID, errors |

### Error Handling

| Error Code | Description | When to Use |
|------------|-------------|-------------|
| `EBMS:0004` | NOT_SERVICED | Invalid recipient for this AP |
| `EBMS:0001` | ValueNotRecognized | Malformed message |
| `EBMS:0303` | DecompressionFailure | GZIP decompression failed |

---

## Current go-as4 Capabilities

### ✅ Fully Implemented

| Feature | Package | Notes |
|---------|---------|-------|
| SOAP 1.2 Envelope | `pkg/message` | Full support |
| ebMS3 Headers | `pkg/message` | UserMessage, SignalMessage, Receipt, Error |
| MEP OneWay/Push | `pkg/message` | Constants defined |
| RSA-SHA256 Signing | `pkg/security` | `RSASigner` with configurable hash |
| BinarySecurityToken | `pkg/security` | Default token reference |
| XML Canonicalization | `pkg/security` | Exclusive C14N with prefix lists |
| WS-Security 1.1 | `pkg/security` | Full header generation |
| Timestamp Signing | `pkg/security` | Included in signed elements |
| SMP 1.0 Client | `pkg/discovery` | ServiceGroup, ServiceMetadata |
| BDXL DNS Lookup | `pkg/discovery` | NAPTR record resolution |
| GZIP Compression | `pkg/compression` | Attachment compression |
| MIME Multipart | `pkg/mime` | AS4 MIME handling |
| P-Mode Configuration | `pkg/pmode` | Full P-Mode structures |
| MSH (Message Service Handler) | `pkg/msh` | Async send/receive with retry |
| HTTPS Transport | `pkg/transport` | TLS client with cert support |
| Certificate Validation | `pkg/security` | Basic PKI validation |

### ⚠️ Partially Implemented

| Feature | Package | Status | Gap |
|---------|---------|--------|-----|
| RSA-OAEP Encryption | `pkg/security` | X25519 primary | Need RSA-OAEP for SDK |
| MessageProperties | `pkg/message` | Basic support | Need originalSender/finalRecipient convenience |
| ConversationId | `pkg/message` | In CollaborationInfo | Need tracking/correlation |
| Error Generation | `pkg/message` | Basic Error struct | Need SDK-specific error codes |

### ❌ Not Implemented

| Feature | Priority | Description |
|---------|----------|-------------|
| XHE Envelope | High | XML Header Envelope parsing/generation |
| OCSP/CRL Revocation | High | Certificate revocation checking |
| SMP Extension Parsing | High | DIGG certificate publishing format |
| SDK P-Mode Presets | Medium | Pre-configured SDK P-Modes |
| Logging Framework | Medium | SDK-compliant audit logging |
| AES-128-GCM for RSA | Medium | SDK encryption algorithm |

---

## Gap Analysis

### Gap 1: XHE (XML Header Envelope) Support

**Priority:** High  
**Effort:** Medium (2-3 days)

SDK requires all business documents to be wrapped in XHE envelopes. This provides:
- Standard routing metadata (FromParty, ToParty)
- Multiple payload support
- Cross-profile interoperability

**Required Implementation:**

```go
// pkg/xhe/xhe.go
package xhe

type XHE struct {
    XMLName           xml.Name   `xml:"oasis:names:specification:ubl:schema:xsd:eDeliveryXHE-1 XHE"`
    XHEVersionID      string     `xml:"XHEVersionID"`
    CustomizationID   string     `xml:"CustomizationID,omitempty"`
    ProfileID         string     `xml:"ProfileID,omitempty"`
    Header            Header     `xml:"Header"`
    Payloads          Payloads   `xml:"Payloads"`
}

type Header struct {
    ID                string     `xml:"ID"`
    CreationDateTime  time.Time  `xml:"CreationDateTime"`
    FromParty         Party      `xml:"FromParty"`
    ToParty           []Party    `xml:"ToParty"`
}

type Payloads struct {
    Payload []Payload `xml:"Payload"`
}

type Payload struct {
    ID              string `xml:"ID,omitempty"`
    ContentTypeCode string `xml:"ContentTypeCode,omitempty"`
    Content         []byte `xml:",innerxml"`
}
```

### Gap 2: OCSP/CRL Certificate Revocation Checking

**Priority:** High  
**Effort:** Medium (2-3 days)

SDK requires real-time certificate revocation checking via OCSP with CRL fallback.

**Required Implementation:**

```go
// pkg/security/revocation.go
package security

type RevocationChecker interface {
    CheckRevocation(cert *x509.Certificate) (bool, error)
}

type OCSPRevocationChecker struct {
    httpClient *http.Client
    crlCache   *CRLCache
    fallback   bool // Use CRL if OCSP fails
}

func (c *OCSPRevocationChecker) CheckRevocation(cert *x509.Certificate) (bool, error) {
    // 1. Try OCSP responder from AIA extension
    // 2. Fall back to CRL if configured
    // 3. Return error if neither available
}
```

### Gap 3: SMP Extension Parsing for Certificate Publishing

**Priority:** High  
**Effort:** Low (1 day)

SDK publishes signing and encryption certificates via SMP Extensions. Need to parse these.

**Required Changes to `pkg/discovery/smp.go`:**

```go
// Add to Endpoint struct
type Endpoint struct {
    // ... existing fields ...
    Extensions []Extension
}

type Extension struct {
    ExtensionID   string
    Name          string
    AgencyID      string
    Value         []byte
}

// SDK-specific certificate types
const (
    ExtensionSigningCert    = "urn:fdc:digg.se:edelivery:certpub:signing-cert"
    ExtensionEncryptionCert = "urn:fdc:digg.se:edelivery:certpub:encryption-cert"
)

func (e *Endpoint) GetSigningCertificate() (*x509.Certificate, error)
func (e *Endpoint) GetEncryptionCertificate() (*x509.Certificate, error)
```

### Gap 4: RSA-OAEP Encryption for Attachments

**Priority:** High  
**Effort:** Medium (2 days)

Current implementation uses X25519/ECDH for key agreement (EU AS4 2.0). SDK requires RSA-OAEP.

**Required Implementation:**

```go
// pkg/security/rsa_encryptor.go - Extend existing
type RSAEncryptor struct {
    recipientCert     *x509.Certificate
    contentAlgorithm  string // AES-128-GCM or AES-128-CBC
    keyTransport      string // RSA-OAEP with SHA-256
}

func (e *RSAEncryptor) EncryptPayloads(payloads []PayloadData) (*EncryptionResult, error)
```

### Gap 5: SDK P-Mode Factory

**Priority:** Medium  
**Effort:** Low (1 day)

Pre-configured P-Modes for SDK federation.

**Required Implementation:**

```go
// pkg/sdk/pmode.go
package sdk

func NewSDKPMode(opts SDKPModeOptions) *pmode.ProcessingMode {
    return &pmode.ProcessingMode{
        ID:         opts.PModeID,
        MEP:        message.MEPOneWay,
        MEPBinding: message.MEPBindingPush,
        Security: &pmode.Security{
            WSSVersion: "1.1",
            X509: &pmode.X509Config{
                Sign: &pmode.SignConfig{
                    Algorithm:      pmode.AlgoRSASHA256,
                    HashFunction:   pmode.HashSHA256,
                    TokenReference: pmode.TokenRefBinarySecurityToken,
                    SignAttachments: true,
                },
                Encryption: &pmode.EncryptionConfig{
                    Algorithm:          pmode.KeyAlgoRSAOAEP256,
                    DataEncryption:     pmode.DataAlgoAES128GCM,
                    EncryptAttachments: true,
                },
            },
        },
        // ... SDK-specific defaults ...
    }
}
```

### Gap 6: Audit Logging Framework

**Priority:** Medium  
**Effort:** Medium (2 days)

SDK requires specific logging fields for compliance and troubleshooting.

**Required Implementation:**

```go
// pkg/logging/audit.go
package logging

type AuditLog struct {
    Timestamp       time.Time
    MessageID       string
    ConversationID  string
    FromAP          string
    ToAP            string
    OriginalSender  string
    FinalRecipient  string
    Action          string
    Status          string
    ErrorCode       string
    ErrorDetail     string
    SigningCertSN   string
    EncryptCertSN   string
}

type AuditLogger interface {
    LogMessageSent(log *AuditLog) error
    LogMessageReceived(log *AuditLog) error
    LogError(log *AuditLog) error
}
```

---

## Implementation Plan

### Phase 1: Core Compliance (Week 1-2)

| Task | Priority | Effort | Dependency |
|------|----------|--------|------------|
| XHE Envelope Support | High | 2d | None |
| OCSP/CRL Revocation | High | 2d | None |
| SMP Extension Parsing | High | 1d | None |
| RSA-OAEP Encryption | High | 2d | None |

**Deliverable:** Basic SDK message exchange working

### Phase 2: Integration Features (Week 3)

| Task | Priority | Effort | Dependency |
|------|----------|--------|------------|
| SDK P-Mode Factory | Medium | 1d | Phase 1 |
| Audit Logging | Medium | 2d | None |
| Error Code Mapping | Medium | 1d | None |

**Deliverable:** Production-ready SDK client

### Phase 3: Testing & Documentation (Week 4)

| Task | Priority | Effort | Dependency |
|------|----------|--------|------------|
| Integration Tests | High | 2d | Phase 2 |
| DIGG QA Environment | High | 2d | Phase 2 |
| Documentation | Medium | 1d | Phase 2 |

**Deliverable:** Validated SDK compliance

---

## Example Configuration

### Complete SDK Client Setup

```go
package main

import (
    "context"
    "crypto/x509"
    "log"

    "github.com/sirosfoundation/go-as4/pkg/discovery"
    "github.com/sirosfoundation/go-as4/pkg/msh"
    "github.com/sirosfoundation/go-as4/pkg/pmode"
    "github.com/sirosfoundation/go-as4/pkg/sdk"
    "github.com/sirosfoundation/go-as4/pkg/security"
    "github.com/sirosfoundation/go-as4/pkg/transport"
)

func main() {
    // Load certificates from PKIAP
    signingKey, signingCert, _ := loadPKCS12("ap-signing.p12", "password")
    encryptionKey, encryptionCert, _ := loadPKCS12("ap-encryption.p12", "password")

    // Create RSA signer for XML Signature
    signer, _ := security.NewRSASigner(signingKey, signingCert, crypto.SHA256)

    // Create RSA encryptor for payloads
    // Note: Recipient cert is fetched from SMP at send time
    
    // Create revocation checker
    revocationChecker := security.NewOCSPRevocationChecker(
        security.WithCRLFallback(true),
        security.WithCacheTimeout(24 * time.Hour),
    )

    // Set up certificate validator with revocation
    certValidator := security.NewDefaultCertificateValidator(rootPool)
    certValidator.WithRevocationChecker(revocationChecker)
    signer.WithCertificateValidator(certValidator)

    // Create SDK-specific P-Mode
    sdkPMode := sdk.NewSDKPMode(sdk.SDKPModeOptions{
        APPartyID:    "0203:my-accesspoint",
        ServiceType:  "urn:fdc:digg.se:edelivery:process",
        Service:      "my-service",
        Action:       "submit",
    })

    // Configure SMP client with BDXL
    smpClient := discovery.NewSMPClient()
    bdxlResolver := discovery.NewBDXLResolver(discovery.BDXLConfig{
        SMLZone: "acc.edelivery.tech.ec.europa.eu", // QA environment
    })
    
    // Create dynamic endpoint resolver
    resolver := msh.NewDynamicResolver(bdxlResolver, smpClient, discovery.SMPV1)

    // Create HTTPS transport with TLS
    httpClient := transport.NewHTTPSClient(transport.Config{
        TLSConfig: &tls.Config{
            MinVersion: tls.VersionTLS12,
        },
        Timeout: 60 * time.Second,
    })

    // Create Message Service Handler
    handler, _ := msh.NewMSH(msh.MSHConfig{
        Resolver: resolver,
        PModeRegistry: map[string]*pmode.ProcessingMode{
            sdkPMode.ID: sdkPMode,
        },
        Signer:     signer,
        HTTPClient: httpClient,
        RetryMaxAttempts: 3,
        RetryDelay:       5 * time.Second,
    })

    // Start MSH
    handler.Start(context.Background())
    defer handler.Stop()

    // Send a message
    msg := &msh.OutboundMessage{
        PModeID: sdkPMode.ID,
        To: msh.PartyInfo{
            PartyID: "0203:recipient-org",
            Role:    "urn:fdc:digg.se:edelivery:transportprofile:as4:role:ap",
        },
        MessageProperties: []message.Property{
            {Name: "originalSender", Type: "urn:fdc:digg.se:edelivery:transportprofile:as4:partytype:participant", Value: "0203:sender-org"},
            {Name: "finalRecipient", Type: "urn:fdc:digg.se:edelivery:transportprofile:as4:partytype:participant", Value: "0203:recipient-org"},
        },
        Payloads: []msh.Payload{
            {
                ContentType: "application/xml",
                Data:        xheEnvelope, // XHE-wrapped business document
            },
        },
    }

    err := handler.SendMessage(context.Background(), msg)
    if err != nil {
        log.Fatalf("Failed to send: %v", err)
    }
}
```

### XHE Envelope Creation Example

```go
package main

import (
    "encoding/xml"
    "time"

    "github.com/sirosfoundation/go-as4/pkg/xhe"
)

func createXHEEnvelope(businessDoc []byte, from, to string) ([]byte, error) {
    envelope := &xhe.XHE{
        XHEVersionID:    "1.0",
        CustomizationID: "urn:fdc:digg.se:edelivery:xhe:1.0",
        Header: xhe.Header{
            ID:               generateUUID(),
            CreationDateTime: time.Now().UTC(),
            FromParty: xhe.Party{
                PartyID: xhe.PartyID{
                    Scheme: "iso6523-actorid-upis",
                    Value:  from,
                },
            },
            ToParty: []xhe.Party{
                {
                    PartyID: xhe.PartyID{
                        Scheme: "iso6523-actorid-upis",
                        Value:  to,
                    },
                },
            },
        },
        Payloads: xhe.Payloads{
            Payload: []xhe.Payload{
                {
                    ID:              "payload-1",
                    ContentTypeCode: "application/xml",
                    Content:         businessDoc,
                },
            },
        },
    }

    return xml.MarshalIndent(envelope, "", "  ")
}
```

### Receiving Messages with Certificate Validation

```go
package main

import (
    "context"
    "log"
    "net/http"

    "github.com/sirosfoundation/go-as4/pkg/msh"
    "github.com/sirosfoundation/go-as4/pkg/security"
)

func main() {
    // Load PKIAP root certificates
    rootPool := x509.NewCertPool()
    rootPool.AppendCertsFromPEM(pkiapRootCerts)

    // Create verifier with revocation checking
    revocationChecker := security.NewOCSPRevocationChecker(
        security.WithCRLFallback(true),
    )
    
    validator := security.NewDefaultCertificateValidator(rootPool)
    validator.WithRevocationChecker(revocationChecker)

    // Create RSA verifier (no private key needed for receiving)
    verifier, _ := security.NewRSAVerifier(nil, crypto.SHA256, crypto.SHA256, security.SignatureModePKCS1v15)
    verifier.WithCertificateValidator(validator)

    // Create receiver MSH
    receiver, _ := msh.NewMSH(msh.MSHConfig{
        // ... config ...
        MessageHandler: func(ctx context.Context, msg *msh.InboundMessage) error {
            // Validate sender certificate
            if err := validator.ValidateCertificate(msg.SignerCert, nil, "signing"); err != nil {
                log.Printf("Certificate validation failed: %v", err)
                return msh.NewAS4Error("EBMS:0101", "Certificate validation failed")
            }

            // Process XHE envelope
            xheDoc, err := xhe.Parse(msg.Payloads[0].Data)
            if err != nil {
                return msh.NewAS4Error("EBMS:0001", "Invalid XHE envelope")
            }

            // Check if we serve the recipient
            recipientID := xheDoc.Header.ToParty[0].PartyID.Value
            if !isServedParticipant(recipientID) {
                return msh.NewAS4Error("EBMS:0004", "NOT_SERVICED: Unknown recipient")
            }

            // Deliver to backend
            return deliverToBackend(xheDoc)
        },
    })

    // Start HTTP server for receiving
    http.HandleFunc("/as4", receiver.HTTPHandler())
    log.Fatal(http.ListenAndServeTLS(":443", "tls-cert.pem", "tls-key.pem", nil))
}
```

---

## References

- [DIGG SDK för Accesspunktsoperatörer](https://www.digg.se/saker-digital-kommunikation/sdk-for-accesspunktsoperatorer)
- [AS4 Transport Profile v1.2](https://www.digg.se/saker-digital-kommunikation/sdk-for-accesspunktsoperatorer/tekniska-specifikationer-for-accesspunkt/transportprofil-as4)
- [PKI för Accesspunkter](https://www.digg.se/saker-digital-kommunikation/sdk-for-accesspunktsoperatorer/tekniska-specifikationer-for-accesspunkt/pki-for-accesspunkter---komponentspecifikation)
- [Certifikatspublicering (SMP)](https://www.digg.se/saker-digital-kommunikation/sdk-for-accesspunktsoperatorer/tekniska-specifikationer-for-accesspunkt/certifikatspublicering-rest-bindning-till-smp)
- [Accesspunktsoperatör Regler och Rutiner](https://www.digg.se/saker-digital-kommunikation/sdk-for-accesspunktsoperatorer/anslutningsavtal-regelverk-samt-bilagor/accesspunktsoperator---gemensamma-regler-och-rutiner)
- [CEF eDelivery AS4 Profile 1.15](https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/eDelivery+AS4+-+1.15)
- [OASIS SMP 1.0](https://docs.oasis-open.org/bdxr/bdx-smp/v1.0/)
