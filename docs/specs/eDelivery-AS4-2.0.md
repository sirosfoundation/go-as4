# eDelivery AS4 2.0 Profile Specification

**Version**: 2.0  
**Adopted**: December 4, 2024  
**Source**: EC Digital Building Blocks  
**License**: EUPL 1.2

---

## 1. Introduction

### 1.1 Purpose
The eDelivery AS4 profile constrains the OASIS ebMS3.0/AS4 specifications to achieve interoperability with modern security characteristics for the eDelivery ecosystem.

### 1.2 Scope
This profile defines implementation requirements for:
- Message exchange patterns
- Security mechanisms (signature and encryption)
- Reliability features
- Multi-hop routing (Four Corner model)
- Dynamic discovery integration

### 1.3 Conformance
Conformance is defined through three levels:
1. **Common Profile** (Section 4) - Mandatory baseline
2. **Feature Conformance** (Section 5) - Optional enhancements
3. **Security Profile** (Section 3) - Cryptographic requirements

---

## 2. Normative References

### 2.1 OASIS Standards
- **[ebMS3-CORE]**: OASIS ebMS 3.0 Core Specification, October 2007 / ISO 15000-1:2021
- **[AS4-PROFILE]**: OASIS AS4 Profile of ebMS 3.0 v1.0, January 2013 / ISO 15000-2:2021
- **[ebMS3-PART2]**: ebMS Version 3.0 Part 2: Advanced Features, May 2011

### 2.2 W3C Standards  
- **[XMLDSIG-11]**: XML Signature 1.1, W3C Recommendation
- **[XMLENC-11]**: XML Encryption 1.1, W3C Recommendation
- **[EXC-C14N]**: Exclusive XML Canonicalization 1.0, W3C Recommendation

### 2.3 OASIS WS-Security
- **[WSS-SOAP]**: WS-Security SOAP Message Security 1.1.1
- **[WSS-X509]**: WS-Security X.509 Certificate Token Profile 1.1.1
- **[WSS-SWA]**: WS-Security SwA Profile 1.1.1

### 2.4 IETF
- **[RFC9231bis]**: XML Security URIs (Ed25519, X25519, HKDF algorithms)

---

## 3. Security Profile

### 3.1 Cryptographic Algorithms - EdDSA Suite (Common Profile)

#### 3.1.1 Digital Signature
```
Algorithm:    EdDSA with Ed25519
URI:          http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519
Key Size:     256 bits (fixed)
Reference:    RFC 9231bis Section 2.5.1
```

#### 3.1.2 Digest Algorithm
```
Algorithm:    SHA-256
URI:          http://www.w3.org/2001/04/xmlenc#sha256
Reference:    RFC 4634
```

#### 3.1.3 Key Agreement
```
Algorithm:    X25519 ECDH
URI:          http://www.w3.org/2021/04/xmldsig-more#x25519
Key Size:     256 bits (fixed)
Reference:    RFC 9231bis Section 4.3.1
```

#### 3.1.4 Key Derivation Function
```
Algorithm:    HKDF with HMAC-SHA-256
URI:          http://www.w3.org/2021/04/xmldsig-more#hkdf
Parameters:   
  - PRK from X25519 shared secret
  - Salt: Recipient's ephemeral public key
  - Info: AES key wrap algorithm URI
Reference:    RFC 5869, RFC 9231bis Section 4.4.1
```

#### 3.1.5 Key Wrapping
```
Algorithm:    AES-128 Key Wrap
URI:          http://www.w3.org/2001/04/xmlenc#kw-aes128
Reference:    RFC 3394
```

#### 3.1.6 Content Encryption
```
Algorithm:    AES-128-GCM
URI:          http://www.w3.org/2009/xmlenc11#aes128-gcm
Key Size:     128 bits
Reference:    NIST SP 800-38D
```

#### 3.1.7 Canonicalization
```
Algorithm:    Exclusive C14N
URI:          http://www.w3.org/2001/10/xml-exc-c14n#
Reference:    W3C Exclusive C14N
```

### 3.2 Alternative ECC Suite

For implementations that cannot support Ed25519/X25519:

#### 3.2.1 Digital Signature (Alternative)
```
Algorithm:    ECDSA with P-256 or BrainpoolP256r1
URI:          http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256
Curves:       secp256r1 (P-256) or BrainpoolP256r1
```

#### 3.2.2 Key Agreement (Alternative)
```
Algorithm:    ECDH-ES with secp256r1 or BrainpoolP256r1
URI:          Curve-specific OIDs
```

### 3.3 TLS Requirements

| Protocol | Status |
|----------|--------|
| SSL 3.0 | MUST NOT |
| TLS 1.0 | MUST NOT |
| TLS 1.1 | MUST NOT |
| TLS 1.2 | MUST |
| TLS 1.3 | SHOULD |

Certificate requirements:
- RSA keys: > 3000 bits
- ECDSA keys: ≥ 250 bits (P-256 or BrainpoolP256r1)

---

## 4. Common Profile (Mandatory)

### 4.1 Message Exchange Patterns

#### 4.1.1 Supported MEPs
```
One-Way:  http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/oneWay
Two-Way:  http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/twoWay
```

#### 4.1.2 MEP Binding
```
Push:  http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/push
```

### 4.2 P-Mode Parameters

#### 4.2.1 Protocol
| Parameter | Value |
|-----------|-------|
| PMode.MEPBinding | `push` |
| PMode[].Protocol.Address | HTTPS URL |
| PMode[].Protocol.SOAPVersion | 1.2 |

#### 4.2.2 Business Info
| Parameter | Requirement |
|-----------|-------------|
| PMode[].BusinessInfo.Service | REQUIRED |
| PMode[].BusinessInfo.Action | REQUIRED |
| PMode[].BusinessInfo.Properties | As per agreement |

#### 4.2.3 Error Handling
| Parameter | Value |
|-----------|-------|
| PMode[].ErrorHandling.Report.SenderErrors | True |
| PMode[].ErrorHandling.Report.ReceiverErrors | True |
| PMode[].ErrorHandling.Report.AsResponse | True |
| PMode[].ErrorHandling.Report.ProcessErrorNotifyConsumer | True |
| PMode[].ErrorHandling.Report.ProcessErrorNotifyProducer | True |

#### 4.2.4 Security
| Parameter | Value |
|-----------|-------|
| PMode[].Security.WSSVersion | 1.1.1 |
| PMode[].Security.X509.Sign.Certificate | Signing certificate |
| PMode[].Security.X509.Sign.HashFunction | SHA-256 |
| PMode[].Security.X509.Encryption.Certificate | Encryption certificate |
| PMode[].Security.X509.Encryption.Algorithm | See Section 3 |
| PMode[].Security.SendReceipt | True |
| PMode[].Security.SendReceipt.NonRepudiation | True |
| PMode[].Security.SendReceipt.ReplyPattern | Response |

#### 4.2.5 Payload Handling
| Parameter | Value |
|-----------|-------|
| PMode[].PayloadService.CompressionType | application/gzip |

#### 4.2.6 Reception Awareness
| Parameter | Value |
|-----------|-------|
| PMode[].ReceptionAwareness | True |
| PMode[].ReceptionAwareness.Retry.Parameters | Max retries and interval |
| PMode[].ReceptionAwareness.DuplicateDetection | True |

### 4.3 Message Structure

#### 4.3.1 SOAP Envelope
```xml
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Header>
    <eb:Messaging xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
      <!-- UserMessage or SignalMessage -->
    </eb:Messaging>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <!-- Security header -->
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    <!-- Empty for messages with attachments -->
  </soap:Body>
</soap:Envelope>
```

#### 4.3.2 UserMessage Elements
```xml
<eb:UserMessage>
  <eb:MessageInfo>
    <eb:Timestamp>2024-12-04T10:30:00.000Z</eb:Timestamp>
    <eb:MessageId>unique-message-id@sender.example</eb:MessageId>
  </eb:MessageInfo>
  <eb:PartyInfo>
    <eb:From>
      <eb:PartyId type="urn:oasis:names:tc:ebcore:partyid-type:unregistered">sender</eb:PartyId>
      <eb:Role>http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/initiator</eb:Role>
    </eb:From>
    <eb:To>
      <eb:PartyId type="urn:oasis:names:tc:ebcore:partyid-type:unregistered">receiver</eb:PartyId>
      <eb:Role>http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/responder</eb:Role>
    </eb:To>
  </eb:PartyInfo>
  <eb:CollaborationInfo>
    <eb:Service type="...">service</eb:Service>
    <eb:Action>action</eb:Action>
    <eb:ConversationId>conversation-id</eb:ConversationId>
  </eb:CollaborationInfo>
  <eb:MessageProperties>
    <!-- Four Corner properties if applicable -->
    <eb:Property name="originalSender">original-sender-id</eb:Property>
    <eb:Property name="finalRecipient">final-recipient-id</eb:Property>
    <eb:Property name="trackingIdentifier">tracking-id</eb:Property>
  </eb:MessageProperties>
  <eb:PayloadInfo>
    <eb:PartInfo href="cid:attachment@example">
      <eb:PartProperties>
        <eb:Property name="CompressionType">application/gzip</eb:Property>
        <eb:Property name="MimeType">application/xml</eb:Property>
      </eb:PartProperties>
    </eb:PartInfo>
  </eb:PayloadInfo>
</eb:UserMessage>
```

#### 4.3.3 Receipt Signal
```xml
<eb:SignalMessage>
  <eb:MessageInfo>
    <eb:Timestamp>2024-12-04T10:30:01.000Z</eb:Timestamp>
    <eb:MessageId>receipt-id@receiver.example</eb:MessageId>
    <eb:RefToMessageId>original-message-id@sender.example</eb:RefToMessageId>
  </eb:MessageInfo>
  <eb:Receipt>
    <ebbp:NonRepudiationInformation xmlns:ebbp="http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0">
      <ebbp:MessagePartNRInformation>
        <ebbp:MessagePartIdentifier>cid:attachment@example</ebbp:MessagePartIdentifier>
        <!-- Reference to signed digest -->
      </ebbp:MessagePartNRInformation>
    </ebbp:NonRepudiationInformation>
  </eb:Receipt>
</eb:SignalMessage>
```

---

## 5. Profile Enhancements (Optional)

### 5.1 Four Corner Model
For multi-hop scenarios with Access Points:
- `originalSender` property: URN of original sending party
- `finalRecipient` property: URN of final receiving party
- `trackingIdentifier` property: Optional tracking reference

### 5.2 Dynamic Receiver (SMP Lookup)
Discovery of receiver endpoint via SMP:
- Query SMP for recipient's AS4 endpoint
- Retrieve and validate certificate from SMP

### 5.3 Dynamic Sender (ebCore Agreement)
Sender identification via ebCore Agreement:
- AgreementRef element references ebCore Agreement
- Recipient validates sender against agreement

### 5.4 Pull Model
Receiver-initiated message retrieval:
```
MEPBinding: http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/pull
```

### 5.5 Split/Join
Large message fragmentation per ebMS Part 2:
- Fragment large messages
- Reassemble at receiver
- Reference: ebMS3-PART2 Section 8

### 5.6 ebCore Agreement Update
Dynamic P-Mode updates via ebCore:
- Update receiver endpoint
- Update certificates
- Update service parameters

---

## 6. Conformance Clauses

### 6.1 Sending MSH

| Clause | Requirement |
|--------|-------------|
| S01 | MUST generate valid ebMS3 UserMessage |
| S02 | MUST sign SOAP Body and all attachments |
| S03 | MUST encrypt payloads when configured |
| S04 | MUST apply GZIP compression |
| S05 | MUST use SOAP 1.2 |
| S06 | MUST support retry mechanism |
| S07 | MUST include MessageId as UUID |
| S08 | MUST include Timestamp |

### 6.2 Receiving MSH

| Clause | Requirement |
|--------|-------------|
| R01 | MUST validate ebMS3 message structure |
| R02 | MUST verify all signatures |
| R03 | MUST decrypt encrypted payloads |
| R04 | MUST decompress GZIP payloads |
| R05 | MUST detect duplicates |
| R06 | MUST send Receipt when configured |
| R07 | MUST send Error signals on failure |
| R08 | MUST validate against P-Mode |

---

## 7. Error Codes

### 7.1 ebMS Error Codes
| Code | Short Description |
|------|------------------|
| EBMS:0001 | ValueNotRecognized |
| EBMS:0002 | FeatureNotSupported |
| EBMS:0003 | ValueInconsistent |
| EBMS:0004 | Other |
| EBMS:0005 | ConnectionFailure |
| EBMS:0006 | EmptyMessagePartitionChannel |
| EBMS:0007 | MimeInconsistency |
| EBMS:0008 | FeatureNotSupported |
| EBMS:0009 | InvalidHeader |
| EBMS:0010 | ProcessingModeMismatch |
| EBMS:0011 | ExternalPayloadError |

### 7.2 Security Error Codes
| Code | Short Description |
|------|------------------|
| EBMS:0101 | FailedAuthentication |
| EBMS:0102 | FailedDecryption |
| EBMS:0103 | PolicyNoncompliance |

---

## 8. Implementation Notes

### 8.1 Message ID Format
```
MessageId ::= UUID "@" domain
Example: 550e8400-e29b-41d4-a716-446655440000@sender.example.com
```

### 8.2 Content-Id Header
```
Content-ID: <attachment-id@sender.example>
Reference: cid:attachment-id@sender.example
```

### 8.3 MIME Multipart Structure
```
Content-Type: multipart/related; 
  type="application/soap+xml";
  boundary="----=_Part_0";
  start="<root.message@sender.example>"

------=_Part_0
Content-Type: application/soap+xml; charset=UTF-8
Content-Transfer-Encoding: binary
Content-ID: <root.message@sender.example>

[SOAP Envelope]

------=_Part_0
Content-Type: application/gzip
Content-Transfer-Encoding: binary
Content-ID: <attachment-id@sender.example>
Content-Description: Compressed payload

[GZIP compressed data]
------=_Part_0--
```

### 8.4 Signature Coverage

The Security header MUST contain a Signature covering:
1. SOAP Body (via ID reference)
2. Each attachment (via cid: reference with SwA transform)
3. Timestamp (via ID reference)
4. Messaging header (via ID reference)

---

## 9. Test Cases

### 9.1 TC00 - Connectivity
Basic TLS handshake and endpoint availability.

### 9.2 TC01 - Minimal Message
UserMessage with:
- No payload
- Signature only (no encryption)
- Basic PartyInfo, CollaborationInfo

### 9.3 TC02 - ENTSOG Single Payload
UserMessage with:
- One XML payload (Edig@s)
- Signature AND encryption
- GZIP compression

### 9.4 TC03 - OOTS Two Payloads  
UserMessage with:
- Two payloads (XML + PDF)
- Signature AND encryption
- GZIP compression on each

---

## Appendix A: Namespace URIs

```
ebMS 3.0:     http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/
SOAP 1.2:     http://www.w3.org/2003/05/soap-envelope
WSS:          http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd
WSU:          http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd
DS:           http://www.w3.org/2000/09/xmldsig#
DS11:         http://www.w3.org/2009/xmldsig11#
XENC:         http://www.w3.org/2001/04/xmlenc#
XENC11:       http://www.w3.org/2009/xmlenc11#
ebbp:         http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0
```

---

## Appendix B: Algorithm URIs

### Signature
| Algorithm | URI |
|-----------|-----|
| Ed25519 | `http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519` |
| ECDSA-SHA256 | `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256` |
| RSA-SHA256 | `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` |

### Digest
| Algorithm | URI |
|-----------|-----|
| SHA-256 | `http://www.w3.org/2001/04/xmlenc#sha256` |

### Key Agreement
| Algorithm | URI |
|-----------|-----|
| X25519 | `http://www.w3.org/2021/04/xmldsig-more#x25519` |
| ECDH-ES P-256 | `http://www.w3.org/2001/04/xmlenc#ecdh-es` |

### Key Derivation
| Algorithm | URI |
|-----------|-----|
| HKDF-SHA256 | `http://www.w3.org/2021/04/xmldsig-more#hkdf` |
| ConcatKDF | `http://www.w3.org/2009/xmlenc11#ConcatKDF` |

### Key Wrapping
| Algorithm | URI |
|-----------|-----|
| AES-128-KW | `http://www.w3.org/2001/04/xmlenc#kw-aes128` |
| AES-256-KW | `http://www.w3.org/2001/04/xmlenc#kw-aes256` |

### Encryption
| Algorithm | URI |
|-----------|-----|
| AES-128-GCM | `http://www.w3.org/2009/xmlenc11#aes128-gcm` |
| AES-256-GCM | `http://www.w3.org/2009/xmlenc11#aes256-gcm` |

### Canonicalization
| Algorithm | URI |
|-----------|-----|
| Exclusive C14N | `http://www.w3.org/2001/10/xml-exc-c14n#` |
| Exclusive C14N w/comments | `http://www.w3.org/2001/10/xml-exc-c14n#WithComments` |

### Transform
| Transform | URI |
|-----------|-----|
| Enveloped Signature | `http://www.w3.org/2000/09/xmldsig#enveloped-signature` |
| Attachment-Content | `http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform` |
| Attachment-Complete | `http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Complete-Signature-Transform` |
