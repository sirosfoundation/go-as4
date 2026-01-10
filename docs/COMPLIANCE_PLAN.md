# go-as4 eDelivery AS4 2.0 Compliance Plan

**Document Version**: 1.0  
**Date**: 2025-01-19  
**Target**: Full compliance with EU eDelivery AS4 2.0 profile

---

## Executive Summary

This document outlines the work required to bring `go-as4` to full compliance with the EU eDelivery AS4 2.0 profile adopted December 4, 2024. The plan is based on gap analysis against the specification requirements documented in [eDelivery-AS4-2.0.md](specs/eDelivery-AS4-2.0.md).

### Current State

- **Signature (Ed25519)**: ✅ Implemented and tested with phase4
- **Signature Verification**: ✅ Working (4/5 interop tests passing)
- **XML Encryption Library**: ✅ Available in `signedxml/xmlenc`
- **Receipt Generation**: ✅ Basic implementation exists
- **MIME Multipart**: ✅ Basic handling implemented
- **Payload Compression**: ✅ GZIP compression available

### Key Gaps

1. **WS-Security Encryption Integration** - Need to wire up `xmlenc` into WS-Security flow
2. **MIME Attachment Parsing** - Failed on TC03 (two payload test)
3. **NonRepudiationInformation Receipt** - Basic receipt, needs NRI structure
4. **Pull Model** - Stubbed but not implemented
5. **Alternative ECC** - Not yet supported

---

## Gap Analysis

### 1. Security Module (`pkg/security/`)

| Requirement | Status | File(s) | Notes |
|-------------|--------|---------|-------|
| Ed25519 Signature | ✅ | `ed25519_signer.go` | RFC 9231 compliant |
| SHA-256 Digest | ✅ | `ed25519_signer.go` | Standard |
| RSA-SHA256 (legacy) | ✅ | `rsa_signer.go` | Phase4 interop |
| Exclusive C14N | ✅ | Via signedxml | With InclusiveNamespaces |
| BinarySecurityToken | ✅ | `ed25519_signer.go`, `as4_signer.go` | Working |
| X509KeyIdentifier | ✅ | `ed25519_signer.go` | Implemented |
| **X25519 Key Agreement** | ⚠️ | `xmlenc_adapter.go` | API exists, not in WS-Sec flow |
| **HKDF Key Derivation** | ⚠️ | `xmlenc_adapter.go` | API exists, not in WS-Sec flow |
| **AES-128-KW** | ⚠️ | `signedxml/xmlenc` | In library, not integrated |
| **AES-128-GCM** | ⚠️ | `encryption.go` | Basic, needs WS-Sec |
| **EncryptedKey in Security Header** | ❌ | - | Not implemented |
| **DataReference to attachments** | ❌ | - | Not implemented |
| ECDSA P-256 (alternative) | ❌ | - | Not implemented |
| ECDH-ES P-256 (alternative) | ❌ | - | Not implemented |

### 2. Message Module (`pkg/message/`)

| Requirement | Status | File(s) | Notes |
|-------------|--------|---------|-------|
| UserMessage structure | ✅ | `types.go` | Complete |
| SignalMessage/Receipt | ✅ | `types.go` | Basic structure |
| Error signal | ✅ | `types.go` | Basic structure |
| MessageInfo | ✅ | `types.go` | Complete |
| PartyInfo | ✅ | `types.go` | Complete |
| CollaborationInfo | ✅ | `types.go` | Complete |
| PayloadInfo/PartInfo | ✅ | `types.go` | Complete |
| MessageProperties | ✅ | `types.go` | Complete |
| **Four Corner Properties** | ⚠️ | - | Can use MessageProperties, needs helpers |
| **NonRepudiationInformation** | ❌ | - | Receipt content not structured |
| Pull signal | ❌ | - | Not implemented |

### 3. MIME Module (`pkg/mime/`)

| Requirement | Status | File(s) | Notes |
|-------------|--------|---------|-------|
| Multipart/related create | ✅ | `multipart.go` | Working |
| **Multipart/related parse** | ⚠️ | `multipart.go` | Basic, needs PartInfo correlation |
| Content-ID generation | ✅ | `multipart.go` | UUID-based |
| **PartInfo/cid correlation** | ❌ | - | TC03 failing due to this |
| Compression (GZIP) | ✅ | `pkg/compression/` | Working |

### 4. MSH Module (`pkg/msh/`)

| Requirement | Status | File(s) | Notes |
|-------------|--------|---------|-------|
| Message sending | ✅ | `msh.go` | Working |
| Message receiving | ✅ | `msh.go` | Working |
| Receipt generation | ⚠️ | `msh.go` | Basic |
| Error handling | ✅ | `msh.go` | ebMS error codes |
| P-Mode resolution | ✅ | `resolver.go` | Working |
| **Duplicate detection** | ⚠️ | - | In ReliabilityTracker but incomplete |
| **Retry mechanism** | ⚠️ | - | Basic implementation |
| Pull model | ❌ | - | Types exist, not implemented |

### 5. Transport Module (`pkg/transport/`)

| Requirement | Status | File(s) | Notes |
|-------------|--------|---------|-------|
| HTTPS transport | ✅ | - | Standard Go HTTP |
| TLS 1.2 minimum | ✅ | - | Go default |
| TLS 1.3 support | ✅ | - | Go default |
| Client cert auth | ✅ | - | Standard Go |

---

## Implementation Roadmap

### Phase 1: WS-Security Encryption Integration (Priority: HIGH)

**Goal**: Complete encryption flow in Security header for TC02/TC03 compliance.

#### Task 1.1: Create Security Header Encryptor
**File**: `pkg/security/wssec_encryptor.go` (new)

```go
// WSSEncryptor handles WS-Security encryption operations
type WSSEncryptor struct {
    recipientPublicKey *ecdh.PublicKey
    hkdfInfo           []byte
}

// EncryptPayloads encrypts MIME parts and adds EncryptedKey to Security header
func (e *WSSEncryptor) EncryptPayloads(security *etree.Element, payloads []mime.Payload) ([]mime.Payload, error)
```

Implementation steps:
1. Generate random CEK (16 bytes for AES-128)
2. Use `xmlenc.X25519KeyAgreement` to wrap CEK 
3. Create `xenc:EncryptedKey` element with:
   - `xenc:EncryptionMethod` (AES-128-KW)
   - `xenc:AgreementMethod` (X25519)
   - `xenc11:KeyDerivationMethod` (HKDF)
   - `xenc:CipherData/CipherValue` (wrapped key)
   - `xenc:ReferenceList/DataReference` (cid: URIs)
4. Add to Security header (after Signature)
5. Encrypt each payload with CEK using AES-128-GCM
6. Return encrypted payloads

**Effort**: 2-3 days

#### Task 1.2: Update AS4 Message Builder
**File**: `pkg/msh/security.go`

Add encryption to the message building flow:
1. After signing, add `EncryptedKey` to Security header
2. Replace payload bytes with encrypted versions
3. Update Content-Type headers for encrypted parts

**Effort**: 1-2 days

#### Task 1.3: Add Decryption Support
**File**: `pkg/security/wssec_decryptor.go` (new)

```go
// WSSDecryptor handles WS-Security decryption operations  
type WSSDecryptor struct {
    privateKey *ecdh.PrivateKey
    hkdfInfo   []byte
}

// DecryptPayloads extracts CEK and decrypts MIME parts
func (d *WSSDecryptor) DecryptPayloads(security *etree.Element, payloads []mime.Payload) ([]mime.Payload, error)
```

**Effort**: 1-2 days

### Phase 2: MIME Attachment Handling Fix (Priority: HIGH)

**Goal**: Fix TC03 test case failure (two payload message).

#### Task 2.1: Improve MIME Parser
**File**: `pkg/mime/multipart.go`

Issues to fix:
1. Parse `PartProperties` from UserMessage correctly
2. Correlate Content-ID with `PartInfo/@href`
3. Handle `cid:` URI format variations

**Effort**: 1 day

#### Task 2.2: Add PartInfo Metadata Extraction
**File**: `pkg/message/parser.go` (new or extend)

```go
// ExtractPayloadMetadata extracts PartInfo from UserMessage
func ExtractPayloadMetadata(userMsg *UserMessage) map[string]PartMetadata

type PartMetadata struct {
    Href            string
    MimeType        string
    CompressionType string
}
```

**Effort**: 1 day

### Phase 3: Receipt Enhancement (Priority: MEDIUM)

**Goal**: Generate proper NonRepudiationInformation receipts.

#### Task 3.1: Implement NRI Structure
**File**: `pkg/message/receipt.go` (new)

```go
// NonRepudiationInformation per ebBP-Signals-2.0
type NonRepudiationInformation struct {
    MessagePartNRInformation []MessagePartNRInformation
}

type MessagePartNRInformation struct {
    MessagePartIdentifier string
    // Contains ds:Reference from original signature
}

// NewNRIReceipt creates receipt with signature references
func NewNRIReceipt(originalMessage *ReceivedMessage) (*SignalMessage, error)
```

Per AS4 spec, the Receipt contains:
- `ebbp:NonRepudiationInformation`
- `ebbp:MessagePartNRInformation` for each signed part
- Copy of `ds:Reference` elements from original signature

**Effort**: 2 days

### Phase 4: Pull Model Support (Priority: LOW)

**Goal**: Implement receiver-initiated message pull per AS4 profile.

#### Task 4.1: Implement PullRequest Signal
**File**: `pkg/message/pull.go` (new)

```go
type PullRequest struct {
    MPC string // Message Partition Channel
}

func NewPullSignal(mpc string) *SignalMessage
```

**Effort**: 1 day

#### Task 4.2: Update MSH for Pull Support
**File**: `pkg/msh/msh.go`

- Add `HandlePullRequest()` method
- Implement message queue by MPC
- Add `PullMessage()` client method

**Effort**: 2-3 days

### Phase 5: Alternative ECC Support (Priority: LOW)

**Goal**: Support ECDSA/ECDH with P-256 curve as alternative to Ed25519/X25519.

#### Task 5.1: ECDSA Signer
**File**: `pkg/security/ecdsa_signer.go` (new)

Support for:
- `ecdsa-sha256` algorithm
- P-256 (secp256r1) and BrainpoolP256r1 curves

**Effort**: 2 days

#### Task 5.2: ECDH-ES Key Agreement
**File**: `pkg/security/ecdh_encryptor.go` (new)

Support for:
- ECDH-ES with P-256
- ConcatKDF as alternative to HKDF

**Effort**: 2 days

### Phase 6: Four Corner Model Helpers (Priority: LOW)

**Goal**: Convenience methods for Four Corner topology.

#### Task 6.1: Four Corner Builder Options
**File**: `pkg/message/builder.go`

```go
func WithOriginalSender(sender string) Option
func WithFinalRecipient(recipient string) Option  
func WithTrackingIdentifier(id string) Option
```

These already work via `WithMessageProperty()` but dedicated helpers improve UX.

**Effort**: 0.5 days

---

## Test Plan

### Unit Tests

| Module | Coverage Target | Current | Notes |
|--------|----------------|---------|-------|
| `pkg/security/` | 80% | ~70% | Add encryption tests |
| `pkg/message/` | 80% | ~60% | Add receipt tests |
| `pkg/mime/` | 80% | ~50% | Add parsing tests |
| `pkg/msh/` | 70% | ~50% | Add integration tests |

### Integration Tests

Based on EU Interoperability Event test cases:

| Test | Description | Status | Target |
|------|-------------|--------|--------|
| TC00 | Network connectivity | ✅ | Maintain |
| TC01 | Minimal message (signature only) | ✅ | Maintain |
| TC02 | ENTSOG single payload (sign+encrypt) | ❌ | Phase 1 |
| TC03 | OOTS two payloads (sign+encrypt) | ❌ | Phase 1+2 |

### Interoperability Tests

Continue testing against:
- phase4 (Holodeck reference implementation)
- EC Security Validator (when integrated)

---

## Dependencies

### External Libraries

| Library | Version | Purpose | Status |
|---------|---------|---------|--------|
| signedxml | latest | XML signatures | ✅ Integrated |
| signedxml/xmlenc | latest | XML encryption | ✅ Available |
| etree | v1.4.0+ | XML manipulation | ✅ Integrated |
| x/crypto | latest | X25519, HKDF | ✅ Integrated |

### Test Resources

| Resource | Source | Use |
|----------|--------|-----|
| EC Security Validator | [BitBucket](https://ec.europa.eu/digital-building-blocks/code/projects/EDELIVERY/repos/edelivery2-as4-security-validator/browse) | Validate Security headers |
| Sample payloads | EC Interop Event | Test TC02/TC03 |
| Reference messages | phase4 captures | Verify format |

---

## Effort Estimate

| Phase | Description | Effort | Priority |
|-------|-------------|--------|----------|
| 1 | WS-Security Encryption | 5-7 days | HIGH |
| 2 | MIME Attachment Fix | 2 days | HIGH |
| 3 | Receipt Enhancement | 2 days | MEDIUM |
| 4 | Pull Model | 3-4 days | LOW |
| 5 | Alternative ECC | 4 days | LOW |
| 6 | Four Corner Helpers | 0.5 days | LOW |

**Total**: ~16-20 days for full compliance

**Minimum for TC02/TC03**: Phases 1+2 = ~7-9 days

---

## Success Criteria

1. **TC01**: Pass minimal message test with Ed25519 signature ✅
2. **TC02**: Pass single payload test with signature + encryption
3. **TC03**: Pass two payload test with signature + encryption
4. **Validator**: Pass EC Security Validator checks
5. **Interop**: Successful exchange with phase4 reference implementation

---

## References

- [eDelivery AS4 2.0 Specification](specs/eDelivery-AS4-2.0.md)
- [EU Interoperability Compliance](EU_INTEROPERABILITY_COMPLIANCE.md)
- [ADR 009: Supporting eDelivery 2024](adr/009-supporting-edelivery-2024.md)
- [phase4 Testing Summary](phase4-testing-summary.md)
