# EU eDelivery AS4 2.0 Interoperability Compliance

## Source

Based on [eDelivery AS4 2.0 Interoperability Event: technical guidance](https://ec.europa.eu/digital-building-blocks/sites/spaces/EDELCOMMUNITY/pages/909706852/eDelivery+AS4+2.0+Interoperability+Event+technical+guidance) (Updated November 2025)

## Required Cryptographic Algorithms

The EU interoperability event mandates the following algorithms for the **Common Usage Profile**:

| Component | Algorithm | URI | Standard |
|-----------|-----------|-----|----------|
| Signature | Ed25519 (EdDSA) | `http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519` | RFC 9231 |
| Digest | SHA-256 | `http://www.w3.org/2001/04/xmlenc#sha256` | - |
| Key Agreement | X25519 | `http://www.w3.org/2021/04/xmldsig-more#x25519` | RFC 9231 |
| Key Derivation | HKDF | `http://www.w3.org/2021/04/xmldsig-more#hkdf` | RFC 9231 |
| Key Wrapping | AES-128-KW | `http://www.w3.org/2001/04/xmlenc#kw-aes128` | XML Enc 1.1 |
| Encryption | AES-128-GCM | `http://www.w3.org/2009/xmlenc11#aes128-gcm` | XML Enc 1.1 |
| HKDF PRF | HMAC-SHA256 | `http://www.w3.org/2001/04/xmldsig-more#hmac-sha256` | RFC 9231 |

### Alternative ECC Option

For participants who also want to test the Alternative Elliptic Curve Cryptography Option:
- Signing: ECDSA with secp256r1 (P-256)
- Encryption: ECDH with secp256r1 (P-256)

## Certificate Requirements

Per the interoperability event:

| Certificate Type | Key Type | OID |
|-----------------|----------|-----|
| Signing | Ed25519 | 1.3.101.112 |
| Encryption/Key Exchange | X25519 | 1.3.101.110 |
| TLS Server (if HTTPS) | Any (RSA/ECDSA/EdDSA) | - |

**Note**: Solutions must validate certificates signed by RSA, EdDSA, or ECDSA issuers.

## go-as4 Implementation Status

### ✅ Complete

1. **Ed25519 Signing** (`pkg/security/ed25519_signer.go`)
   - Uses signedxml library with Ed25519 support
   - Algorithm URI: `http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519`
   - SHA-256 reference digests
   - WS-Security BinarySecurityToken support
   - Attachment signing via `cid:` URI references

2. **SHA-256 Digests**
   - Used for all `ds:Reference` elements
   - Algorithm URI: `http://www.w3.org/2001/04/xmlenc#sha256`

3. **AES-128-GCM Data Encryption** (`pkg/security/encryption.go`)
   - Algorithm URI: `http://www.w3.org/2009/xmlenc11#aes128-gcm`
   - Proper GCM nonce handling

4. **X25519 Key Agreement** (`pkg/security/encryption.go`)
   - Ephemeral-static key agreement
   - Algorithm URI: `http://www.w3.org/2021/04/xmldsig-more#x25519`

5. **HKDF Key Derivation** (`pkg/security/encryption.go`)
   - Using HMAC-SHA256
   - Algorithm URI: `http://www.w3.org/2021/04/xmldsig-more#hkdf`

### ⚠️ Partially Complete / Needs Work

1. **WS-Security Integration**
   - XML Encryption primitives are now available in `signedxml/xmlenc`
   - Need to integrate into go-as4 WS-Security flow
   - Add `xenc:EncryptedKey` to Security header (after Signature)
   - Create `xenc:EncryptedData` for each attachment
   - Reference via `cid:` URIs

2. **Current Encryption API Update**
   - Current: Encryption metadata returned as map
   - Update: Use `signedxml/xmlenc.Encryptor` and `X25519KeyAgreement`

### ✅ Recently Implemented (signedxml/xmlenc)

1. **AES Key Wrap (RFC 3394)**
   - File: `signedxml/xmlenc/keywrap.go`
   - Functions: `AESKeyWrap()`, `AESKeyUnwrap()`
   - Supports AES-128/192/256-KW
   - Official RFC 3394 test vectors pass

2. **X25519 Key Agreement with HKDF**
   - File: `signedxml/xmlenc/keyagreement.go`
   - `X25519KeyAgreement` type with `WrapKey()` / `UnwrapKey()` methods
   - Uses `crypto/ecdh` for X25519
   - HKDF using `golang.org/x/crypto/hkdf`
   - Produces proper `xenc:EncryptedKey` structure with:
     - `xenc:AgreementMethod` (X25519)
     - `xenc11:KeyDerivationMethod` (HKDF)
     - `dsig-more:HKDFParams` (PRF, Salt, Info, KeyLength)
     - `xenc:OriginatorKeyInfo` with ephemeral X25519 public key

3. **XML Encryption Structures**
   - File: `signedxml/xmlenc/types.go`
   - Full `EncryptedData` and `EncryptedKey` types
   - XML serialization/parsing support
   - Proper namespace handling (xenc:, xenc11:, dsig-more:, dsig11:)

4. **AES-GCM and AES-CBC Encryption**
   - File: `signedxml/xmlenc/keywrap.go`
   - Functions: `AESGCMEncrypt()`, `AESGCMDecrypt()`
   - Functions: `AESCBCEncrypt()`, `AESCBCDecrypt()`

5. **High-level Encryption API**
   - File: `signedxml/xmlenc/encrypt.go`
   - `Encryptor` type with `EncryptElement()` / `EncryptContent()`
   - `Decryptor` type with `DecryptElement()`
   - `EncryptElementInPlace()` for in-document encryption

### Example Usage (signedxml/xmlenc)

```go
import "github.com/leifj/signedxml/xmlenc"

// Generate or load recipient X25519 key
recipientPrivate, _ := xmlenc.GenerateX25519KeyPair()
recipientPublic := recipientPrivate.PublicKey()

// Sender: Encrypt element with X25519 + AES-128-GCM
hkdfParams := xmlenc.DefaultHKDFParams([]byte("EU AS4 2.0"))
senderKA, _ := xmlenc.NewX25519KeyAgreement(recipientPublic, hkdfParams)
encryptor := xmlenc.NewEncryptor(xmlenc.AlgorithmAES128GCM, senderKA)
encryptedData, _ := encryptor.EncryptElement(xmlElement)

// Generate XML
doc := xmlenc.NewEncryptedDataDocument(encryptedData)
xmlBytes, _ := doc.WriteToBytes()

// Recipient: Decrypt
// Extract ephemeral public key from EncryptedKey structure
ephemeralPubBytes := encryptedData.KeyInfo.EncryptedKey.KeyInfo.AgreementMethod.OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey
ephemeralPublic, _ := xmlenc.ParseX25519PublicKey(ephemeralPubBytes)

recipientKA := xmlenc.NewX25519KeyAgreementForDecrypt(recipientPrivate, ephemeralPublic, hkdfParams)
decryptor := xmlenc.NewDecryptor(recipientKA)
decryptedElement, _ := decryptor.DecryptElement(encryptedData)
```

### ❌ Not Yet Implemented

1. **Full WS-Security Encryption Integration**
   - Adding `xenc:EncryptedKey` to Security header
   - Proper `xenc:DataReference` for MIME parts

2. **MIME Part Encryption**
   - Encrypting attachment payloads
   - Setting encrypted MIME headers

## Implementation Roadmap

### Phase 1: ✅ XML Encryption Library (Complete)

The `signedxml/xmlenc` package now provides:
- AES Key Wrap (RFC 3394) with test vectors
- X25519 key agreement with HKDF
- Full XML Encryption 1.1 type structures
- High-level Encrypt/Decrypt API

### Phase 2: go-as4 WS-Security Integration (Current Focus)

Update `pkg/security/` to use `signedxml/xmlenc`:

1. **Create X25519 XML Encryptor** (`pkg/security/x25519_xml_encryptor.go`)
   - Use `xmlenc.X25519KeyAgreement` for key wrapping
   - Generate proper `xenc:EncryptedKey` elements
   - Add `wsse:SecurityTokenReference` for recipient key

2. **Integrate into AS4 Encryptor** (`pkg/security/as4_encryptor.go`)
   - Add `xenc:EncryptedKey` to Security header
   - Reference encrypted attachments via `xenc:DataReference`

3. **MIME Part Encryption**
   - Encrypt attachment payloads with generated CEK
   - Update MIME headers for encrypted content

### Phase 4: Test Cases (Priority: Medium)

Implement test cases matching EU event scenarios:

| Test | Description | Payloads | Encryption |
|------|-------------|----------|------------|
| TC01 | Minimal message | None | No |
| TC02 | ENTSOG single payload | 1 XML | Yes |
| TC03 | OOTS two payloads | 1 XML + 1 PDF | Yes |

## Test Case P-Mode Configuration

```go
// TC01: Minimal AS4 Message Exchange
pmode := &PMode{
    MEP: "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/oneWay",
    MEPBinding: "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/push",
    MPC: "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/defaultMPC",
    BusinessInfo: &BusinessInfo{
        Service: "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/service",
        Action: "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/test",
    },
    Security: &SecurityConfig{
        SignatureAlgorithm: "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519",
        DigestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    },
    Compression: true,
}

// TC02/TC03: Add encryption config
pmode.Security.Encryption = &EncryptionConfig{
    KeyAgreement: "http://www.w3.org/2021/04/xmldsig-more#x25519",
    KeyDerivation: "http://www.w3.org/2021/04/xmldsig-more#hkdf",
    KeyWrap: "http://www.w3.org/2001/04/xmlenc#kw-aes128",
    DataEncryption: "http://www.w3.org/2009/xmlenc11#aes128-gcm",
}
```

## Priority Order

1. **Immediate (TC01 ready)**: Ed25519 signing ✅
2. **Complete**: XML Encryption library (signedxml/xmlenc) ✅
3. **Current**: go-as4 WS-Security integration with xmlenc
4. **Next**: Full attachment encryption (TC02/TC03)
5. **Future**: Alternative ECC option (secp256r1)

## References

- [eDelivery AS4 Profile 2.0](https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/845480153/eDelivery+AS4+-+2.0)
- [AS4 Security Validator](https://ec.europa.eu/digital-building-blocks/code/projects/EDELIVERY/repos/edelivery2-as4-security-validator/browse)
- [RFC 9231: Additional XML Security URIs](https://www.rfc-editor.org/rfc/rfc9231.html)
- [RFC 3394: AES Key Wrap](https://www.rfc-editor.org/rfc/rfc3394.html)
- [XML Encryption 1.1](https://www.w3.org/TR/xmlenc-core1/)
