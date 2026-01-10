# eDelivery AS4 2.0 Specifications Reference

This directory contains reference documentation and specifications for implementing the eDelivery AS4 2.0 profile.

## Key Specifications

### 1. eDelivery AS4 2.0 Profile (Primary Target)

**Source**: [EC Digital Building Blocks](https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/845480153/eDelivery+AS4+-+2.0)  
**Status**: Adopted December 4, 2024  
**License**: EUPL 1.2

Key documents:
- [eDelivery-AS4-2.0.md](eDelivery-AS4-2.0.md) - Extracted specification content

### 2. Base OASIS Specifications

#### 2.1 ebMS 3.0 Core (ISO 15000-1)
**URL**: https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/core/os/ebms_core-3.0-spec-os.pdf  
**Standard**: OASIS Standard, October 1, 2007 / ISO 15000-1:2021

#### 2.2 AS4 Profile of ebMS 3.0 (ISO 15000-2)
**URL**: https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/  
**Standard**: OASIS Standard, January 23, 2013 / ISO 15000-2:2021

#### 2.3 ebMS 3.0 Part 2 - Advanced Features
**URL**: https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/part2/201004/ebms-v3-part2.pdf  
**Standard**: OASIS Committee Specification, May 19, 2011  
**Note**: Used for Split/Join feature

### 3. WS-Security Specifications

#### 3.1 WS-Security SOAP Message Security 1.1.1
**URL**: https://docs.oasis-open.org/wss-m/wss/v1.1.1/wss-SOAPMessageSecurity-v1.1.1.doc

#### 3.2 WS-Security X.509 Certificate Token Profile 1.1.1
**URL**: https://docs.oasis-open.org/wss-m/wss/v1.1.1/wss-x509TokenProfile-v1.1.1.doc

#### 3.3 WS-Security SwA Profile 1.1.1
**URL**: https://docs.oasis-open.org/wss-m/wss/v1.1.1/wss-SwAProfile-v1.1.1.doc

### 4. XML Security Specifications

#### 4.1 XML Signature 1.1
**URL**: https://www.w3.org/TR/xmldsig-core1/  
**Schema**: https://www.w3.org/TR/xmldsig-core1/xmldsig11-schema.xsd

#### 4.2 XML Encryption 1.1
**URL**: https://www.w3.org/TR/xmlenc-core1/  
**Schemas**:
- https://www.w3.org/TR/xmlenc-core1/xenc-schema.xsd
- https://www.w3.org/TR/xmlenc-core1/xenc-schema-11.xsd

#### 4.3 RFC 9231 / RFC 9231bis - XML Security URIs
**URL**: https://datatracker.ietf.org/doc/draft-eastlake-rfc9231bis-xmlsec-uris/  
**Note**: Defines new algorithm URIs including Ed25519, X25519, HKDF

### 5. WS-Security Schema Files

For validation purposes:
- http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd
- http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd
- http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd

## eDelivery AS4 2.0 Key Requirements

### Cryptographic Suite (Common Profile)

| Function | Algorithm | URI |
|----------|-----------|-----|
| Signature | EdDSA Ed25519 | `http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519` |
| Digest | SHA-256 | `http://www.w3.org/2001/04/xmlenc#sha256` |
| Key Agreement | X25519 | `http://www.w3.org/2021/04/xmldsig-more#x25519` |
| Key Derivation | HKDF | `http://www.w3.org/2021/04/xmldsig-more#hkdf` |
| Key Wrapping | AES-128 KeyWrap | `http://www.w3.org/2001/04/xmlenc#kw-aes128` |
| Encryption | AES-128-GCM | `http://www.w3.org/2009/xmlenc11#aes128-gcm` |
| Canonicalization | Exclusive C14N | `http://www.w3.org/2001/10/xml-exc-c14n#` |

### Alternative ECC Option

| Function | Algorithm | URI |
|----------|-----------|-----|
| Signature | ECDSA P-256 | `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256` |
| Key Agreement | ECDH-ES (secp256r1) | Named curve OID |

### P-Mode Parameters Summary

| Parameter | Value |
|-----------|-------|
| PMode.MEP | `http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/oneWay` or `twoWay` |
| PMode.MEPBinding | `http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/push` |
| PMode[].Protocol.SOAPVersion | 1.2 |
| PMode[].Security.WSSVersion | 1.1.1 |
| PMode[].Security.X509.Sign | True |
| PMode[].Security.X509.Encryption.Encrypt | True |
| PMode[].Security.SendReceipt | True |
| PMode[].Security.SendReceipt.NonRepudiation | True |
| PMode[].Security.SendReceipt.ReplyPattern | Response |
| PMode[].PayloadService.CompressionType | application/gzip |
| PMode[].ReceptionAwareness | True |
| PMode[].ReceptionAwareness.Retry | True |
| PMode[].ReceptionAwareness.DuplicateDetection | True |

### TLS Requirements

- MUST NOT: SSL 3.0, TLS 1.0, TLS 1.1
- MUST: TLS 1.2 minimum
- SHOULD: TLS 1.3

### Four Corner Topology Requirements

When using Four Corner model:
- `originalSender` MessageProperty - REQUIRED
- `finalRecipient` MessageProperty - REQUIRED  
- `trackingIdentifier` MessageProperty - OPTIONAL

## Test Resources

### EC eDelivery2 AS4 Security Validator
**Source**: https://ec.europa.eu/digital-building-blocks/code/projects/EDELIVERY/repos/edelivery2-as4-security-validator/browse  
**Purpose**: Validate security headers against eDelivery AS4 2.0

### Interoperability Test Cases

From the eDelivery Interoperability Event guidance:

1. **TC00**: Network connectivity test
2. **TC01**: Minimal AS4 message (no payload, signature only)
3. **TC02**: ENTSOG message with single payload (sign + encrypt)
4. **TC03**: OOTS message with two payloads (sign + encrypt)

### Test Payloads Available
- ENTSOG: `Edig@s_payload.xml`
- OOTS: `OOTS_payload_1.xml`, `OOTS_payload_2.pdf`

## Related eDelivery Profiles

- [eDelivery SMP 2.0](https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/843612543/eDelivery+SMP+-+2.0)
- [eDelivery BDXL 2.0](https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/843612547/eDelivery+BDXL+-+2.0)
- [eDelivery ebCore Party Id 2.0](https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/843612550/eDelivery+ebCore+Party+Id+2.0)

## Implementation Support

### Java Libraries (for reference)
- Apache Santuario xmlsec: 3.0.5+
- Apache WSS4J: 3.0.4+
- Apache CXF: 4.0.5+

### Go Libraries
- signedxml (with InclusiveNamespaces fix)
- xmlenc (needs X25519/HKDF support)

## References

Full bibliography available in the eDelivery AS4 2.0 profile section 8.
