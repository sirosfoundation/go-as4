// Copyright (c) 2024 SIROS Foundation
// SPDX-License-Identifier: BSD-2-Clause

/*
Package security implements WS-Security for AS4 message signing and encryption.

This package provides comprehensive WS-Security 1.1.1 support for AS4 messages,
including digital signatures and XML encryption.

# Digital Signatures

The package supports multiple signature algorithms:

RSA-SHA256 (Interoperable):

	signer := security.NewRSASigner(privateKey, certificate)
	signedDoc, err := signer.Sign(doc)

Ed25519 (AS4 2.0):

	signer := security.NewEd25519Signer(privateKey, certificate)
	signedDoc, err := signer.Sign(doc)

Signature features:
  - SHA-256 digest algorithm
  - Exclusive XML Canonicalization with InclusiveNamespaces
  - Reference-based signing of message parts
  - BinarySecurityToken for certificate attachment

# Encryption

The package provides SwA (SOAP with Attachments) encryption:

	encryptor := security.NewSwAEncryptor(recipientCert)
	encrypted, err := encryptor.Encrypt(doc, attachments)

Encryption algorithms:
  - AES-128-GCM for content encryption
  - RSA-OAEP for key transport
  - AES-128 Key Wrap (AS4 2.0)
  - X25519 key agreement (AS4 2.0)

# Certificate Reference Methods

When encrypting, the library supports multiple ways to reference the
recipient's certificate (CertReferenceType):

	CertRefAuto           - Automatic selection (SKI if available, else IssuerSerial)
	CertRefIssuerSerial   - X509IssuerSerial (universal compatibility)
	CertRefSKI            - SubjectKeyIdentifier (requires X.509v3 with SKI)
	CertRefBSTDirectReference - Embedded BinarySecurityToken
	CertRefThumbprint     - SHA-1 certificate thumbprint

Example:

	attachment := &security.SwAEncryptedAttachment{
	    ContentID:   "payload-123",
	    CertRefType: security.CertRefIssuerSerial,
	}
	security.AddSwAEncryptionToDocument(doc, attachment, recipientCert)

# Configuration

Configure security settings:

	config := security.NewSecurityConfig(
	    security.WithSigningKey(privateKey),
	    security.WithSigningCert(signingCert),
	    security.WithRecipientCert(encryptionCert),
	)

# References

  - WS-Security 1.1.1: https://docs.oasis-open.org/wss/v1.1/
  - WS-Security X.509 Token Profile: https://docs.oasis-open.org/wss/v1.1/wss-v1.1-spec-os-x509TokenProfile.pdf
  - XML Signature: https://www.w3.org/TR/xmldsig-core1/
  - XML Encryption: https://www.w3.org/TR/xmlenc-core1/
  - OASIS AS4 Security: https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/
*/
package security
