package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/beevik/etree"
)

// CertReferenceType defines how a certificate is referenced in WS-Security messages.
// Different receivers may require different reference types based on their implementation
// and the certificate's capabilities (e.g., presence of SKI extension).
type CertReferenceType int

const (
	// CertRefAuto automatically selects the best reference type based on certificate capabilities.
	// Priority: SKI (if available) -> IssuerSerial (fallback)
	CertRefAuto CertReferenceType = iota

	// CertRefIssuerSerial uses X509IssuerSerial (Issuer DN + Serial Number).
	// Works with all certificate versions and is recommended by the X509 profile.
	// Compatible with: phase4/WSS4J, most WS-Security implementations
	CertRefIssuerSerial

	// CertRefSKI uses SubjectKeyIdentifier from the certificate's SKI extension.
	// Only works if the certificate has an SKI extension (typically v3+ certs).
	// More compact than IssuerSerial but not universally supported.
	CertRefSKI

	// CertRefBSTDirectReference embeds the full certificate as a BinarySecurityToken.
	// Largest payload but ensures receiver has all certificate data.
	// This is the default for phase4 outbound messages.
	CertRefBSTDirectReference

	// CertRefThumbprint uses SHA-1 hash of the DER-encoded certificate.
	// Compact but requires receiver to have the certificate pre-cached.
	CertRefThumbprint
)

// String returns a human-readable name for the reference type.
func (t CertReferenceType) String() string {
	switch t {
	case CertRefAuto:
		return "Auto"
	case CertRefIssuerSerial:
		return "IssuerSerial"
	case CertRefSKI:
		return "SKI"
	case CertRefBSTDirectReference:
		return "BSTDirectReference"
	case CertRefThumbprint:
		return "Thumbprint"
	default:
		return "Unknown"
	}
}

// CertHasSKI checks if a certificate has a Subject Key Identifier extension.
func CertHasSKI(cert *x509.Certificate) bool {
	ski := GetSubjectKeyIdentifier(cert)
	return ski != nil && len(ski) > 0
}

// GetSubjectKeyIdentifier extracts the Subject Key Identifier from a certificate's SKI extension.
// Returns nil if the certificate doesn't have an SKI extension.
func GetSubjectKeyIdentifier(cert *x509.Certificate) []byte {
	// OID for Subject Key Identifier: 2.5.29.14
	skiOID := asn1.ObjectIdentifier{2, 5, 29, 14}

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(skiOID) {
			// SKI is an OCTET STRING containing the identifier
			// The extension value is DER-encoded OCTET STRING
			var ski []byte
			if _, err := asn1.Unmarshal(ext.Value, &ski); err == nil {
				return ski
			}
			// Fallback: try direct extraction (older format)
			if len(ext.Value) > 2 {
				return ext.Value[2:] // Skip ASN.1 OCTET STRING tag and length
			}
		}
	}
	return nil
}

// GetCertificateThumbprint returns the SHA-1 thumbprint of a certificate.
func GetCertificateThumbprint(cert *x509.Certificate) []byte {
	hash := sha1.Sum(cert.Raw)
	return hash[:]
}

// SelectBestCertRefType determines the best certificate reference type for a given certificate.
// This implements the auto-detection logic for CertRefAuto.
func SelectBestCertRefType(cert *x509.Certificate) CertReferenceType {
	// Check if certificate has SKI extension
	if CertHasSKI(cert) {
		return CertRefSKI
	}

	// Fallback to IssuerSerial which works with all certificate versions
	return CertRefIssuerSerial
}

// ResolveCertRefType resolves CertRefAuto to a concrete reference type.
func ResolveCertRefType(refType CertReferenceType, cert *x509.Certificate) CertReferenceType {
	if refType == CertRefAuto {
		return SelectBestCertRefType(cert)
	}
	return refType
}

// EncryptAttachmentData encrypts attachment data according to WS-Security spec
// Uses AES-128-GCM for data encryption and RSA-OAEP-SHA256 with MGF1-SHA256 for key encryption
// (Basic128GCMSha256MgfSha256 algorithm suite)
// Returns encrypted data with authentication tag appended (GCM standard)
func EncryptAttachmentData(data []byte, recipientCert *x509.Certificate) (encryptedDataWithTag []byte, encryptedKey []byte, err error) {
	// Generate random AES-128 key (16 bytes for Basic128GCMSha256MgfSha256)
	symmetricKey := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, symmetricKey); err != nil {
		return nil, nil, fmt.Errorf("failed to generate symmetric key: %w", err)
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce for AES-GCM (12 bytes is standard for GCM)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data with AES-GCM (automatically appends authentication tag)
	encryptedData := gcm.Seal(nil, nonce, data, nil)

	// Encrypt the symmetric key with recipient's RSA public key
	publicKey, ok := recipientCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("recipient certificate does not contain RSA public key")
	}

	// Use RSA-OAEP with SHA-256 and MGF1-SHA256 (as specified by Basic128GCMSha256MgfSha256)
	encryptedKey, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, symmetricKey, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt symmetric key: %w", err)
	}

	// Prepend nonce to encrypted data (GCM standard for transport)
	encryptedDataWithTag = append(nonce, encryptedData...)

	return encryptedDataWithTag, encryptedKey, nil
}

// SwAEncryptedAttachment holds information about an encrypted attachment
// for WS-Security SOAP with Attachments (SwA) encryption
type SwAEncryptedAttachment struct {
	ContentID         string            // Original Content-ID (without angle brackets)
	EncryptedData     []byte            // AES-GCM encrypted content (nonce prepended)
	EncryptedKey      []byte            // RSA-OAEP encrypted symmetric key
	EncryptedDataID   string            // ID for the xenc:EncryptedData element
	OriginalMimeType  string            // Original MIME type
	EncryptedMimeType string            // MIME type for encrypted data (application/octet-stream)
	CertRefType       CertReferenceType // How to reference the recipient certificate (default: Auto)
}

// AddSwAEncryptionToDocument adds WS-Security SwA encryption elements to a SOAP document.
// This follows the WS-Security SOAP with Attachments (SwA) profile:
// 1. xenc:EncryptedKey element in Security header (with certificate reference)
// 2. xenc:EncryptedData element in Security header with CipherReference to MIME attachment
//
// The certificate reference type is determined by attachment.CertRefType:
// - CertRefAuto: automatically selects best method based on certificate capabilities
// - CertRefIssuerSerial: uses X509IssuerSerial (works with all cert versions)
// - CertRefSKI: uses SubjectKeyIdentifier (requires SKI extension in cert)
// - CertRefBSTDirectReference: embeds full certificate as BinarySecurityToken
// - CertRefThumbprint: uses SHA-1 thumbprint of certificate
//
// The EncryptedData is placed in the Security header (not Body) to avoid being
// counted as a payload element by AS4 implementations.
func AddSwAEncryptionToDocument(doc *etree.Document, attachment *SwAEncryptedAttachment, recipientCert *x509.Certificate) error {
	return AddSwAEncryptionToDocumentWithRefType(doc, attachment, recipientCert, attachment.CertRefType)
}

// AddSwAEncryptionToDocumentWithRefType adds WS-Security SwA encryption elements with explicit
// certificate reference type. This allows overriding the attachment's CertRefType setting.
func AddSwAEncryptionToDocumentWithRefType(doc *etree.Document, attachment *SwAEncryptedAttachment, recipientCert *x509.Certificate, refType CertReferenceType) error {
	envelope := doc.Root()
	if envelope == nil {
		return fmt.Errorf("no root envelope element")
	}

	// Find Security header
	header := envelope.FindElement("//Header")
	if header == nil {
		header = envelope.FindElement(".//*[local-name()='Header']")
	}
	if header == nil {
		return fmt.Errorf("no SOAP header found")
	}

	security := header.FindElement(".//*[local-name()='Security']")
	if security == nil {
		return fmt.Errorf("no Security element found")
	}

	// Resolve certificate reference type
	resolvedRefType := ResolveCertRefType(refType, recipientCert)

	// Generate IDs
	encryptedDataID := attachment.EncryptedDataID
	if encryptedDataID == "" {
		encryptedDataID = "ED-" + generateID()
	}
	encryptedKeyID := "EK-" + generateID()
	bstID := "X509-" + generateID() // For BST direct reference

	// For BST_DIRECT_REFERENCE, add BinarySecurityToken first
	if resolvedRefType == CertRefBSTDirectReference {
		bst := etree.NewElement("wsse:BinarySecurityToken")
		bst.CreateAttr("xmlns:wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
		bst.CreateAttr("xmlns:wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
		bst.CreateAttr("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary")
		bst.CreateAttr("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")
		bst.CreateAttr("wsu:Id", bstID)
		bst.SetText(base64.StdEncoding.EncodeToString(recipientCert.Raw))
		security.AddChild(bst)
	}

	// 1. Add EncryptedKey to Security header FIRST
	// WSS4J processes elements in document order, so EncryptedKey must come before EncryptedData
	encryptedKeyElem := etree.NewElement("xenc:EncryptedKey")
	encryptedKeyElem.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
	encryptedKeyElem.CreateAttr("Id", encryptedKeyID)

	// EncryptionMethod for key (RSA-OAEP with SHA-256 and MGF1-SHA256)
	keyEncMethod := encryptedKeyElem.CreateElement("xenc:EncryptionMethod")
	keyEncMethod.CreateAttr("Algorithm", "http://www.w3.org/2009/xmlenc11#rsa-oaep")

	// Add DigestMethod for SHA-256
	digestMethod := keyEncMethod.CreateElement("ds:DigestMethod")
	digestMethod.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	digestMethod.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")

	// Add MGF (Mask Generation Function) for MGF1-SHA256
	mgf := keyEncMethod.CreateElement("xenc11:MGF")
	mgf.CreateAttr("xmlns:xenc11", "http://www.w3.org/2009/xmlenc11#")
	mgf.CreateAttr("Algorithm", "http://www.w3.org/2009/xmlenc11#mgf1sha256")

	// KeyInfo with certificate reference - method depends on resolvedRefType
	keyInfo := encryptedKeyElem.CreateElement("ds:KeyInfo")
	keyInfo.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")

	if err := addCertificateReference(keyInfo, recipientCert, resolvedRefType, bstID); err != nil {
		return fmt.Errorf("failed to add certificate reference: %w", err)
	}

	// CipherData with encrypted symmetric key
	keyCipherData := encryptedKeyElem.CreateElement("xenc:CipherData")
	keyCipherValue := keyCipherData.CreateElement("xenc:CipherValue")
	keyCipherValue.SetText(base64.StdEncoding.EncodeToString(attachment.EncryptedKey))

	// ReferenceList pointing to EncryptedData element ID
	refList := encryptedKeyElem.CreateElement("xenc:ReferenceList")
	dataRef := refList.CreateElement("xenc:DataReference")
	dataRef.CreateAttr("URI", "#"+encryptedDataID)

	// Add EncryptedKey to Security header
	security.AddChild(encryptedKeyElem)

	// 2. Add EncryptedData to Security header (for SwA attachment)
	// This references the MIME attachment via CipherReference
	encDataElem := etree.NewElement("xenc:EncryptedData")
	encDataElem.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
	encDataElem.CreateAttr("Id", encryptedDataID)
	encDataElem.CreateAttr("MimeType", attachment.OriginalMimeType)
	encDataElem.CreateAttr("Type", "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Only")

	// EncryptionMethod for data (AES-128-GCM)
	dataEncMethod := encDataElem.CreateElement("xenc:EncryptionMethod")
	dataEncMethod.CreateAttr("Algorithm", "http://www.w3.org/2009/xmlenc11#aes128-gcm")

	// KeyInfo pointing to EncryptedKey (WSS4J requires this)
	encDataKeyInfo := encDataElem.CreateElement("ds:KeyInfo")
	encDataKeyInfo.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	encDataSecTokenRef := encDataKeyInfo.CreateElement("wsse:SecurityTokenReference")
	encDataSecTokenRef.CreateAttr("xmlns:wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
	encDataSecTokenRef.CreateAttr("xmlns:wsse11", "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd")
	encDataSecTokenRef.CreateAttr("wsse11:TokenType", "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey")
	encKeyRef := encDataSecTokenRef.CreateElement("wsse:Reference")
	encKeyRef.CreateAttr("URI", "#"+encryptedKeyID)

	// CipherData with CipherReference to MIME attachment
	cipherData := encDataElem.CreateElement("xenc:CipherData")
	cipherRef := cipherData.CreateElement("xenc:CipherReference")
	cipherRef.CreateAttr("URI", "cid:"+attachment.ContentID)

	// Add SwA transform
	transforms := cipherRef.CreateElement("xenc:Transforms")
	transform := transforms.CreateElement("ds:Transform")
	transform.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	transform.CreateAttr("Algorithm", "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Ciphertext-Transform")

	// Add EncryptedData to Security header (after EncryptedKey)
	security.AddChild(encDataElem)

	return nil
}

// addCertificateReference adds the appropriate certificate reference elements to a KeyInfo element
// based on the specified reference type.
func addCertificateReference(keyInfo *etree.Element, cert *x509.Certificate, refType CertReferenceType, bstID string) error {
	secTokenRef := keyInfo.CreateElement("wsse:SecurityTokenReference")
	secTokenRef.CreateAttr("xmlns:wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")

	switch refType {
	case CertRefIssuerSerial:
		// X509IssuerSerial: works with all certificate versions
		// <ds:X509Data>
		//   <ds:X509IssuerSerial>
		//     <ds:X509IssuerName>CN=...</ds:X509IssuerName>
		//     <ds:X509SerialNumber>123456</ds:X509SerialNumber>
		//   </ds:X509IssuerSerial>
		// </ds:X509Data>
		x509Data := secTokenRef.CreateElement("ds:X509Data")
		x509IssuerSerial := x509Data.CreateElement("ds:X509IssuerSerial")
		x509IssuerName := x509IssuerSerial.CreateElement("ds:X509IssuerName")
		x509IssuerName.SetText(cert.Issuer.String())
		x509SerialNumber := x509IssuerSerial.CreateElement("ds:X509SerialNumber")
		x509SerialNumber.SetText(cert.SerialNumber.String())

	case CertRefSKI:
		// SubjectKeyIdentifier: requires SKI extension in certificate
		// <wsse:KeyIdentifier
		//   EncodingType="...#Base64Binary"
		//   ValueType="...#X509SubjectKeyIdentifier">
		//   base64-encoded-ski
		// </wsse:KeyIdentifier>
		ski := GetSubjectKeyIdentifier(cert)
		if ski == nil || len(ski) == 0 {
			return fmt.Errorf("certificate does not have Subject Key Identifier extension")
		}
		keyId := secTokenRef.CreateElement("wsse:KeyIdentifier")
		keyId.CreateAttr("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary")
		keyId.CreateAttr("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier")
		keyId.SetText(base64.StdEncoding.EncodeToString(ski))

	case CertRefBSTDirectReference:
		// Direct reference to BinarySecurityToken (full certificate embedded)
		// <wsse:Reference URI="#X509-xxx"
		//   ValueType="...#X509v3"/>
		ref := secTokenRef.CreateElement("wsse:Reference")
		ref.CreateAttr("URI", "#"+bstID)
		ref.CreateAttr("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")

	case CertRefThumbprint:
		// Thumbprint (SHA-1 hash of DER-encoded certificate)
		// <wsse:KeyIdentifier
		//   EncodingType="...#Base64Binary"
		//   ValueType="...#ThumbprintSHA1">
		//   base64-encoded-thumbprint
		// </wsse:KeyIdentifier>
		thumbprint := GetCertificateThumbprint(cert)
		keyId := secTokenRef.CreateElement("wsse:KeyIdentifier")
		keyId.CreateAttr("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary")
		keyId.CreateAttr("ValueType", "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1")
		keyId.SetText(base64.StdEncoding.EncodeToString(thumbprint))

	default:
		return fmt.Errorf("unsupported certificate reference type: %v", refType)
	}

	return nil
}

// 
// NOTE: This function uses direct cid: references which may not work with all implementations.
// For phase4/WSS4J compatibility, use AddSwAEncryptionToDocument instead.
func AddEncryptedKeysToSecurity(doc *etree.Document, attachmentEncKeys map[string][]byte, recipientCert *x509.Certificate) error {
	envelope := doc.Root()
	if envelope == nil {
		return fmt.Errorf("no root envelope element")
	}

	// Find Security header
	header := envelope.FindElement("//Header")
	if header == nil {
		return fmt.Errorf("no SOAP header found")
	}

	security := header.FindElement(".//*[local-name()='Security']")
	if security == nil {
		return fmt.Errorf("no Security element found")
	}

	// Add EncryptedKey for each attachment
	for contentID, encKey := range attachmentEncKeys {
		encryptedKeyElem := security.CreateElement("xenc:EncryptedKey")
		encryptedKeyElem.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
		encryptedKeyID := fmt.Sprintf("EK-%s", generateID())
		encryptedKeyElem.CreateAttr("Id", encryptedKeyID)

		// EncryptionMethod for key (RSA-OAEP with SHA-256 and MGF1-SHA256)
		keyEncMethod := encryptedKeyElem.CreateElement("xenc:EncryptionMethod")
		keyEncMethod.CreateAttr("Algorithm", "http://www.w3.org/2009/xmlenc11#rsa-oaep")

		// Add DigestMethod for SHA-256
		digestMethod := keyEncMethod.CreateElement("ds:DigestMethod")
		digestMethod.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
		digestMethod.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")

		// Add MGF (Mask Generation Function) for MGF1-SHA256
		mgf := keyEncMethod.CreateElement("xenc11:MGF")
		mgf.CreateAttr("xmlns:xenc11", "http://www.w3.org/2009/xmlenc11#")
		mgf.CreateAttr("Algorithm", "http://www.w3.org/2009/xmlenc11#mgf1sha256")

		// KeyInfo pointing to recipient certificate using X509IssuerSerial
		// This is more reliable than SKI for WSS4J/phase4 as the certificate
		// may not have a Subject Key Identifier extension
		keyInfo := encryptedKeyElem.CreateElement("ds:KeyInfo")
		keyInfo.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
		secTokenRef := keyInfo.CreateElement("wsse:SecurityTokenReference")
		secTokenRef.CreateAttr("xmlns:wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")

		// Use X509IssuerSerial to reference recipient certificate (WSS4J compatible)
		x509Data := secTokenRef.CreateElement("ds:X509Data")
		x509IssuerSerial := x509Data.CreateElement("ds:X509IssuerSerial")
		x509IssuerName := x509IssuerSerial.CreateElement("ds:X509IssuerName")
		x509IssuerName.SetText(recipientCert.Issuer.String())
		x509SerialNumber := x509IssuerSerial.CreateElement("ds:X509SerialNumber")
		x509SerialNumber.SetText(recipientCert.SerialNumber.String())

		// CipherData with encrypted symmetric key
		keyCipherData := encryptedKeyElem.CreateElement("xenc:CipherData")
		keyCipherValue := keyCipherData.CreateElement("xenc:CipherValue")
		keyCipherValue.SetText(base64.StdEncoding.EncodeToString(encKey))

		// ReferenceList pointing to encrypted attachment
		refList := encryptedKeyElem.CreateElement("xenc:ReferenceList")
		dataRef := refList.CreateElement("xenc:DataReference")
		// Strip < > from ContentID if present
		cid := strings.Trim(contentID, "<>")
		dataRef.CreateAttr("URI", "cid:"+cid)
	}

	return nil
}

// createEncryptedDataElement creates an xenc:EncryptedData element for AES-128-GCM
func createEncryptedDataElement(id string, cipherText, nonce []byte) *etree.Element {
	encData := etree.NewElement("xenc:EncryptedData")
	encData.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
	encData.CreateAttr("Id", id)
	encData.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Content")

	// EncryptionMethod for data (AES-128-GCM)
	encMethod := encData.CreateElement("xenc:EncryptionMethod")
	encMethod.CreateAttr("Algorithm", "http://www.w3.org/2009/xmlenc11#aes128-gcm")

	// CipherData
	cipherData := encData.CreateElement("xenc:CipherData")
	cipherValue := cipherData.CreateElement("xenc:CipherValue")

	// Prepend nonce to cipher text (GCM standard for transport)
	combined := append(nonce, cipherText...)
	cipherValue.SetText(base64.StdEncoding.EncodeToString(combined))

	return encData
}

// DecryptAttachment decrypts an encrypted attachment using AES-128-GCM
func DecryptAttachment(encryptedDataWithNonce, encryptedKey []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	// Decrypt the symmetric key with our private key using RSA-OAEP-SHA256
	symmetricKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt symmetric key: %w", err)
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Extract nonce and ciphertext
	nonceSize := gcm.NonceSize()
	if len(encryptedDataWithNonce) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	nonce := encryptedDataWithNonce[:nonceSize]
	ciphertext := encryptedDataWithNonce[nonceSize:]

	// Decrypt and verify authentication tag
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}
