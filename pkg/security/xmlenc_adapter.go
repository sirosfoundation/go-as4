// Package security provides AS4 security operations including encryption.
// This file provides adapters to the xmlenc package from signedxml for
// XML Encryption 1.1 compliance per EU AS4 2.0 requirements.
package security

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"

	"github.com/beevik/etree"
	"github.com/leifj/signedxml/xmlenc"
)

// X25519Encryptor wraps xmlenc for AS4-specific encryption operations.
// It implements XML Encryption 1.1 using X25519 key agreement, HKDF key derivation,
// AES-128-KW key wrapping, and AES-128-GCM content encryption as required by
// EU eDelivery AS4 2.0 Common Usage Profile.
type X25519Encryptor struct {
	recipientPublicKey *ecdh.PublicKey
	hkdfInfo           []byte
}

// NewX25519Encryptor creates a new encryptor for X25519 key agreement.
// The recipientPublicKey should be the recipient's X25519 public key.
// hkdfInfo is optional context info for HKDF; if nil, a default is used.
func NewX25519Encryptor(recipientPublicKey *ecdh.PublicKey, hkdfInfo []byte) *X25519Encryptor {
	if hkdfInfo == nil {
		hkdfInfo = []byte("EU eDelivery AS4 2.0")
	}
	return &X25519Encryptor{
		recipientPublicKey: recipientPublicKey,
		hkdfInfo:           hkdfInfo,
	}
}

// EncryptElement encrypts an XML element using X25519/HKDF/AES-128-GCM.
// Returns an EncryptedData structure that can be serialized to XML.
func (e *X25519Encryptor) EncryptElement(element *etree.Element) (*xmlenc.EncryptedData, error) {
	hkdfParams := xmlenc.DefaultHKDFParams(e.hkdfInfo)
	ka, err := xmlenc.NewX25519KeyAgreement(e.recipientPublicKey, hkdfParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create key agreement: %w", err)
	}

	encryptor := xmlenc.NewEncryptor(xmlenc.AlgorithmAES128GCM, ka)
	return encryptor.EncryptElement(element)
}

// EncryptBytes encrypts binary data and returns base64-encoded ciphertext
// wrapped in an EncryptedData structure.
func (e *X25519Encryptor) EncryptBytes(data []byte) (*xmlenc.EncryptedData, error) {
	// Create a wrapper element for the binary data
	doc := etree.NewDocument()
	root := doc.CreateElement("Data")
	root.SetText(base64.StdEncoding.EncodeToString(data))

	return e.EncryptElement(root)
}

// X25519Decryptor wraps xmlenc for AS4-specific decryption operations.
type X25519Decryptor struct {
	privateKey *ecdh.PrivateKey
	hkdfInfo   []byte
}

// NewX25519Decryptor creates a new decryptor using the recipient's X25519 private key.
func NewX25519Decryptor(privateKey *ecdh.PrivateKey, hkdfInfo []byte) *X25519Decryptor {
	if hkdfInfo == nil {
		hkdfInfo = []byte("EU eDelivery AS4 2.0")
	}
	return &X25519Decryptor{
		privateKey: privateKey,
		hkdfInfo:   hkdfInfo,
	}
}

// DecryptElement decrypts an EncryptedData structure and returns the original XML element.
func (d *X25519Decryptor) DecryptElement(encData *xmlenc.EncryptedData) (*etree.Element, error) {
	// Validate required nested structure
	if encData.KeyInfo == nil {
		return nil, fmt.Errorf("KeyInfo is missing from EncryptedData")
	}
	if encData.KeyInfo.EncryptedKey == nil {
		return nil, fmt.Errorf("EncryptedKey is missing from KeyInfo")
	}
	if encData.KeyInfo.EncryptedKey.KeyInfo == nil {
		return nil, fmt.Errorf("KeyInfo is missing from EncryptedKey")
	}
	if encData.KeyInfo.EncryptedKey.KeyInfo.AgreementMethod == nil {
		return nil, fmt.Errorf("AgreementMethod is missing")
	}
	if encData.KeyInfo.EncryptedKey.KeyInfo.AgreementMethod.OriginatorKeyInfo == nil {
		return nil, fmt.Errorf("OriginatorKeyInfo is missing from AgreementMethod")
	}
	if encData.KeyInfo.EncryptedKey.KeyInfo.AgreementMethod.OriginatorKeyInfo.KeyValue == nil {
		return nil, fmt.Errorf("KeyValue is missing from OriginatorKeyInfo")
	}
	if encData.KeyInfo.EncryptedKey.KeyInfo.AgreementMethod.OriginatorKeyInfo.KeyValue.ECKeyValue == nil {
		return nil, fmt.Errorf("ECKeyValue is missing from KeyValue")
	}

	// Extract ephemeral public key from the encrypted data
	ephPubBytes := encData.KeyInfo.EncryptedKey.KeyInfo.AgreementMethod.
		OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey

	ephemeralPublic, err := xmlenc.ParseX25519PublicKey(ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ephemeral public key: %w", err)
	}

	hkdfParams := xmlenc.DefaultHKDFParams(d.hkdfInfo)
	ka := xmlenc.NewX25519KeyAgreementForDecrypt(d.privateKey, ephemeralPublic, hkdfParams)
	decryptor := xmlenc.NewDecryptor(ka)

	return decryptor.DecryptElement(encData)
}

// DecryptBytes decrypts an EncryptedData structure containing base64-encoded binary data.
func (d *X25519Decryptor) DecryptBytes(encData *xmlenc.EncryptedData) ([]byte, error) {
	elem, err := d.DecryptElement(encData)
	if err != nil {
		return nil, err
	}

	// Decode the base64 content
	return base64.StdEncoding.DecodeString(elem.Text())
}

// GenerateX25519KeyPair generates a new X25519 key pair for encryption.
// This is a convenience wrapper around xmlenc.GenerateX25519KeyPair.
func GenerateX25519KeyPair() (*ecdh.PrivateKey, error) {
	return xmlenc.GenerateX25519KeyPair()
}

// ExtractX25519PublicKeyFromCert extracts an X25519 public key from a certificate.
// Note: Standard X.509 certificates typically contain RSA or ECDSA keys, not X25519.
// For X25519, the public key is usually distributed out-of-band or in a custom extension.
// This function returns an error if the certificate doesn't contain an X25519 key.
func ExtractX25519PublicKeyFromCert(cert interface{}) (*ecdh.PublicKey, error) {
	// X25519 keys in certificates are not standard, but may be in SubjectPublicKeyInfo
	// For EU AS4 2.0, keys are typically exchanged out-of-band
	return nil, fmt.Errorf("X25519 key extraction from certificate not yet implemented - use out-of-band key exchange")
}

// ParseEncryptedDataFromXML parses an xenc:EncryptedData element from XML.
func ParseEncryptedDataFromXML(element *etree.Element) (*xmlenc.EncryptedData, error) {
	return xmlenc.ParseEncryptedData(element)
}

// EncryptedDataToXML converts an EncryptedData structure to an XML element.
func EncryptedDataToXML(encData *xmlenc.EncryptedData) *etree.Element {
	return encData.ToElement()
}

// CreateEncryptedDataDocument creates an etree.Document with the EncryptedData as root.
func CreateEncryptedDataDocument(encData *xmlenc.EncryptedData) *etree.Document {
	return xmlenc.NewEncryptedDataDocument(encData)
}

// AS4PayloadEncryptor provides AS4-specific payload encryption functionality.
// It supports both X25519 (EU AS4 2.0) and RSA-OAEP (legacy) key transport.
type AS4PayloadEncryptor struct {
	x25519Encryptor *X25519Encryptor
	// rsaEncryptor is kept for legacy RSA-OAEP support
	// rsaEncryptor *RSAEncryptor
}

// NewAS4PayloadEncryptor creates a new AS4 payload encryptor.
// For EU AS4 2.0 compliance, use X25519 key agreement.
func NewAS4PayloadEncryptor(x25519PubKey *ecdh.PublicKey, hkdfInfo []byte) *AS4PayloadEncryptor {
	return &AS4PayloadEncryptor{
		x25519Encryptor: NewX25519Encryptor(x25519PubKey, hkdfInfo),
	}
}

// EncryptPayload encrypts an AS4 payload and returns the EncryptedData structure.
func (e *AS4PayloadEncryptor) EncryptPayload(payload []byte) (*xmlenc.EncryptedData, error) {
	if e.x25519Encryptor != nil {
		return e.x25519Encryptor.EncryptBytes(payload)
	}
	return nil, fmt.Errorf("no encryptor configured")
}

// AS4PayloadDecryptor provides AS4-specific payload decryption functionality.
type AS4PayloadDecryptor struct {
	x25519Decryptor *X25519Decryptor
}

// NewAS4PayloadDecryptor creates a new AS4 payload decryptor.
func NewAS4PayloadDecryptor(x25519PrivKey *ecdh.PrivateKey, hkdfInfo []byte) *AS4PayloadDecryptor {
	return &AS4PayloadDecryptor{
		x25519Decryptor: NewX25519Decryptor(x25519PrivKey, hkdfInfo),
	}
}

// DecryptPayload decrypts an AS4 payload from an EncryptedData structure.
func (d *AS4PayloadDecryptor) DecryptPayload(encData *xmlenc.EncryptedData) ([]byte, error) {
	if d.x25519Decryptor != nil {
		return d.x25519Decryptor.DecryptBytes(encData)
	}
	return nil, fmt.Errorf("no decryptor configured")
}
