// Package security implements WS-Security 1.1.1 for AS4 messaging
//
// This package provides:
// - WS-Security envelope construction with timestamps and token references
// - Integration with signedxml for XML digital signatures
// - Integration with go-trust/authzenclient for certificate validation
//
// XML signature operations are delegated to the signedxml package.
// Certificate validation is delegated to go-trust AuthZEN.
package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
)

// Algorithm URIs for XML signature and encryption
const (
	// Signature algorithms
	AlgorithmRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	AlgorithmRSASHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	AlgorithmRSASHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	AlgorithmEd25519   = "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519"

	// Digest algorithms
	AlgorithmSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
	AlgorithmSHA384 = "http://www.w3.org/2001/04/xmlenc#sha384"
	AlgorithmSHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"

	// Canonicalization algorithms
	AlgorithmC14N             = "http://www.w3.org/2001/10/xml-exc-c14n#"
	AlgorithmC14NWithComments = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"

	// Encryption algorithms
	AlgorithmX25519    = "http://www.w3.org/2021/04/xmldsig-more#x25519"
	AlgorithmHKDF      = "http://www.w3.org/2021/04/xmldsig-more#hkdf"
	AlgorithmAES128GCM = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	AlgorithmAES256GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
	AlgorithmAES128KW  = "http://www.w3.org/2001/04/xmlenc#kw-aes128"
	AlgorithmRSAOAEP   = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
)

// WS-Security namespaces
const (
	NSSecurityExt  = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	NSSecurityUtil = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	NSXMLDSig      = "http://www.w3.org/2000/09/xmldsig#"
	NSXMLEnc       = "http://www.w3.org/2001/04/xmlenc#"
	NSSOAP12       = "http://www.w3.org/2003/05/soap-envelope"
)

// SecurityConfig holds security configuration for AS4
type SecurityConfig struct {
	SigningKey       ed25519.PrivateKey // Ed25519 private key for signing
	SigningCert      *x509.Certificate  // Certificate for signing
	EncryptionKey    *[32]byte          // X25519 private key for encryption
	EncryptionCert   *x509.Certificate  // Certificate for encryption
	RecipientCert    *x509.Certificate  // Recipient's certificate for encryption
	TrustPDPEndpoint string             // AuthZEN PDP endpoint URL for certificate validation
}

// WS-Security XML types for envelope construction

// Signature represents an XML digital signature
type Signature struct {
	XMLName        xml.Name    `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	ID             string      `xml:"Id,attr,omitempty"`
	SignedInfo     *SignedInfo `xml:"SignedInfo"`
	SignatureValue string      `xml:"SignatureValue"`
	KeyInfo        *KeyInfo    `xml:"KeyInfo"`
}

// SignedInfo contains information about the signature
type SignedInfo struct {
	CanonicalizationMethod *CanonicalizationMethod `xml:"CanonicalizationMethod"`
	SignatureMethod        *SignatureMethod        `xml:"SignatureMethod"`
	Reference              []Reference             `xml:"Reference"`
}

// CanonicalizationMethod specifies the canonicalization algorithm
type CanonicalizationMethod struct {
	Algorithm           string               `xml:"Algorithm,attr"`
	InclusiveNamespaces *InclusiveNamespaces `xml:"InclusiveNamespaces,omitempty"`
}

// InclusiveNamespaces for exclusive C14N
type InclusiveNamespaces struct {
	PrefixList string `xml:"PrefixList,attr"`
}

// SignatureMethod specifies the signature algorithm
type SignatureMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// Reference represents a signed element reference
type Reference struct {
	URI          string        `xml:"URI,attr"`
	Transforms   *Transforms   `xml:"Transforms,omitempty"`
	DigestMethod *DigestMethod `xml:"DigestMethod"`
	DigestValue  string        `xml:"DigestValue"`
}

// Transforms contains transformation algorithms
type Transforms struct {
	Transform []Transform `xml:"Transform"`
}

// Transform represents a transformation
type Transform struct {
	Algorithm           string               `xml:"Algorithm,attr"`
	InclusiveNamespaces *InclusiveNamespaces `xml:"http://www.w3.org/2001/10/xml-exc-c14n# InclusiveNamespaces,omitempty"`
}

// DigestMethod specifies the digest algorithm
type DigestMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// KeyInfo contains key information
type KeyInfo struct {
	ID                     string                  `xml:"Id,attr,omitempty"`
	SecurityTokenReference *SecurityTokenReference `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd SecurityTokenReference,omitempty"`
	X509Data               *X509Data               `xml:"http://www.w3.org/2000/09/xmldsig# X509Data,omitempty"`
}

// SecurityTokenReference references a security token
type SecurityTokenReference struct {
	ID            string         `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd Id,attr,omitempty"`
	TokenType     string         `xml:"http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd TokenType,attr,omitempty"`
	Reference     *TokenRef      `xml:"Reference,omitempty"`
	KeyIdentifier *KeyIdentifier `xml:"KeyIdentifier,omitempty"`
}

// TokenRef references a security token by URI
type TokenRef struct {
	URI       string `xml:"URI,attr"`
	ValueType string `xml:"ValueType,attr,omitempty"`
}

// KeyIdentifier identifies a key
type KeyIdentifier struct {
	EncodingType string `xml:"EncodingType,attr,omitempty"`
	ValueType    string `xml:"ValueType,attr,omitempty"`
	Value        string `xml:",chardata"`
}

// X509Data contains X.509 certificate information
type X509Data struct {
	X509Certificate  string            `xml:"X509Certificate,omitempty"`
	X509IssuerSerial *X509IssuerSerial `xml:"X509IssuerSerial,omitempty"`
}

// X509IssuerSerial identifies a certificate by issuer and serial
type X509IssuerSerial struct {
	X509IssuerName   string `xml:"X509IssuerName"`
	X509SerialNumber string `xml:"X509SerialNumber"`
}

// BinarySecurityToken contains a binary security token (certificate)
type BinarySecurityToken struct {
	ID           string `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd Id,attr,omitempty"`
	EncodingType string `xml:"EncodingType,attr"`
	ValueType    string `xml:"ValueType,attr"`
	Value        string `xml:",chardata"`
}

// Timestamp contains WS-Security timestamp information
type Timestamp struct {
	ID      string `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd Id,attr,omitempty"`
	Created string `xml:"Created"`
	Expires string `xml:"Expires,omitempty"`
}

// Encryption types

// EncryptedKey represents an encrypted key
type EncryptedKey struct {
	XMLName          xml.Name          `xml:"http://www.w3.org/2001/04/xmlenc# EncryptedKey"`
	ID               string            `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd Id,attr,omitempty"`
	EncryptionMethod *EncryptionMethod `xml:"EncryptionMethod"`
	KeyInfo          *KeyInfo          `xml:"KeyInfo"`
	CipherData       *CipherData       `xml:"CipherData"`
	ReferenceList    *ReferenceList    `xml:"ReferenceList,omitempty"`
}

// EncryptionMethod specifies the encryption algorithm
type EncryptionMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

// CipherData contains encrypted data
type CipherData struct {
	CipherValue     string           `xml:"CipherValue,omitempty"`
	CipherReference *CipherReference `xml:"CipherReference,omitempty"`
}

// CipherReference references encrypted data
type CipherReference struct {
	URI        string      `xml:"URI,attr"`
	Transforms *Transforms `xml:"Transforms,omitempty"`
}

// ReferenceList lists encrypted data references
type ReferenceList struct {
	DataReference []DataReference `xml:"DataReference"`
}

// DataReference references encrypted data
type DataReference struct {
	URI string `xml:"URI,attr"`
}

// EncryptedData represents encrypted data
type EncryptedData struct {
	XMLName          xml.Name          `xml:"http://www.w3.org/2001/04/xmlenc# EncryptedData"`
	ID               string            `xml:"Id,attr,omitempty"`
	Type             string            `xml:"Type,attr,omitempty"`
	MimeType         string            `xml:"MimeType,attr,omitempty"`
	EncryptionMethod *EncryptionMethod `xml:"EncryptionMethod"`
	KeyInfo          *KeyInfo          `xml:"KeyInfo,omitempty"`
	CipherData       *CipherData       `xml:"CipherData"`
}

// generateID generates a random ID for XML elements using hex encoding
// to avoid special characters like '=' that may cause issues with XPointer
func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
