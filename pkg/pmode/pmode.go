// Package pmode implements Processing Mode configuration for AS4

package pmode

import (
	"time"
)

// Algorithm suite profiles for interoperability
type SecurityProfile string

const (
	// ProfileAS4v2 uses modern elliptic curve cryptography (Ed25519/X25519)
	ProfileAS4v2 SecurityProfile = "as4v2"
	// ProfileDomibus uses traditional RSA/AES for compatibility with Domibus
	ProfileDomibus SecurityProfile = "domibus"
	// ProfileEDelivery uses EU eDelivery standard algorithms
	ProfileEDelivery SecurityProfile = "edelivery"
	// ProfileCustom allows full custom algorithm configuration
	ProfileCustom SecurityProfile = "custom"
)

// Signature algorithms
type SignatureAlgorithm string

const (
	AlgoEd25519     SignatureAlgorithm = "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519"
	AlgoRSASHA256   SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	AlgoRSASHA384   SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	AlgoRSASHA512   SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	AlgoECDSASHA256 SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
)

// Hash algorithms
type HashAlgorithm string

const (
	HashSHA256 HashAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256"
	HashSHA384 HashAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha384"
	HashSHA512 HashAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha512"
)

// Encryption algorithms for key agreement/transport
type KeyEncryptionAlgorithm string

const (
	KeyAlgoX25519     KeyEncryptionAlgorithm = "http://www.w3.org/2021/04/xmlenc#x25519"
	KeyAlgoRSAOAEP    KeyEncryptionAlgorithm = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	KeyAlgoRSAOAEP256 KeyEncryptionAlgorithm = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
)

// Data encryption algorithms
type DataEncryptionAlgorithm string

const (
	DataAlgoAES128GCM DataEncryptionAlgorithm = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	DataAlgoAES256GCM DataEncryptionAlgorithm = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
	DataAlgoAES128CBC DataEncryptionAlgorithm = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	DataAlgoAES256CBC DataEncryptionAlgorithm = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
)

// Canonicalization algorithms
type CanonicalizationAlgorithm string

const (
	C14NExclusive CanonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#"
	C14NInclusive CanonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
)

// Namespace versions for message format
type NamespaceVersion string

const (
	// NamespaceEBMS3 is the ebXML Messaging 3.0 namespace (AS4 Profile 1.0)
	NamespaceEBMS3 NamespaceVersion = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
	// NamespaceAS4v2 is the AS4 2.0 namespace
	NamespaceAS4v2 NamespaceVersion = "http://docs.oasis-open.org/ebxml-msg/as4/v2.0/ns/core/202X/"
)

// Token reference methods
type TokenReferenceMethod string

const (
	TokenRefBinarySecurityToken TokenReferenceMethod = "BinarySecurityToken"
	TokenRefKeyIdentifier       TokenReferenceMethod = "KeyIdentifier"
	TokenRefIssuerSerial        TokenReferenceMethod = "IssuerSerial"
	TokenRefThumbprint          TokenReferenceMethod = "Thumbprint"
)

// ProcessingMode represents an AS4 Processing Mode configuration
type ProcessingMode struct {
	ID   string
	Legs []Leg

	// General parameters
	Agreement  *Agreement
	MEP        string // MEP URI
	MEPBinding string // MEP binding URI

	// Business info
	Service string
	Action  string

	// Protocol
	Protocol *Protocol

	// Security
	Security *Security

	// Reception Awareness
	ReceptionAwareness *ReceptionAwareness

	// Payload Service
	PayloadService *PayloadService

	// Message format version
	NamespaceVersion NamespaceVersion // ebMS3 or AS4v2

	// Security profile (determines default algorithm suite)
	SecurityProfile SecurityProfile
}

// Leg represents one leg of a message exchange
type Leg struct {
	Protocol           *Protocol
	BusinessInfo       *BusinessInfo
	ErrorHandling      *ErrorHandling
	Security           *Security
	PayloadService     *PayloadService
	ReceptionAwareness *ReceptionAwareness
}

// Agreement contains agreement reference information
type Agreement struct {
	Name  string
	Type  string
	Pmode string
}

// Protocol contains protocol parameters
type Protocol struct {
	Address     string
	SOAPVersion string // "1.2" for AS4
}

// BusinessInfo contains business-level message information
type BusinessInfo struct {
	Service    *Service
	Action     string
	MPC        string // Message Partition Channel (for Pull)
	Properties []Property
}

// Service represents a service
type Service struct {
	Value string
	Type  string
}

// Property represents a message or part property
type Property struct {
	Name  string
	Value string
	Type  string
}

// Security contains security parameters
type Security struct {
	WSSVersion    string // "1.1.1"
	X509          *X509Config
	UsernameToken *UsernameToken
	SendReceipt   *SendReceipt
}

// X509Config contains X.509 certificate-based security settings
type X509Config struct {
	Sign       *SignConfig
	Encryption *EncryptionConfig
}

// SignConfig contains signing configuration
type SignConfig struct {
	Algorithm        SignatureAlgorithm        // Signature algorithm (Ed25519, RSA-SHA256, etc.)
	HashFunction     HashAlgorithm             // Hash function for digest calculation
	Certificate      []byte                    // DER-encoded certificate
	Canonicalization CanonicalizationAlgorithm // C14N algorithm (default: exclusive)
	TokenReference   TokenReferenceMethod      // How to reference the signing token
	SignAttachments  bool                      // Whether to sign MIME attachments
}

// EncryptionConfig contains encryption configuration
type EncryptionConfig struct {
	Algorithm          KeyEncryptionAlgorithm  // Key encryption/agreement algorithm
	KeyDerivation      string                  // HKDF for X25519, empty for RSA
	DataEncryption     DataEncryptionAlgorithm // Symmetric encryption for payload data
	KeyWrap            string                  // Key wrap algorithm (for RSA)
	Certificate        []byte                  // DER-encoded certificate
	EncryptAttachments bool                    // Whether to encrypt MIME attachments
}

// UsernameToken contains username/password authentication (for Pull)
type UsernameToken struct {
	Username string
	Password string
	Digest   bool
	Nonce    bool
	Created  bool
}

// SendReceipt contains receipt sending configuration
type SendReceipt struct {
	ReplyPattern   string // "response" or "callback"
	ReplyTo        string // URL for callback
	NonRepudiation bool
}

// ReceptionAwareness contains reliability parameters
type ReceptionAwareness struct {
	Enabled            bool
	Retry              *RetryConfig
	DuplicateDetection *DuplicateDetectionConfig
}

// RetryConfig contains retry parameters
type RetryConfig struct {
	Enabled         bool
	MaxRetries      int
	RetryInterval   time.Duration
	RetryMultiplier float64
}

// DuplicateDetectionConfig contains duplicate detection parameters
type DuplicateDetectionConfig struct {
	Enabled      bool
	HashFunction string
	Window       time.Duration
}

// ErrorHandling contains error handling configuration
type ErrorHandling struct {
	Report *ErrorReport
}

// ErrorReport configures error reporting
type ErrorReport struct {
	AsResponse                     bool
	ReceiverErrorsTo               string
	SenderErrorsTo                 string
	ProcessErrorNotifyProducer     bool
	MissingReceiptNotifyProducer   bool
	DeliveryFailuresNotifyProducer bool
}

// PayloadService contains payload handling configuration
type PayloadService struct {
	CompressionType string // "application/gzip" or empty
}

// PModeManager manages processing modes
type PModeManager struct {
	pmodes map[string]*ProcessingMode
}

// NewPModeManager creates a new P-Mode manager
func NewPModeManager() *PModeManager {
	return &PModeManager{
		pmodes: make(map[string]*ProcessingMode),
	}
}

// AddPMode adds a processing mode
func (m *PModeManager) AddPMode(pmode *ProcessingMode) {
	m.pmodes[pmode.ID] = pmode
}

// GetPMode retrieves a processing mode by ID
func (m *PModeManager) GetPMode(id string) *ProcessingMode {
	return m.pmodes[id]
}

// RemovePMode removes a processing mode
func (m *PModeManager) RemovePMode(id string) {
	delete(m.pmodes, id)
}

// FindPMode finds a matching P-Mode based on message parameters
func (m *PModeManager) FindPMode(service, action string, fromParty, toParty string) *ProcessingMode {
	for _, pmode := range m.pmodes {
		if pmode.Service == service && pmode.Action == action {
			return pmode
		}
	}
	return nil
}

// DefaultPMode creates a default P-Mode for testing
func DefaultPMode() *ProcessingMode {
	return &ProcessingMode{
		ID:         "default-pmode",
		MEP:        "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/oneWay",
		MEPBinding: "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/push",
		Protocol: &Protocol{
			Address:     "https://receiver.example.com/as4",
			SOAPVersion: "1.2",
		},
		Security: &Security{
			WSSVersion: "1.1.1",
			X509: &X509Config{
				Sign: &SignConfig{
					Algorithm:    "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519",
					HashFunction: "http://www.w3.org/2001/04/xmlenc#sha256",
				},
			},
			SendReceipt: &SendReceipt{
				ReplyPattern:   "response",
				NonRepudiation: true,
			},
		},
		ReceptionAwareness: &ReceptionAwareness{
			Enabled: true,
			Retry: &RetryConfig{
				Enabled:         true,
				MaxRetries:      3,
				RetryInterval:   time.Minute,
				RetryMultiplier: 2.0,
			},
			DuplicateDetection: &DuplicateDetectionConfig{
				Enabled:      true,
				HashFunction: "SHA-256",
				Window:       24 * time.Hour,
			},
		},
		PayloadService: &PayloadService{
			CompressionType: "application/gzip",
		},
		NamespaceVersion: NamespaceEBMS3, // Default to ebMS3 for compatibility
		SecurityProfile:  ProfileDomibus, // Default to Domibus profile
	}
}

// GetDefaultSignConfig returns default signing configuration based on security profile
func GetDefaultSignConfig(profile SecurityProfile) *SignConfig {
	switch profile {
	case ProfileAS4v2:
		return &SignConfig{
			Algorithm:        AlgoEd25519,
			HashFunction:     HashSHA256,
			Canonicalization: C14NExclusive,
			TokenReference:   TokenRefBinarySecurityToken,
			SignAttachments:  true,
		}
	case ProfileDomibus, ProfileEDelivery:
		return &SignConfig{
			Algorithm:        AlgoRSASHA256,
			HashFunction:     HashSHA256,
			Canonicalization: C14NExclusive,
			TokenReference:   TokenRefKeyIdentifier,
			SignAttachments:  true,
		}
	default:
		// ProfileCustom or unknown - return minimal config
		return &SignConfig{
			Algorithm:        AlgoRSASHA256,
			HashFunction:     HashSHA256,
			Canonicalization: C14NExclusive,
			TokenReference:   TokenRefBinarySecurityToken,
			SignAttachments:  false,
		}
	}
}

// GetDefaultEncryptionConfig returns default encryption configuration based on security profile
func GetDefaultEncryptionConfig(profile SecurityProfile) *EncryptionConfig {
	switch profile {
	case ProfileAS4v2:
		return &EncryptionConfig{
			Algorithm:          KeyAlgoX25519,
			KeyDerivation:      "HKDF-SHA256",
			DataEncryption:     DataAlgoAES128GCM,
			EncryptAttachments: true,
		}
	case ProfileDomibus, ProfileEDelivery:
		return &EncryptionConfig{
			Algorithm:          KeyAlgoRSAOAEP,
			KeyDerivation:      "",
			DataEncryption:     DataAlgoAES128GCM,
			KeyWrap:            "http://www.w3.org/2001/04/xmlenc#kw-aes128",
			EncryptAttachments: true,
		}
	default:
		return &EncryptionConfig{
			Algorithm:          KeyAlgoRSAOAEP,
			DataEncryption:     DataAlgoAES128GCM,
			EncryptAttachments: false,
		}
	}
}

// GetNamespaceURI returns the namespace URI for the configured version
func (pm *ProcessingMode) GetNamespaceURI() string {
	if pm.NamespaceVersion == "" {
		// Default to ebMS3 for compatibility
		return string(NamespaceEBMS3)
	}
	return string(pm.NamespaceVersion)
}

// IsEBMS3 returns true if using ebMS 3.0 namespace
func (pm *ProcessingMode) IsEBMS3() bool {
	return pm.NamespaceVersion == NamespaceEBMS3 || pm.NamespaceVersion == ""
}

// IsAS4v2 returns true if using AS4 2.0 namespace
func (pm *ProcessingMode) IsAS4v2() bool {
	return pm.NamespaceVersion == NamespaceAS4v2
}
