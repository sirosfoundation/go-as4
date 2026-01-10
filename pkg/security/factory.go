// Package security provides unified signer and encryptor interfaces
package security

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/sirosfoundation/go-as4/pkg/pmode"
)

// Signer is a unified interface for XML signing (Ed25519 or RSA)
type Signer interface {
	SignEnvelope(envelopeXML []byte) ([]byte, error)
	SignEnvelopeWithAttachments(envelopeXML []byte, attachments []Attachment) ([]byte, error)
	VerifyEnvelope(envelopeXML []byte) error
	VerifyEnvelopeWithAttachments(envelopeXML []byte, attachments []Attachment) error
}

// Attachment represents a MIME attachment to be signed
type Attachment struct {
	ContentID   string // e.g., "<payload-1@as4.siros.org>"
	ContentType string
	Data        []byte
}

// Encryptor is a unified interface for payload encryption (X25519 or RSA)
type Encryptor interface {
	EncryptPayload(data []byte) (encrypted []byte, metadata map[string]string, err error)
	DecryptPayload(encrypted []byte, metadata map[string]string) ([]byte, error)
}

// SignerFactory creates signers based on algorithm configuration
type SignerFactory struct{}

// NewSigner creates a signer based on the sign configuration
func (f *SignerFactory) NewSigner(config *pmode.SignConfig, privateKey interface{}, cert *x509.Certificate) (Signer, error) {
	if config == nil {
		return nil, fmt.Errorf("sign config is required")
	}

	switch config.Algorithm {
	case pmode.AlgoEd25519:
		// Ed25519 signer
		ed25519Key, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("expected ed25519.PrivateKey, got %T", privateKey)
		}
		return NewXMLSigner(ed25519Key, cert)

	case pmode.AlgoRSASHA256:
		// RSA-SHA256 signer
		rsaKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("expected *rsa.PrivateKey, got %T", privateKey)
		}
		return NewRSASignerWithTokenRef(rsaKey, cert, crypto.SHA256, crypto.SHA256, config.TokenReference)

	case pmode.AlgoRSASHA384:
		// RSA-SHA384 signer
		rsaKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("expected *rsa.PrivateKey, got %T", privateKey)
		}
		return NewRSASignerWithTokenRef(rsaKey, cert, crypto.SHA384, crypto.SHA384, config.TokenReference)

	case pmode.AlgoRSASHA512:
		// RSA-SHA512 signer
		rsaKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("expected *rsa.PrivateKey, got %T", privateKey)
		}
		return NewRSASignerWithTokenRef(rsaKey, cert, crypto.SHA512, crypto.SHA512, config.TokenReference)

	default:
		return nil, fmt.Errorf("unsupported signature algorithm: %s", config.Algorithm)
	}
}

// EncryptorFactory creates encryptors based on algorithm configuration
type EncryptorFactory struct{}

// NewEncryptor creates an encryptor based on the encryption configuration
func (f *EncryptorFactory) NewEncryptor(config *pmode.EncryptionConfig, recipientCert *x509.Certificate) (Encryptor, error) {
	if config == nil {
		return nil, fmt.Errorf("encryption config is required")
	}

	switch config.Algorithm {
	case pmode.KeyAlgoX25519:
		// X25519 key agreement with HKDF
		recipientPubKey, err := extractX25519PublicKey(recipientCert)
		if err != nil {
			return nil, fmt.Errorf("failed to extract X25519 public key: %w", err)
		}
		var pubKey [32]byte
		copy(pubKey[:], recipientPubKey)
		return NewAESEncryptor(pubKey), nil

	case pmode.KeyAlgoRSAOAEP, pmode.KeyAlgoRSAOAEP256:
		// RSA-OAEP key transport
		return NewRSAEncryptor(recipientCert, string(config.DataEncryption))

	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", config.Algorithm)
	}
}

// NewDecryptor creates a decryptor based on the encryption configuration
func (f *EncryptorFactory) NewDecryptor(config *pmode.EncryptionConfig, privateKey interface{}) (Encryptor, error) {
	if config == nil {
		return nil, fmt.Errorf("encryption config is required")
	}

	switch config.Algorithm {
	case pmode.KeyAlgoX25519:
		// X25519 key agreement with HKDF
		x25519Key, ok := privateKey.([32]byte)
		if !ok {
			// Try converting from slice
			keySlice, ok := privateKey.([]byte)
			if !ok || len(keySlice) != 32 {
				return nil, fmt.Errorf("invalid X25519 private key type")
			}
			copy(x25519Key[:], keySlice)
		}
		return NewAESDecryptor(x25519Key), nil

	case pmode.KeyAlgoRSAOAEP, pmode.KeyAlgoRSAOAEP256:
		// RSA-OAEP key transport
		rsaKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("expected *rsa.PrivateKey, got %T", privateKey)
		}
		return NewRSADecryptor(rsaKey, string(config.DataEncryption))

	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", config.Algorithm)
	}
}

// extractX25519PublicKey extracts X25519 public key from certificate
// This is a placeholder - actual implementation would depend on how X25519
// keys are stored in X.509 certificates
func extractX25519PublicKey(cert *x509.Certificate) ([]byte, error) {
	// For now, we assume the certificate subject public key info contains
	// the X25519 public key. This would need proper ASN.1 parsing.

	// Temporary: check if it's an Ed25519 cert and derive X25519 from it
	// In production, X25519 keys should be explicitly stored
	if ed25519Key, ok := cert.PublicKey.(ed25519.PublicKey); ok {
		// This is a simplification - in reality you'd need proper X25519 keys
		if len(ed25519Key) != 32 {
			return nil, fmt.Errorf("invalid Ed25519 key length")
		}
		// For compatibility, we return the Ed25519 key
		// Real implementation should use actual X25519 keys
		return []byte(ed25519Key), nil
	}

	return nil, fmt.Errorf("X25519 public key extraction not implemented for certificate type")
}

// GetDefaultAlgorithms returns default algorithm configuration for a security profile
func GetDefaultAlgorithms(profile pmode.SecurityProfile) (*pmode.SignConfig, *pmode.EncryptionConfig) {
	signConfig := pmode.GetDefaultSignConfig(profile)
	encryptConfig := pmode.GetDefaultEncryptionConfig(profile)
	return signConfig, encryptConfig
}
