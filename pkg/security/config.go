package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
)

// Option represents a functional option for SecurityConfig
type Option func(*SecurityConfig)

// NewSecurityConfig creates a new security configuration
func NewSecurityConfig(opts ...Option) *SecurityConfig {
	cfg := &SecurityConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

// WithSigningKey sets the Ed25519 signing key
func WithSigningKey(key ed25519.PrivateKey) Option {
	return func(cfg *SecurityConfig) {
		cfg.SigningKey = key
	}
}

// WithSigningCert sets the signing certificate
func WithSigningCert(cert *x509.Certificate) Option {
	return func(cfg *SecurityConfig) {
		cfg.SigningCert = cert
	}
}

// WithEncryptionKey sets the X25519 encryption key
func WithEncryptionKey(key *[32]byte) Option {
	return func(cfg *SecurityConfig) {
		cfg.EncryptionKey = key
	}
}

// WithEncryptionCert sets the encryption certificate
func WithEncryptionCert(cert *x509.Certificate) Option {
	return func(cfg *SecurityConfig) {
		cfg.EncryptionCert = cert
	}
}

// WithRecipientCert sets the recipient's certificate for encryption
func WithRecipientCert(cert *x509.Certificate) Option {
	return func(cfg *SecurityConfig) {
		cfg.RecipientCert = cert
	}
}

// GenerateEd25519Key generates a new Ed25519 key pair
// Uses crypto/rand.Reader explicitly for cryptographically secure randomness
func GenerateEd25519Key() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}
