// Package keystore provides key management abstractions for the AS4 server
//
// This package defines a unified interface for signing operations that can be
// implemented by different backends:
//
//   - PRF-based: Keys encrypted with FIDO2/PRF-derived keys, decrypted during
//     authenticated sessions
//   - PKCS#11: Keys stored in hardware security modules (HSM) or smart cards
//   - File-based: Keys loaded from PEM files (development only)
//
// The abstraction allows the AS4 server to sign messages without knowing the
// underlying key storage mechanism.
package keystore

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"io"
	"time"
)

// Common errors
var (
	ErrKeyNotFound      = errors.New("signing key not found")
	ErrNotAuthenticated = errors.New("session not authenticated for signing")
	ErrKeyLocked        = errors.New("signing key is locked")
	ErrPINRequired      = errors.New("PIN required to unlock key")
	ErrSessionExpired   = errors.New("signing session has expired")
)

// SignerProvider provides signing capabilities for a tenant/participant
//
// Implementations must be safe for concurrent use.
type SignerProvider interface {
	// GetSigner returns a signer for the specified tenant and key ID.
	// The context may contain session credentials (e.g., PRF output, PIN).
	//
	// For PRF mode: ctx should contain the decrypted main key from FIDO2 auth
	// For PKCS#11 mode: ctx should contain the PIN or be nil if already authenticated
	// For file mode: ctx is ignored
	GetSigner(ctx context.Context, tenantID, keyID string) (Signer, error)

	// GetCertificate returns the X.509 certificate for the specified key.
	// This can be called without authentication as certificates are public.
	GetCertificate(ctx context.Context, tenantID, keyID string) (*x509.Certificate, error)

	// ListKeys returns all key IDs available for a tenant.
	ListKeys(ctx context.Context, tenantID string) ([]KeyInfo, error)

	// Close releases any resources held by the provider.
	Close() error
}

// Signer performs cryptographic signing operations
//
// This interface is intentionally minimal - it provides just enough to sign
// AS4 messages. The implementation handles the complexity of key access.
type Signer interface {
	// Sign signs the digest using the underlying private key.
	// The opts parameter specifies the signature algorithm.
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)

	// Public returns the public key corresponding to the private key.
	Public() crypto.PublicKey

	// Certificate returns the X.509 certificate for this signer.
	Certificate() *x509.Certificate

	// Algorithm returns the signature algorithm URI for XML signatures.
	Algorithm() string
}

// KeyInfo describes a signing key
type KeyInfo struct {
	// KeyID is the unique identifier for this key within the tenant
	KeyID string

	// Label is a human-readable name for the key
	Label string

	// Algorithm is the key algorithm (e.g., "RSA", "EC", "Ed25519")
	Algorithm string

	// KeySize is the key size in bits (e.g., 2048 for RSA, 256 for P-256)
	KeySize int

	// NotBefore is when the associated certificate becomes valid
	NotBefore time.Time

	// NotAfter is when the associated certificate expires
	NotAfter time.Time

	// CertificateSubject is the subject DN of the certificate
	CertificateSubject string
}

// SessionCredentials carries authentication context for signing operations
type SessionCredentials struct {
	// TenantID identifies the tenant
	TenantID string

	// UserID identifies the authenticated user
	UserID string

	// MainKey is the decrypted main encryption key (PRF mode only)
	// This key is used to decrypt the tenant's signing key
	MainKey []byte

	// PIN is the PKCS#11 PIN (PKCS#11 mode only)
	PIN string

	// ExpiresAt is when these credentials expire
	ExpiresAt time.Time
}

// ContextKey is the type for context keys in this package
type ContextKey string

const (
	// CredentialsKey is the context key for SessionCredentials
	CredentialsKey ContextKey = "keystore.credentials"
)

// CredentialsFromContext extracts session credentials from context
func CredentialsFromContext(ctx context.Context) (*SessionCredentials, bool) {
	creds, ok := ctx.Value(CredentialsKey).(*SessionCredentials)
	return creds, ok
}

// ContextWithCredentials adds session credentials to context
func ContextWithCredentials(ctx context.Context, creds *SessionCredentials) context.Context {
	return context.WithValue(ctx, CredentialsKey, creds)
}

// EncryptedKeyBlob represents a key encrypted with a PRF-derived key
type EncryptedKeyBlob struct {
	// KeyID is the unique identifier for this key
	KeyID string

	// Algorithm is the key algorithm (e.g., "RSA", "EC")
	Algorithm string

	// EncryptedKey is the encrypted private key (PKCS#8 DER encrypted with AES-GCM)
	EncryptedKey []byte

	// IV is the AES-GCM initialization vector
	IV []byte

	// Tag is the AES-GCM authentication tag (may be appended to EncryptedKey)
	Tag []byte

	// Salt is the HKDF salt used to derive the encryption key from MainKey
	Salt []byte
}

// EncryptedKeyStore provides storage for encrypted signing keys (PRF mode)
type EncryptedKeyStore interface {
	// GetEncryptedKey retrieves an encrypted key blob for a tenant
	GetEncryptedKey(ctx context.Context, tenantID, keyID string) (*EncryptedKeyBlob, error)

	// StoreEncryptedKey saves an encrypted key blob for a tenant
	StoreEncryptedKey(ctx context.Context, tenantID string, blob *EncryptedKeyBlob) error

	// GetCertificate retrieves the X.509 certificate for a key
	GetCertificate(ctx context.Context, tenantID, keyID string) (*x509.Certificate, error)

	// StoreCertificate saves an X.509 certificate for a key
	StoreCertificate(ctx context.Context, tenantID, keyID string, cert *x509.Certificate) error

	// ListKeys lists all key IDs for a tenant
	ListKeys(ctx context.Context, tenantID string) ([]KeyInfo, error)

	// DeleteKey removes a key and its certificate
	DeleteKey(ctx context.Context, tenantID, keyID string) error
}
