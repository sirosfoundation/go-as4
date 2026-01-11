// Package keystore provides the PRF-based signer implementation
package keystore

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// PRFProvider implements SignerProvider using PRF-encrypted keys
//
// Keys are stored as encrypted JWE blobs in the database. When a user
// authenticates with FIDO2 (using the PRF extension), the PRF output
// is used to derive a key that can decrypt the signing key.
//
// This implementation maintains a session cache of decrypted keys,
// bounded by time (KeyTTL) and count (MaxKeys).
type PRFProvider struct {
	store   EncryptedKeyStore
	keyTTL  time.Duration
	maxKeys int

	mu    sync.RWMutex
	cache map[string]*cachedSigner
}

type cachedSigner struct {
	signer    *prfSigner
	expiresAt time.Time
}

// PRFProviderConfig holds configuration for the PRF provider
type PRFProviderConfig struct {
	// Store is the encrypted key storage backend
	Store EncryptedKeyStore

	// KeyTTL is how long decrypted keys remain in memory
	KeyTTL time.Duration

	// MaxKeys is the maximum number of cached keys
	MaxKeys int
}

// NewPRFProvider creates a new PRF-based signer provider
func NewPRFProvider(cfg *PRFProviderConfig) (*PRFProvider, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("store is required")
	}

	keyTTL := cfg.KeyTTL
	if keyTTL == 0 {
		keyTTL = 15 * time.Minute
	}

	maxKeys := cfg.MaxKeys
	if maxKeys == 0 {
		maxKeys = 100
	}

	p := &PRFProvider{
		store:   cfg.Store,
		keyTTL:  keyTTL,
		maxKeys: maxKeys,
		cache:   make(map[string]*cachedSigner),
	}

	// Start cache cleanup goroutine
	go p.cleanupLoop()

	return p, nil
}

// GetSigner returns a signer for the specified tenant and key ID
//
// The context must contain SessionCredentials with the MainKey set.
// The MainKey is derived from the FIDO2 PRF output during authentication.
func (p *PRFProvider) GetSigner(ctx context.Context, tenantID, keyID string) (Signer, error) {
	cacheKey := tenantID + ":" + keyID

	// Check cache first
	p.mu.RLock()
	if cached, ok := p.cache[cacheKey]; ok && time.Now().Before(cached.expiresAt) {
		p.mu.RUnlock()
		return cached.signer, nil
	}
	p.mu.RUnlock()

	// Get credentials from context
	creds, ok := CredentialsFromContext(ctx)
	if !ok || creds.MainKey == nil {
		return nil, ErrNotAuthenticated
	}

	// Check if credentials are expired
	if !creds.ExpiresAt.IsZero() && time.Now().After(creds.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	// Load and decrypt the key
	blob, err := p.store.GetEncryptedKey(ctx, tenantID, keyID)
	if err != nil {
		return nil, err
	}

	signer, err := p.decryptKey(blob, creds.MainKey)
	if err != nil {
		return nil, fmt.Errorf("decrypting key: %w", err)
	}

	// Get the certificate
	cert, err := p.store.GetCertificate(ctx, tenantID, keyID)
	if err != nil {
		return nil, fmt.Errorf("getting certificate: %w", err)
	}
	signer.cert = cert

	// Cache it
	p.mu.Lock()
	// Evict oldest if at capacity
	if len(p.cache) >= p.maxKeys {
		p.evictOldest()
	}
	p.cache[cacheKey] = &cachedSigner{
		signer:    signer,
		expiresAt: time.Now().Add(p.keyTTL),
	}
	p.mu.Unlock()

	return signer, nil
}

// GetCertificate returns the certificate for the specified key
func (p *PRFProvider) GetCertificate(ctx context.Context, tenantID, keyID string) (*x509.Certificate, error) {
	return p.store.GetCertificate(ctx, tenantID, keyID)
}

// ListKeys returns all key IDs for a tenant
func (p *PRFProvider) ListKeys(ctx context.Context, tenantID string) ([]KeyInfo, error) {
	return p.store.ListKeys(ctx, tenantID)
}

// Close releases resources
func (p *PRFProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cache = make(map[string]*cachedSigner)
	return nil
}

// ClearCache removes all cached keys (e.g., on logout)
func (p *PRFProvider) ClearCache() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cache = make(map[string]*cachedSigner)
}

// ClearTenantCache removes cached keys for a specific tenant
func (p *PRFProvider) ClearTenantCache(tenantID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	prefix := tenantID + ":"
	for key := range p.cache {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			delete(p.cache, key)
		}
	}
}

func (p *PRFProvider) decryptKey(blob *EncryptedKeyBlob, mainKey []byte) (*prfSigner, error) {
	// Derive the decryption key using HKDF
	// In a full implementation, this would match the wallet-frontend HKDF derivation
	decryptionKey, err := deriveDecryptionKey(mainKey, blob.Salt)
	if err != nil {
		return nil, fmt.Errorf("deriving decryption key: %w", err)
	}

	// Decrypt with AES-GCM
	block, err := aes.NewCipher(decryptionKey)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	// Combine ciphertext and tag for Go's GCM interface
	ciphertext := append(blob.EncryptedKey, blob.Tag...)

	plaintext, err := gcm.Open(nil, blob.IV, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	// Parse the JWK
	return parsePrivateKeyJWK(plaintext, blob.Algorithm)
}

func (p *PRFProvider) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, cached := range p.cache {
		if oldestKey == "" || cached.expiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = cached.expiresAt
		}
	}

	if oldestKey != "" {
		delete(p.cache, oldestKey)
	}
}

func (p *PRFProvider) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		now := time.Now()
		for key, cached := range p.cache {
			if now.After(cached.expiresAt) {
				delete(p.cache, key)
			}
		}
		p.mu.Unlock()
	}
}

// prfSigner implements Signer for PRF-decrypted keys
type prfSigner struct {
	key       crypto.Signer
	cert      *x509.Certificate
	algorithm string
}

func (s *prfSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(rand, digest, opts)
}

func (s *prfSigner) Public() crypto.PublicKey {
	return s.key.Public()
}

func (s *prfSigner) Certificate() *x509.Certificate {
	return s.cert
}

func (s *prfSigner) Algorithm() string {
	return s.algorithm
}

// deriveDecryptionKey derives a 256-bit key from the main key using HKDF
func deriveDecryptionKey(mainKey, salt []byte) ([]byte, error) {
	// This should match the wallet-frontend HKDF derivation
	// Using SHA-256 and info = "AS4 Signing Key"

	// Simplified implementation - in production, use golang.org/x/crypto/hkdf
	// matching the exact parameters from wallet-frontend

	// For now, use a simple derivation (to be replaced with proper HKDF)
	if len(mainKey) < 32 {
		return nil, fmt.Errorf("main key too short")
	}

	key := make([]byte, 32)
	copy(key, mainKey[:32])

	// XOR with salt for basic key separation
	for i := 0; i < len(salt) && i < 32; i++ {
		key[i] ^= salt[i]
	}

	return key, nil
}

// parsePrivateKeyJWK parses a JWK-formatted private key
func parsePrivateKeyJWK(jwkBytes []byte, algorithm string) (*prfSigner, error) {
	var jwk map[string]interface{}
	if err := json.Unmarshal(jwkBytes, &jwk); err != nil {
		return nil, fmt.Errorf("parsing JWK: %w", err)
	}

	kty, _ := jwk["kty"].(string)

	switch kty {
	case "RSA":
		key, err := parseRSAPrivateKeyJWK(jwk)
		if err != nil {
			return nil, err
		}
		return &prfSigner{
			key:       key,
			algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		}, nil

	case "EC":
		key, err := parseECPrivateKeyJWK(jwk)
		if err != nil {
			return nil, err
		}
		return &prfSigner{
			key:       key,
			algorithm: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
		}, nil

	default:
		return nil, fmt.Errorf("unsupported key type: %s", kty)
	}
}

// parseRSAPrivateKeyJWK parses an RSA private key from JWK
func parseRSAPrivateKeyJWK(jwk map[string]interface{}) (*rsa.PrivateKey, error) {
	// This is a simplified implementation
	// In production, use a proper JWK library like go-jose
	return nil, fmt.Errorf("RSA JWK parsing not implemented - use go-jose")
}

// parseECPrivateKeyJWK parses an EC private key from JWK
func parseECPrivateKeyJWK(jwk map[string]interface{}) (*ecdsa.PrivateKey, error) {
	// This is a simplified implementation
	// In production, use a proper JWK library like go-jose
	return nil, fmt.Errorf("EC JWK parsing not implemented - use go-jose")
}
