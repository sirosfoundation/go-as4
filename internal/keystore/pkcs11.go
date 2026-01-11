//go:build pkcs11

// Package keystore provides the PKCS#11 signer implementation
package keystore

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/ThalesGroup/crypto11"
)

// PKCS11Provider implements SignerProvider using a PKCS#11 token (HSM/smart card)
type PKCS11Provider struct {
	ctx             *crypto11.Context
	keyLabelPattern string
	mu              sync.RWMutex
	signers         map[string]*pkcs11Signer // Cache of tenant+keyID -> signer
}

// PKCS11Config holds configuration for the PKCS#11 provider
type PKCS11Config struct {
	// ModulePath is the path to the PKCS#11 library (.so/.dylib/.dll)
	ModulePath string

	// SlotID is the slot number to use (optional if SlotLabel is provided)
	SlotID *uint

	// SlotLabel is the token label to search for (optional if SlotID is provided)
	SlotLabel string

	// PIN is the user PIN for authentication
	PIN string

	// KeyLabelPattern is the pattern for key labels
	// Use {tenant-id} as placeholder, e.g., "tenant-{tenant-id}-signing"
	KeyLabelPattern string
}

// NewPKCS11Provider creates a new PKCS#11 signer provider
func NewPKCS11Provider(cfg *PKCS11Config) (*PKCS11Provider, error) {
	config := &crypto11.Config{
		Path: cfg.ModulePath,
		Pin:  cfg.PIN,
	}

	if cfg.SlotID != nil {
		slotID := int(*cfg.SlotID)
		config.SlotNumber = &slotID
	}
	if cfg.SlotLabel != "" {
		config.TokenLabel = cfg.SlotLabel
	}

	ctx, err := crypto11.Configure(config)
	if err != nil {
		return nil, fmt.Errorf("configuring PKCS#11: %w", err)
	}

	pattern := cfg.KeyLabelPattern
	if pattern == "" {
		pattern = "tenant-{tenant-id}-signing"
	}

	return &PKCS11Provider{
		ctx:             ctx,
		keyLabelPattern: pattern,
		signers:         make(map[string]*pkcs11Signer),
	}, nil
}

// GetSigner returns a signer for the specified tenant and key ID
func (p *PKCS11Provider) GetSigner(ctx context.Context, tenantID, keyID string) (Signer, error) {
	cacheKey := tenantID + ":" + keyID

	// Check cache first
	p.mu.RLock()
	if signer, ok := p.signers[cacheKey]; ok {
		p.mu.RUnlock()
		return signer, nil
	}
	p.mu.RUnlock()

	// Load the key
	label := p.keyLabel(tenantID, keyID)
	signer, err := p.loadSigner(label)
	if err != nil {
		return nil, err
	}

	// Cache it
	p.mu.Lock()
	p.signers[cacheKey] = signer
	p.mu.Unlock()

	return signer, nil
}

// GetCertificate returns the certificate for the specified key
func (p *PKCS11Provider) GetCertificate(ctx context.Context, tenantID, keyID string) (*x509.Certificate, error) {
	label := p.keyLabel(tenantID, keyID)
	certs, err := p.ctx.FindCertificate(nil, []byte(label), nil)
	if err != nil {
		return nil, fmt.Errorf("finding certificate: %w", err)
	}
	if certs == nil {
		return nil, ErrKeyNotFound
	}
	return certs, nil
}

// ListKeys returns all key IDs for a tenant
func (p *PKCS11Provider) ListKeys(ctx context.Context, tenantID string) ([]KeyInfo, error) {
	// PKCS#11 doesn't have a great way to enumerate by pattern,
	// so we'd need to enumerate all and filter
	// For now, return empty - this can be implemented based on specific HSM capabilities
	return nil, nil
}

// Close releases PKCS#11 resources
func (p *PKCS11Provider) Close() error {
	return p.ctx.Close()
}

func (p *PKCS11Provider) keyLabel(tenantID, keyID string) string {
	label := strings.Replace(p.keyLabelPattern, "{tenant-id}", tenantID, -1)
	if keyID != "" && keyID != "default" {
		label = label + "-" + keyID
	}
	return label
}

func (p *PKCS11Provider) loadSigner(label string) (*pkcs11Signer, error) {
	// Find the private key by label
	key, err := p.ctx.FindKeyPair(nil, []byte(label))
	if err != nil {
		return nil, fmt.Errorf("finding key pair: %w", err)
	}
	if key == nil {
		return nil, ErrKeyNotFound
	}

	// Find the associated certificate
	cert, err := p.ctx.FindCertificate(nil, []byte(label), nil)
	if err != nil {
		return nil, fmt.Errorf("finding certificate: %w", err)
	}

	// Determine algorithm from key type
	algorithm := determineAlgorithm(key)

	return &pkcs11Signer{
		key:       key,
		cert:      cert,
		algorithm: algorithm,
	}, nil
}

// pkcs11Signer implements Signer using a PKCS#11 key
type pkcs11Signer struct {
	key       crypto.Signer
	cert      *x509.Certificate
	algorithm string
}

func (s *pkcs11Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(rand, digest, opts)
}

func (s *pkcs11Signer) Public() crypto.PublicKey {
	return s.key.Public()
}

func (s *pkcs11Signer) Certificate() *x509.Certificate {
	return s.cert
}

func (s *pkcs11Signer) Algorithm() string {
	return s.algorithm
}

func determineAlgorithm(key crypto.Signer) string {
	switch key.Public().(type) {
	case interface {
		Params() interface{ Name() string }
	}:
		// ECDSA
		return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	default:
		// Assume RSA
		return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	}
}
