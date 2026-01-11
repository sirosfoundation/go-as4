// Package keystore provides the file-based signer implementation
package keystore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// FileProvider implements SignerProvider using PEM files on disk
//
// This is intended for development and testing only. In production,
// use PKCS#11 or PRF-based key storage.
//
// Key files are expected at: {keyDir}/{tenantID}/{keyID}.key
// Certificate files at: {keyDir}/{tenantID}/{keyID}.crt
type FileProvider struct {
	keyDir  string
	mu      sync.RWMutex
	signers map[string]*fileSigner
}

// NewFileProvider creates a new file-based signer provider
func NewFileProvider(keyDir string) (*FileProvider, error) {
	info, err := os.Stat(keyDir)
	if err != nil {
		return nil, fmt.Errorf("checking key directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("key directory is not a directory: %s", keyDir)
	}

	return &FileProvider{
		keyDir:  keyDir,
		signers: make(map[string]*fileSigner),
	}, nil
}

// GetSigner returns a signer for the specified tenant and key ID
func (p *FileProvider) GetSigner(ctx context.Context, tenantID, keyID string) (Signer, error) {
	cacheKey := tenantID + ":" + keyID

	// Check cache first
	p.mu.RLock()
	if signer, ok := p.signers[cacheKey]; ok {
		p.mu.RUnlock()
		return signer, nil
	}
	p.mu.RUnlock()

	// Load from disk
	signer, err := p.loadSigner(tenantID, keyID)
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
func (p *FileProvider) GetCertificate(ctx context.Context, tenantID, keyID string) (*x509.Certificate, error) {
	certPath := filepath.Join(p.keyDir, tenantID, keyID+".crt")
	return loadCertificate(certPath)
}

// ListKeys returns all key IDs for a tenant
func (p *FileProvider) ListKeys(ctx context.Context, tenantID string) ([]KeyInfo, error) {
	tenantDir := filepath.Join(p.keyDir, tenantID)
	entries, err := os.ReadDir(tenantDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading tenant directory: %w", err)
	}

	var keys []KeyInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.Ext(name) != ".key" {
			continue
		}
		keyID := name[:len(name)-4] // Remove .key extension

		// Try to load the certificate for metadata
		certPath := filepath.Join(tenantDir, keyID+".crt")
		cert, err := loadCertificate(certPath)
		if err != nil {
			continue // Skip keys without certificates
		}

		keys = append(keys, KeyInfo{
			KeyID:              keyID,
			Label:              keyID,
			Algorithm:          keyAlgorithmName(cert.PublicKey),
			KeySize:            keySize(cert.PublicKey),
			NotBefore:          cert.NotBefore,
			NotAfter:           cert.NotAfter,
			CertificateSubject: cert.Subject.String(),
		})
	}

	return keys, nil
}

// Close releases resources
func (p *FileProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.signers = make(map[string]*fileSigner)
	return nil
}

func (p *FileProvider) loadSigner(tenantID, keyID string) (*fileSigner, error) {
	keyPath := filepath.Join(p.keyDir, tenantID, keyID+".key")
	certPath := filepath.Join(p.keyDir, tenantID, keyID+".crt")

	// Load private key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrKeyNotFound
		}
		return nil, fmt.Errorf("reading key file: %w", err)
	}

	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	// Load certificate
	cert, err := loadCertificate(certPath)
	if err != nil {
		return nil, fmt.Errorf("loading certificate: %w", err)
	}

	algorithm := determineAlgorithmFromKey(key)

	return &fileSigner{
		key:       key,
		cert:      cert,
		algorithm: algorithm,
	}, nil
}

// fileSigner implements Signer for file-based keys
type fileSigner struct {
	key       crypto.Signer
	cert      *x509.Certificate
	algorithm string
}

func (s *fileSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(rand, digest, opts)
}

func (s *fileSigner) Public() crypto.PublicKey {
	return s.key.Public()
}

func (s *fileSigner) Certificate() *x509.Certificate {
	return s.cert
}

func (s *fileSigner) Algorithm() string {
	return s.algorithm
}

func parsePrivateKey(pemData []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("key is not a signer")
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}

func loadCertificate(path string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading certificate file: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	return x509.ParseCertificate(block.Bytes)
}

func determineAlgorithmFromKey(key crypto.Signer) string {
	switch key.(type) {
	case *ecdsa.PrivateKey:
		return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	case *rsa.PrivateKey:
		return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	default:
		return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	}
}

func keyAlgorithmName(pub crypto.PublicKey) string {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		return "EC"
	case *rsa.PublicKey:
		return "RSA"
	default:
		return "Unknown"
	}
}

func keySize(pub crypto.PublicKey) int {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	case *rsa.PublicKey:
		return k.N.BitLen()
	default:
		return 0
	}
}
