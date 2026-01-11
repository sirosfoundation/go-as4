//go:build !pkcs11

// Package keystore provides a stub for PKCS#11 when not compiled with the pkcs11 tag.
package keystore

import (
	"context"
	"crypto/x509"
	"errors"
)

// PKCS11Provider is a stub that returns an error when PKCS#11 support is not compiled in.
type PKCS11Provider struct{}

// PKCS11Config holds configuration for the PKCS#11 provider
type PKCS11Config struct {
	ModulePath      string
	SlotID          *uint
	SlotLabel       string
	PIN             string
	KeyLabelPattern string
}

// ErrPKCS11NotSupported is returned when PKCS#11 operations are attempted
// but the binary was not compiled with PKCS#11 support.
var ErrPKCS11NotSupported = errors.New("PKCS#11 support not compiled in (build with -tags pkcs11)")

// NewPKCS11Provider returns an error because PKCS#11 is not compiled in.
func NewPKCS11Provider(cfg *PKCS11Config) (*PKCS11Provider, error) {
	return nil, ErrPKCS11NotSupported
}

// GetSigner returns an error because PKCS#11 is not compiled in.
func (p *PKCS11Provider) GetSigner(ctx context.Context, tenantID, keyID string) (Signer, error) {
	return nil, ErrPKCS11NotSupported
}

// GetCertificate returns an error because PKCS#11 is not compiled in.
func (p *PKCS11Provider) GetCertificate(ctx context.Context, tenantID, keyID string) (*x509.Certificate, error) {
	return nil, ErrPKCS11NotSupported
}

// ListKeys returns an error because PKCS#11 is not compiled in.
func (p *PKCS11Provider) ListKeys(ctx context.Context, tenantID string) ([]KeyInfo, error) {
	return nil, ErrPKCS11NotSupported
}

// Close is a no-op.
func (p *PKCS11Provider) Close() error {
	return nil
}
