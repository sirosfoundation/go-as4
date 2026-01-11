// Package keystore provides the factory for creating signer providers
package keystore

import (
	"fmt"

	"github.com/sirosfoundation/go-as4/internal/config"
)

// NewProvider creates a SignerProvider based on the configuration
func NewProvider(cfg *config.SigningConfig, store EncryptedKeyStore) (SignerProvider, error) {
	switch cfg.Mode {
	case "pkcs11":
		return newPKCS11Provider(cfg)
	case "prf":
		return newPRFProvider(cfg, store)
	case "file":
		return newFileProvider(cfg)
	default:
		return nil, fmt.Errorf("unknown signing mode: %s", cfg.Mode)
	}
}

func newPKCS11Provider(cfg *config.SigningConfig) (SignerProvider, error) {
	p11cfg := &PKCS11Config{
		ModulePath:      cfg.PKCS11.ModulePath,
		SlotLabel:       cfg.PKCS11.SlotLabel,
		PIN:             cfg.PKCS11.PIN,
		KeyLabelPattern: cfg.PKCS11.KeyLabelPattern,
	}
	if cfg.PKCS11.SlotID > 0 {
		slotID := cfg.PKCS11.SlotID
		p11cfg.SlotID = &slotID
	}
	return NewPKCS11Provider(p11cfg)
}

func newPRFProvider(cfg *config.SigningConfig, store EncryptedKeyStore) (SignerProvider, error) {
	if store == nil {
		return nil, fmt.Errorf("encrypted key store is required for PRF mode")
	}
	return NewPRFProvider(&PRFProviderConfig{
		Store:   store,
		KeyTTL:  cfg.Session.KeyTTL,
		MaxKeys: cfg.Session.MaxKeys,
	})
}

func newFileProvider(cfg *config.SigningConfig) (SignerProvider, error) {
	keyDir := cfg.File.KeyDir
	if keyDir == "" {
		keyDir = "./keys"
	}
	return NewFileProvider(keyDir)
}
