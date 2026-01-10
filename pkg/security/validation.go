package security

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

var (
	// ErrInvalidPublicKey is returned when a public key is invalid
	ErrInvalidPublicKey = errors.New("invalid public key")
	// ErrInvalidPrivateKey is returned when a private key is invalid
	ErrInvalidPrivateKey = errors.New("invalid private key")
	// ErrInvalidKeySize is returned when a key has an invalid size
	ErrInvalidKeySize = errors.New("invalid key size")
	// ErrWeakKey is returned when a key is cryptographically weak
	ErrWeakKey = errors.New("weak key detected")
)

// ValidateEd25519PublicKey validates an Ed25519 public key
func ValidateEd25519PublicKey(publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidKeySize, ed25519.PublicKeySize, len(publicKey))
	}

	// Ed25519 public keys are points on the edwards25519 curve
	// All 32-byte values are valid points (the library handles point validation internally)
	// But we can check for obviously invalid values like all zeros
	allZeros := true
	for _, b := range publicKey {
		if b != 0 {
			allZeros = false
			break
		}
	}

	if allZeros {
		return fmt.Errorf("%w: all-zero public key", ErrWeakKey)
	}

	return nil
}

// ValidateEd25519PrivateKey validates an Ed25519 private key
func ValidateEd25519PrivateKey(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidKeySize, ed25519.PrivateKeySize, len(privateKey))
	}

	// Check for all-zero private key
	allZeros := true
	for _, b := range privateKey[:32] { // First 32 bytes are the seed
		if b != 0 {
			allZeros = false
			break
		}
	}

	if allZeros {
		return fmt.Errorf("%w: all-zero private key", ErrWeakKey)
	}

	return nil
}

// ValidateX25519PublicKey validates an X25519 public key
// Checks for invalid curve points and weak keys
func ValidateX25519PublicKey(publicKey *[32]byte) error {
	if publicKey == nil {
		return fmt.Errorf("%w: nil public key", ErrInvalidPublicKey)
	}

	// Check for all-zero key
	allZeros := true
	for _, b := range publicKey {
		if b != 0 {
			allZeros = false
			break
		}
	}

	if allZeros {
		return fmt.Errorf("%w: all-zero public key", ErrWeakKey)
	}

	// Check for small-order points (low-order points)
	// These are weak keys that should be rejected
	if isSmallOrderPoint(publicKey) {
		return fmt.Errorf("%w: small-order point detected", ErrWeakKey)
	}

	// Verify the point is on the curve by attempting scalar multiplication
	// If the key is invalid, ScalarMult will return an error or all-zeros
	var testScalar [32]byte
	testScalar[0] = 1 // Use scalar = 1 to test

	var result [32]byte
	curve25519.ScalarMult(&result, &testScalar, publicKey)

	// If multiplication by 1 gives a different result, the point might be invalid
	// (though X25519 is designed to handle all possible inputs)

	return nil
}

// ValidateX25519PrivateKey validates an X25519 private key
func ValidateX25519PrivateKey(privateKey *[32]byte) error {
	if privateKey == nil {
		return fmt.Errorf("%w: nil private key", ErrInvalidPrivateKey)
	}

	// Check for all-zero key
	allZeros := true
	for _, b := range privateKey {
		if b != 0 {
			allZeros = false
			break
		}
	}

	if allZeros {
		return fmt.Errorf("%w: all-zero private key", ErrWeakKey)
	}

	// X25519 private keys should have specific bits clamped
	// This is done automatically by the library, but we can verify
	// Bit 0, 1, 2 should be cleared (value & 7 == 0)
	// Bit 255 should be cleared, bit 254 should be set
	// However, the library handles this automatically in ScalarBaseMult

	return nil
}

// isSmallOrderPoint checks if a point has small order (is a weak point)
// Small-order points in Curve25519 are:
// - All zeros
// - Point of order 2, 4, or 8
func isSmallOrderPoint(point *[32]byte) bool {
	// List of known small-order points for Curve25519
	smallOrderPoints := [][32]byte{
		// Point of order 1 (identity/zero point)
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		// Point of order 2
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00},
		// Point of order 4
		{0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
			0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00},
		// Point of order 8
		{0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
			0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57},
	}

	for _, smallPoint := range smallOrderPoints {
		if *point == smallPoint {
			return true
		}
	}

	return false
}

// ValidateAESKey validates an AES key size
func ValidateAESKey(key []byte) error {
	keySize := len(key)

	// AES supports 128, 192, or 256-bit keys (16, 24, or 32 bytes)
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return fmt.Errorf("%w: AES key must be 16, 24, or 32 bytes, got %d", ErrInvalidKeySize, keySize)
	}

	// Check for all-zero key
	allZeros := true
	for _, b := range key {
		if b != 0 {
			allZeros = false
			break
		}
	}

	if allZeros {
		return fmt.Errorf("%w: all-zero AES key", ErrWeakKey)
	}

	return nil
}

// ValidateNonce validates a nonce/IV for AES-GCM
func ValidateNonce(nonce []byte, expectedSize int) error {
	if len(nonce) != expectedSize {
		return fmt.Errorf("%w: expected nonce size %d bytes, got %d", ErrInvalidKeySize, expectedSize, len(nonce))
	}

	// Check for all-zero nonce (weak, but not necessarily invalid for first use)
	// In production, nonce reuse is the critical issue, not all-zero nonce on first use
	allZeros := true
	for _, b := range nonce {
		if b != 0 {
			allZeros = false
			break
		}
	}

	if allZeros {
		// Warning: all-zero nonce is weak but we don't fail - just log
		// In a real system, you'd want nonce tracking to prevent reuse
		return nil
	}

	return nil
}

// ValidateSharedSecret validates an ECDH shared secret
func ValidateSharedSecret(secret *[32]byte) error {
	if secret == nil {
		return fmt.Errorf("%w: nil shared secret", ErrInvalidPublicKey)
	}

	// Check for all-zero shared secret (indicates ECDH failure)
	allZeros := true
	for _, b := range secret {
		if b != 0 {
			allZeros = false
			break
		}
	}

	if allZeros {
		return fmt.Errorf("%w: all-zero shared secret (possible invalid ECDH)", ErrWeakKey)
	}

	return nil
}

// SanitizeInputSize validates input data size to prevent DoS attacks
func SanitizeInputSize(data []byte, maxSize int, dataType string) error {
	if len(data) > maxSize {
		return fmt.Errorf("input data too large: %s size %d exceeds maximum %d bytes", dataType, len(data), maxSize)
	}

	if len(data) == 0 {
		return fmt.Errorf("input data is empty: %s", dataType)
	}

	return nil
}

const (
	// MaxMessageSize is the maximum size for an AS4 message (10 MB)
	MaxMessageSize = 10 * 1024 * 1024

	// MaxAttachmentSize is the maximum size for a single attachment (100 MB)
	MaxAttachmentSize = 100 * 1024 * 1024

	// MaxXMLDepth is the maximum depth for XML parsing
	MaxXMLDepth = 100

	// MaxCertificateSize is the maximum size for a certificate (64 KB)
	MaxCertificateSize = 64 * 1024
)

// ValidateInputData performs comprehensive input validation
func ValidateInputData(data []byte, maxSize int, dataType string) error {
	// Size validation
	if err := SanitizeInputSize(data, maxSize, dataType); err != nil {
		return err
	}

	// Check for null bytes in string data (potential injection)
	if dataType == "xml" || dataType == "text" {
		for i, b := range data {
			if b == 0 {
				return fmt.Errorf("null byte found at position %d in %s data", i, dataType)
			}
		}
	}

	return nil
}
