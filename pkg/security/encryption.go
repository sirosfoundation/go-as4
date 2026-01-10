// Package security implements AES-GCM encryption for AS4 messages
package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// AESEncryptor handles AES-GCM encryption with X25519 key agreement
type AESEncryptor struct {
	privateKey         [32]byte
	recipientPublicKey [32]byte
}

// NewAESEncryptor creates a new AES-GCM encryptor
func NewAESEncryptor(recipientPublicKey [32]byte) *AESEncryptor {
	return &AESEncryptor{
		recipientPublicKey: recipientPublicKey,
	}
}

// NewAESDecryptor creates a new AES-GCM decryptor
func NewAESDecryptor(privateKey [32]byte) *AESEncryptor {
	return &AESEncryptor{
		privateKey: privateKey,
	}
}

// Encrypt encrypts data using X25519 key agreement, HKDF, and AES-128-GCM
func (e *AESEncryptor) Encrypt(plaintext []byte) (ciphertext, ephemeralPublicKey, nonce []byte, err error) {
	// Validate recipient public key
	if err := ValidateX25519PublicKey(&e.recipientPublicKey); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid recipient public key: %w", err)
	}

	// Validate plaintext size
	if err := SanitizeInputSize(plaintext, MaxMessageSize, "plaintext"); err != nil {
		return nil, nil, nil, err
	}

	// Generate ephemeral X25519 key pair
	var ephemeralPrivate [32]byte
	var ephemeralPublic [32]byte

	if _, err := rand.Read(ephemeralPrivate[:]); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	curve25519.ScalarBaseMult(&ephemeralPublic, &ephemeralPrivate)

	// Validate generated ephemeral key
	if err := ValidateX25519PublicKey(&ephemeralPublic); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid generated ephemeral key: %w", err)
	}

	// Perform X25519 key agreement
	var sharedSecret [32]byte
	curve25519.ScalarMult(&sharedSecret, &ephemeralPrivate, &e.recipientPublicKey)

	// Validate shared secret
	if err := ValidateSharedSecret(&sharedSecret); err != nil {
		return nil, nil, nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive encryption key using HKDF-SHA256
	// No salt needed since ephemeral key provides randomness
	var salt []byte = nil

	info := []byte("AS4-AES128-GCM-ENCRYPTION")

	hkdfReader := hkdf.New(sha256.New, sharedSecret[:], salt, info)
	derivedKey := make([]byte, 16) // 128 bits for AES-128
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Validate derived key
	if err := ValidateAESKey(derivedKey); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid derived key: %w", err)
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonceData := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonceData); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Validate nonce
	if err := ValidateNonce(nonceData, aesgcm.NonceSize()); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid nonce: %w", err)
	}

	// Encrypt the data
	ciphertext = aesgcm.Seal(nil, nonceData, plaintext, nil)

	return ciphertext, ephemeralPublic[:], nonceData, nil
}

// Decrypt decrypts data using X25519 key agreement, HKDF, and AES-128-GCM
func (e *AESEncryptor) Decrypt(ciphertext, ephemeralPublicKey, nonce []byte) ([]byte, error) {
	// Validate inputs
	if err := SanitizeInputSize(ciphertext, MaxMessageSize+1024, "ciphertext"); err != nil {
		return nil, err
	}

	if len(ephemeralPublicKey) != 32 {
		return nil, fmt.Errorf("invalid ephemeral public key size: expected 32 bytes, got %d", len(ephemeralPublicKey))
	}

	// Validate ephemeral public key
	var ephemeralPub [32]byte
	copy(ephemeralPub[:], ephemeralPublicKey)

	if err := ValidateX25519PublicKey(&ephemeralPub); err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %w", err)
	}

	// Validate private key
	if err := ValidateX25519PrivateKey(&e.privateKey); err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	// Perform X25519 key agreement using our private key and sender's ephemeral public key
	var sharedSecret [32]byte
	curve25519.ScalarMult(&sharedSecret, &e.privateKey, &ephemeralPub)

	// Validate shared secret
	if err := ValidateSharedSecret(&sharedSecret); err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive decryption key using HKDF-SHA256
	// No salt needed since ephemeral key provides randomness
	var salt []byte = nil

	info := []byte("AS4-AES128-GCM-ENCRYPTION")

	hkdfReader := hkdf.New(sha256.New, sharedSecret[:], salt, info)
	derivedKey := make([]byte, 16) // 128 bits for AES-128
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Validate derived key
	if err := ValidateAESKey(derivedKey); err != nil {
		return nil, fmt.Errorf("invalid derived key: %w", err)
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Validate nonce
	if err := ValidateNonce(nonce, aesgcm.NonceSize()); err != nil {
		return nil, fmt.Errorf("invalid nonce: %w", err)
	}

	// Decrypt the data
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// EncryptPayload encrypts a payload and returns encrypted data with base64-encoded metadata (implements Encryptor interface)
func (e *AESEncryptor) EncryptPayload(data []byte) (encrypted []byte, metadata map[string]string, err error) {
	ciphertext, ephemeralPubKey, nonce, err := e.Encrypt(data)
	if err != nil {
		return nil, nil, err
	}

	metadata = map[string]string{
		"ephemeralPublicKey": base64.StdEncoding.EncodeToString(ephemeralPubKey),
		"nonce":              base64.StdEncoding.EncodeToString(nonce),
		"algorithm":          AlgorithmAES128GCM,
		"keyAgreement":       AlgorithmX25519,
	}

	return ciphertext, metadata, nil
}

// DecryptPayload decrypts a payload using base64-encoded metadata (implements Encryptor interface)
func (e *AESEncryptor) DecryptPayload(encrypted []byte, metadata map[string]string) ([]byte, error) {
	ephemeralPubKey, err := base64.StdEncoding.DecodeString(metadata["ephemeralPublicKey"])
	if err != nil {
		return nil, fmt.Errorf("failed to decode ephemeral public key: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(metadata["nonce"])
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	return e.Decrypt(encrypted, ephemeralPubKey, nonce)
}

// EncryptPayload encrypts a payload and returns encrypted data with metadata
func EncryptPayload(plaintext []byte, recipientPublicKey [32]byte) (*EncryptedPayload, error) {
	encryptor := NewAESEncryptor(recipientPublicKey)

	ciphertext, ephemeralPubKey, nonce, err := encryptor.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}

	return &EncryptedPayload{
		Ciphertext:         base64.StdEncoding.EncodeToString(ciphertext),
		EphemeralPublicKey: base64.StdEncoding.EncodeToString(ephemeralPubKey),
		Nonce:              base64.StdEncoding.EncodeToString(nonce),
		Algorithm:          AlgorithmAES128GCM,
		KeyAgreement:       AlgorithmX25519,
		KeyDerivation:      AlgorithmHKDF,
	}, nil
}

// DecryptPayload decrypts an encrypted payload
func DecryptPayload(encrypted *EncryptedPayload, privateKey [32]byte) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	ephemeralPubKey, err := base64.StdEncoding.DecodeString(encrypted.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ephemeral public key: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(encrypted.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	encryptor := &AESEncryptor{
		privateKey: privateKey,
	}

	return encryptor.Decrypt(ciphertext, ephemeralPubKey, nonce)
}

// EncryptedPayload represents an encrypted payload with metadata
type EncryptedPayload struct {
	Ciphertext         string
	EphemeralPublicKey string
	Nonce              string
	Algorithm          string
	KeyAgreement       string
	KeyDerivation      string
}

// WrapKey wraps a symmetric key using AES Key Wrap (RFC 3394)
func WrapKey(kek, keyToWrap []byte) ([]byte, error) {
	// Validate KEK
	if err := ValidateAESKey(kek); err != nil {
		return nil, fmt.Errorf("invalid KEK: %w", err)
	}

	// Validate key to wrap
	if err := ValidateAESKey(keyToWrap); err != nil {
		return nil, fmt.Errorf("invalid key to wrap: %w", err)
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// AES Key Wrap implementation (RFC 3394)
	n := len(keyToWrap) / 8
	if len(keyToWrap)%8 != 0 {
		return nil, fmt.Errorf("key to wrap must be a multiple of 8 bytes")
	}

	// Initialize variables
	a := uint64(0xA6A6A6A6A6A6A6A6) // Default IV
	r := make([][]byte, n+1)
	r[0] = make([]byte, 8)
	for i := 1; i <= n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], keyToWrap[(i-1)*8:i*8])
	}

	// Calculate intermediate values
	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			// B = AES(K, A | R[i])
			b := make([]byte, 16)
			putUint64(b[0:8], a)
			copy(b[8:16], r[i])

			block.Encrypt(b, b)

			// A = MSB(64, B) ^ t where t = (n*j)+i
			t := uint64(n*j + i)
			a = getUint64(b[0:8]) ^ t

			// R[i] = LSB(64, B)
			copy(r[i], b[8:16])
		}
	}

	// Output the results
	c := make([]byte, (n+1)*8)
	putUint64(c[0:8], a)
	for i := 1; i <= n; i++ {
		copy(c[i*8:(i+1)*8], r[i])
	}

	return c, nil
}

// UnwrapKey unwraps a symmetric key using AES Key Wrap (RFC 3394)
func UnwrapKey(kek, wrappedKey []byte) ([]byte, error) {
	// Validate KEK
	if err := ValidateAESKey(kek); err != nil {
		return nil, fmt.Errorf("invalid KEK: %w", err)
	}

	if len(wrappedKey)%8 != 0 || len(wrappedKey) < 24 {
		return nil, fmt.Errorf("invalid wrapped key size")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	n := (len(wrappedKey) / 8) - 1

	// Initialize variables
	a := getUint64(wrappedKey[0:8])
	r := make([][]byte, n+1)
	r[0] = make([]byte, 8)
	for i := 1; i <= n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], wrappedKey[i*8:(i+1)*8])
	}

	// Calculate intermediate values
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			// B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
			t := uint64(n*j + i)
			b := make([]byte, 16)
			putUint64(b[0:8], a^t)
			copy(b[8:16], r[i])

			block.Decrypt(b, b)

			// A = MSB(64, B)
			a = getUint64(b[0:8])

			// R[i] = LSB(64, B)
			copy(r[i], b[8:16])
		}
	}

	// Check IV
	if a != 0xA6A6A6A6A6A6A6A6 {
		return nil, fmt.Errorf("key unwrap failed: invalid IV")
	}

	// Output the results
	plainKey := make([]byte, n*8)
	for i := 1; i <= n; i++ {
		copy(plainKey[(i-1)*8:i*8], r[i])
	}

	// Validate unwrapped key
	if err := ValidateAESKey(plainKey); err != nil {
		return nil, fmt.Errorf("invalid unwrapped key: %w", err)
	}

	return plainKey, nil
}

// Helper functions for uint64 encoding/decoding
func putUint64(b []byte, v uint64) {
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
}

func getUint64(b []byte) uint64 {
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}

// KeyPairGenerator generates X25519 key pairs
type KeyPairGenerator struct{}

// GenerateX25519KeyPair generates a new X25519 key pair
func (g *KeyPairGenerator) GenerateX25519KeyPair() (publicKey, privateKey [32]byte, err error) {
	if _, err := rand.Read(privateKey[:]); err != nil {
		return [32]byte{}, [32]byte{}, fmt.Errorf("failed to generate private key: %w", err)
	}

	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return publicKey, privateKey, nil
}
