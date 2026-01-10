package security

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAESEncryptor_EncryptDecrypt(t *testing.T) {
	// Generate X25519 key pair for recipient
	generator := &KeyPairGenerator{}
	recipientPublic, recipientPrivate, err := generator.GenerateX25519KeyPair()
	require.NoError(t, err)

	// Create encryptor
	encryptor := NewAESEncryptor(recipientPublic)
	require.NotNil(t, encryptor)

	// Test data
	plaintext := []byte("This is secret data that needs to be encrypted")

	// Encrypt
	ciphertext, ephemeralPubKey, nonce, err := encryptor.Encrypt(plaintext)
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)
	assert.NotEmpty(t, ephemeralPubKey)
	assert.NotEmpty(t, nonce)
	assert.NotEqual(t, plaintext, ciphertext)

	// Decrypt
	decryptor := &AESEncryptor{
		privateKey: recipientPrivate,
	}
	decrypted, err := decryptor.Decrypt(ciphertext, ephemeralPubKey, nonce)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestEncryptDecryptPayload(t *testing.T) {
	// Generate X25519 key pair
	generator := &KeyPairGenerator{}
	publicKey, privateKey, err := generator.GenerateX25519KeyPair()
	require.NoError(t, err)

	// Test data
	plaintext := []byte("Sensitive payload data")

	// Encrypt
	encrypted, err := EncryptPayload(plaintext, publicKey)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted.Ciphertext)
	assert.NotEmpty(t, encrypted.EphemeralPublicKey)
	assert.NotEmpty(t, encrypted.Nonce)
	assert.Equal(t, AlgorithmAES128GCM, encrypted.Algorithm)
	assert.Equal(t, AlgorithmX25519, encrypted.KeyAgreement)
	assert.Equal(t, AlgorithmHKDF, encrypted.KeyDerivation)

	// Decrypt
	decrypted, err := DecryptPayload(encrypted, privateKey)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestWrapUnwrapKey(t *testing.T) {
	// Key Encryption Key (KEK) - 128 bits
	// Use a fixed key for reproducible testing
	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	}

	// Key to wrap - must be multiple of 8 bytes
	keyToWrap := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
	}

	// Wrap key
	wrappedKey, err := WrapKey(kek, keyToWrap)
	require.NoError(t, err)
	assert.NotEmpty(t, wrappedKey)
	assert.NotEqual(t, keyToWrap, wrappedKey)
	assert.Equal(t, len(keyToWrap)+8, len(wrappedKey)) // Wrapped key is 8 bytes longer

	// Unwrap key
	unwrappedKey, err := UnwrapKey(kek, wrappedKey)
	require.NoError(t, err)
	t.Logf("Original key:   %x", keyToWrap)
	t.Logf("Unwrapped key:  %x", unwrappedKey)
	assert.Equal(t, keyToWrap, unwrappedKey, "Unwrapped key should match original key")
}

func TestWrapKey_InvalidKeySize(t *testing.T) {
	// Invalid KEK size
	invalidKEK := make([]byte, 15) // Not 16, 24, or 32
	keyToWrap := make([]byte, 16)

	_, err := WrapKey(invalidKEK, keyToWrap)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid KEK")
}

func TestWrapKey_InvalidKeyToWrapSize(t *testing.T) {
	kek := make([]byte, 16)
	rand.Read(kek)

	// Key to wrap not multiple of 8
	invalidKey := make([]byte, 15)

	_, err := WrapKey(kek, invalidKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key to wrap")
}

func TestUnwrapKey_InvalidWrappedKey(t *testing.T) {
	kek := make([]byte, 16)
	rand.Read(kek)

	// Invalid wrapped key (wrong size)
	invalidWrapped := make([]byte, 15)

	_, err := UnwrapKey(kek, invalidWrapped)
	assert.Error(t, err)
}

func TestKeyPairGenerator_GenerateX25519KeyPair(t *testing.T) {
	generator := &KeyPairGenerator{}

	pub, priv, err := generator.GenerateX25519KeyPair()
	require.NoError(t, err)
	assert.NotEqual(t, [32]byte{}, pub)
	assert.NotEqual(t, [32]byte{}, priv)

	// Generate another pair - should be different
	pub2, priv2, err := generator.GenerateX25519KeyPair()
	require.NoError(t, err)
	assert.NotEqual(t, pub, pub2)
	assert.NotEqual(t, priv, priv2)
}

func TestNewXMLSigner_ReturnsError(t *testing.T) {
	// NewXMLSigner for Ed25519 requires valid key and certificate
	_, err := NewXMLSigner(nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "private key is required")
}
