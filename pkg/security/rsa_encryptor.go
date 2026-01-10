// Package security implements RSA-OAEP encryption for AS4
package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// RSAEncryptor handles RSA-OAEP key transport with AES-GCM data encryption
type RSAEncryptor struct {
	recipientPublicKey *rsa.PublicKey
	privateKey         *rsa.PrivateKey
	dataAlgorithm      string // AES-128-GCM or AES-256-GCM
}

// NewRSAEncryptor creates a new RSA-based encryptor
func NewRSAEncryptor(recipientCert *x509.Certificate, dataAlgorithm string) (*RSAEncryptor, error) {
	publicKey, ok := recipientCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate does not contain RSA public key")
	}

	if dataAlgorithm == "" {
		dataAlgorithm = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	}

	return &RSAEncryptor{
		recipientPublicKey: publicKey,
		dataAlgorithm:      dataAlgorithm,
	}, nil
}

// NewRSADecryptor creates a new RSA-based decryptor
func NewRSADecryptor(privateKey *rsa.PrivateKey, dataAlgorithm string) (*RSAEncryptor, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}

	if dataAlgorithm == "" {
		dataAlgorithm = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	}

	return &RSAEncryptor{
		privateKey:    privateKey,
		dataAlgorithm: dataAlgorithm,
	}, nil
}

// Encrypt encrypts data using RSA-OAEP for key transport and AES-GCM for data
func (e *RSAEncryptor) Encrypt(plaintext []byte) (ciphertext []byte, encryptedKey []byte, nonce []byte, err error) {
	if e.recipientPublicKey == nil {
		return nil, nil, nil, fmt.Errorf("recipient public key not set")
	}

	// Determine AES key size based on algorithm
	keySize := 16 // AES-128
	if e.dataAlgorithm == "http://www.w3.org/2009/xmlenc11#aes256-gcm" {
		keySize = 32 // AES-256
	}

	// Generate random AES key
	aesKey := make([]byte, keySize)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	// Encrypt the AES key with RSA-OAEP
	encryptedKey, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, e.recipientPublicKey, aesKey, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("RSA-OAEP encryption failed: %w", err)
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data with AES-GCM
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)

	return ciphertext, encryptedKey, nonce, nil
}

// Decrypt decrypts data using RSA-OAEP for key transport and AES-GCM for data
func (e *RSAEncryptor) Decrypt(ciphertext []byte, encryptedKey []byte, nonce []byte) ([]byte, error) {
	if e.privateKey == nil {
		return nil, fmt.Errorf("private key not set")
	}

	// Decrypt the AES key with RSA-OAEP
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, e.privateKey, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP decryption failed: %w", err)
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt data with AES-GCM
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	return plaintext, nil
}

// EncryptPayload encrypts a single payload and returns encryption metadata
func (e *RSAEncryptor) EncryptPayload(data []byte) (encrypted []byte, metadata map[string]string, err error) {
	ciphertext, encryptedKey, nonce, err := e.Encrypt(data)
	if err != nil {
		return nil, nil, err
	}

	metadata = map[string]string{
		"EncryptedKey":        base64.StdEncoding.EncodeToString(encryptedKey),
		"Nonce":               base64.StdEncoding.EncodeToString(nonce),
		"EncryptionAlgorithm": e.dataAlgorithm,
		"KeyAlgorithm":        "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
	}

	return ciphertext, metadata, nil
}

// DecryptPayload decrypts a payload using metadata
func (e *RSAEncryptor) DecryptPayload(encrypted []byte, metadata map[string]string) ([]byte, error) {
	encryptedKeyB64 := metadata["EncryptedKey"]
	nonceB64 := metadata["Nonce"]

	if encryptedKeyB64 == "" || nonceB64 == "" {
		return nil, fmt.Errorf("missing encryption metadata")
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(encryptedKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}

	return e.Decrypt(encrypted, encryptedKey, nonce)
}
