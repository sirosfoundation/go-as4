// Copyright (c) 2025 SIROS Foundation
// SPDX-License-Identifier: BSD-2-Clause

package msh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/sirosfoundation/go-as4/pkg/message"
	"github.com/sirosfoundation/go-as4/pkg/pmode"
	"github.com/sirosfoundation/go-as4/pkg/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to generate test Ed25519 key pair with certificate
func generateTestKeyPairWithCert(t *testing.T, commonName string) (ed25519.PrivateKey, *x509.Certificate) {
	t.Helper()

	// Generate Ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Create self-signed certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return privKey, cert
}

func TestSecurityProcessor_SignEnvelope(t *testing.T) {
	t.Skip("Ed25519 XML signing deprecated - use RSA signing via RSASigner")
}

func TestSecurityProcessor_EncryptPayloads(t *testing.T) {
	// Generate X25519 keys for encryption
	generator := &security.KeyPairGenerator{}
	recipientPub, _, err := generator.GenerateX25519KeyPair()
	require.NoError(t, err)

	// Create AES encryptor
	encryptor := security.NewAESEncryptor(recipientPub)
	require.NotNil(t, encryptor)

	// Create SecurityProcessor
	secProc := NewSecurityProcessor(nil, encryptor)
	require.NotNil(t, secProc)
	assert.False(t, secProc.HasSigner())
	assert.True(t, secProc.HasEncryptor())

	// Create test payloads
	payloads := []Payload{
		{
			ContentID:   "payload1",
			ContentType: "text/plain",
			Data:        []byte("Sensitive data 1"),
			Properties:  make(map[string]string),
		},
		{
			ContentID:   "payload2",
			ContentType: "application/json",
			Data:        []byte(`{"key": "value"}`),
			Properties:  make(map[string]string),
		},
	}

	// Encrypt payloads
	err = secProc.EncryptPayloads(payloads)
	require.NoError(t, err)

	// Verify encryption metadata is present
	for i, payload := range payloads {
		assert.NotEmpty(t, payload.Properties["EphemeralPublicKey"], "Payload %d missing ephemeral key", i)
		assert.NotEmpty(t, payload.Properties["Nonce"], "Payload %d missing nonce", i)
		assert.Equal(t, "AES-128-GCM", payload.Properties["EncryptionAlgorithm"], "Payload %d", i)
		// Data should be encrypted (different from original)
		assert.NotEqual(t, "Sensitive data 1", string(payload.Data), "Payload should be encrypted")
	}
}

func TestMSH_WithSecurity_SignedMessage(t *testing.T) {
	t.Skip("Ed25519 XML signing deprecated - use RSA signing via RSASigner")
}

func TestMSH_WithSecurity_EncryptedPayloads(t *testing.T) {
	// Generate X25519 keys
	generator := &security.KeyPairGenerator{}
	recipientPub, _, err := generator.GenerateX25519KeyPair()
	require.NoError(t, err)

	// Create AES encryptor
	encryptor := security.NewAESEncryptor(recipientPub)
	require.NotNil(t, encryptor)

	// Create endpoint resolver
	resolver := NewStaticEndpointResolver()
	resolver.RegisterEndpoint("receiver", &EndpointInfo{
		URL:     "http://receiver.example.com/as4",
		PartyID: "receiver",
	})

	// Create P-Mode with encryption configuration
	pm := &pmode.ProcessingMode{
		ID: "test-pmode-encrypted",
		Security: &pmode.Security{
			X509: &pmode.X509Config{
				Encryption: &pmode.EncryptionConfig{
					Algorithm: "http://www.w3.org/2009/xmlenc11#aes128-gcm",
				},
			},
		},
	}

	// Create MSH with encryption
	msh, err := NewMSH(MSHConfig{
		Resolver:      resolver,
		PModeRegistry: map[string]*pmode.ProcessingMode{"test-pmode-encrypted": pm},
		AESEncryptor:  encryptor,
		WorkerCount:   2,
		MaxQueueSize:  10,
	})
	require.NoError(t, err)
	require.NotNil(t, msh.securityProcessor)
	assert.True(t, msh.securityProcessor.HasEncryptor())

	// Start MSH
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = msh.Start(ctx)
	require.NoError(t, err)
	defer msh.Stop()

	// Create test envelope
	env := &message.Envelope{
		Header: &message.Header{
			Messaging: &message.Messaging{
				UserMessage: &message.UserMessage{
					MessageInfo: &message.MessageInfo{
						Timestamp: time.Now(),
						MessageId: "encrypted-msg-integration@test.example.com",
					},
					PartyInfo: &message.PartyInfo{
						From: &message.Party{
							PartyId: []message.PartyId{{Value: "sender"}},
							Role:    "Sender",
						},
						To: &message.Party{
							PartyId: []message.PartyId{{Value: "receiver"}},
							Role:    "Receiver",
						},
					},
					CollaborationInfo: &message.CollaborationInfo{
						Service:        message.Service{Value: "SecureService"},
						Action:         "SecureAction",
						ConversationId: "secure-conv",
					},
				},
			},
		},
		Body: &message.Body{},
	}

	// Create outbound message with payloads
	outMsg := &OutboundMessage{
		MessageID:   "encrypted-msg-integration@test.example.com",
		FromPartyID: "sender",
		ToPartyID:   "receiver",
		Service:     "SecureService",
		Action:      "SecureAction",
		Envelope:    env,
		Payloads: []Payload{
			{
				ContentID:   "payload1",
				ContentType: "text/plain",
				Data:        []byte("Confidential information"),
				Properties:  make(map[string]string),
			},
		},
		PMode: pm,
	}

	// Apply security (encryption)
	err = msh.applyOutboundSecurity(env, outMsg, pm)
	assert.NoError(t, err, "Security application should succeed")

	// Verify payload is encrypted
	assert.NotEmpty(t, outMsg.Payloads[0].Properties["EphemeralPublicKey"])
	assert.NotEmpty(t, outMsg.Payloads[0].Properties["Nonce"])
	assert.NotEqual(t, "Confidential information", string(outMsg.Payloads[0].Data))
}

func TestSecurityProcessor_NoSecurity(t *testing.T) {
	// Create SecurityProcessor with no signer or encryptor
	secProc := NewSecurityProcessor(nil, nil)
	require.NotNil(t, secProc)
	assert.False(t, secProc.HasSigner())
	assert.False(t, secProc.HasEncryptor())

	// Signing should fail
	env := &message.Envelope{
		Header: &message.Header{
			Messaging: &message.Messaging{},
		},
		Body: &message.Body{},
	}

	_, err := secProc.SignEnvelope(env)
	assert.Error(t, err, "Should error when no signer configured")

	// Encryption should succeed (it's a no-op)
	payloads := []Payload{{Data: []byte("test")}}
	err = secProc.EncryptPayloads(payloads)
	assert.NoError(t, err, "Should succeed (no-op) when no encryptor")
}

func TestSecurityProcessor_VerifyEnvelope_NoSigner(t *testing.T) {
	secProc := NewSecurityProcessor(nil, nil)

	err := secProc.VerifyEnvelope([]byte("<test>xml</test>"))
	assert.Error(t, err, "Should error when no signer configured")
	assert.Contains(t, err.Error(), "no signer configured")
}

func TestSecurityProcessor_HasWSSEncryptor(t *testing.T) {
	// Without WSS encryptor
	secProc := NewSecurityProcessor(nil, nil)
	assert.False(t, secProc.HasWSSEncryptor())

	// With WSS encryptor (via NewSecurityProcessorWithWSS)
	privKey, err := security.GenerateX25519KeyPair()
	require.NoError(t, err)
	recipientPub := privKey.PublicKey()

	secProcWSS := NewSecurityProcessorWithWSS(nil, recipientPub, nil)
	assert.True(t, secProcWSS.HasWSSEncryptor())
	assert.False(t, secProcWSS.HasSigner())
}

func TestSecurityProcessor_NewSecurityProcessorWithWSS(t *testing.T) {
	privKey, err := security.GenerateX25519KeyPair()
	require.NoError(t, err)
	recipientPub := privKey.PublicKey()

	// Test with both encryptor and decryptor
	secProc := NewSecurityProcessorWithWSS(nil, recipientPub, privKey)
	require.NotNil(t, secProc)
	assert.True(t, secProc.HasWSSEncryptor())
	assert.True(t, secProc.HasEncryptor())
	assert.False(t, secProc.HasSigner())

	// Test with only decryptor
	secProcDecrypt := NewSecurityProcessorWithWSS(nil, nil, privKey)
	require.NotNil(t, secProcDecrypt)
	assert.False(t, secProcDecrypt.HasWSSEncryptor())

	// Test with only encryptor
	secProcEncrypt := NewSecurityProcessorWithWSS(nil, recipientPub, nil)
	require.NotNil(t, secProcEncrypt)
	assert.True(t, secProcEncrypt.HasWSSEncryptor())
}

func TestSecurityProcessor_DecryptPayloads_NotEncrypted(t *testing.T) {
	secProc := NewSecurityProcessor(nil, nil)

	// Payloads without encryption metadata should be skipped
	payloads := []Payload{
		{
			ContentID:   "test1",
			ContentType: "text/plain",
			Data:        []byte("not encrypted data"),
			Properties:  map[string]string{}, // No encryption metadata
		},
		{
			ContentID:   "test2",
			ContentType: "text/xml",
			Data:        []byte("<xml>also not encrypted</xml>"),
			// nil Properties
		},
	}

	err := secProc.DecryptPayloads(payloads, [32]byte{})
	assert.NoError(t, err)

	// Data should be unchanged
	assert.Equal(t, "not encrypted data", string(payloads[0].Data))
	assert.Equal(t, "<xml>also not encrypted</xml>", string(payloads[1].Data))
}

func TestSecurityProcessor_DecryptPayloads_InvalidMetadata(t *testing.T) {
	secProc := NewSecurityProcessor(nil, nil)

	// Invalid base64 in EphemeralPublicKey
	payloadsInvalidEphem := []Payload{
		{
			ContentID: "test",
			Data:      []byte("data"),
			Properties: map[string]string{
				"EphemeralPublicKey": "not-valid-base64!!!",
				"Nonce":              "dGVzdG5vbmNl", // valid base64
			},
		},
	}

	err := secProc.DecryptPayloads(payloadsInvalidEphem, [32]byte{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode ephemeral public key")

	// Invalid base64 in Nonce
	payloadsInvalidNonce := []Payload{
		{
			ContentID: "test",
			Data:      []byte("data"),
			Properties: map[string]string{
				"EphemeralPublicKey": "dGVzdGtleQ==", // valid base64
				"Nonce":              "not-valid-base64!!!",
			},
		},
	}

	err = secProc.DecryptPayloads(payloadsInvalidNonce, [32]byte{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode nonce")
}

func TestSecurityProcessor_EncryptPayloads_NilProperties(t *testing.T) {
	// Generate X25519 keys for encryption
	generator := &security.KeyPairGenerator{}
	recipientPub, _, err := generator.GenerateX25519KeyPair()
	require.NoError(t, err)

	encryptor := security.NewAESEncryptor(recipientPub)
	secProc := NewSecurityProcessor(nil, encryptor)

	// Payload with nil Properties should get initialized
	payloads := []Payload{
		{
			ContentID:   "test",
			ContentType: "text/plain",
			Data:        []byte("test data"),
			Properties:  nil, // nil Properties
		},
	}

	err = secProc.EncryptPayloads(payloads)
	require.NoError(t, err)

	// Properties should be initialized and contain encryption metadata
	assert.NotNil(t, payloads[0].Properties)
	assert.NotEmpty(t, payloads[0].Properties["EphemeralPublicKey"])
	assert.NotEmpty(t, payloads[0].Properties["Nonce"])
	assert.Equal(t, "AES-128-GCM", payloads[0].Properties["EncryptionAlgorithm"])
}
