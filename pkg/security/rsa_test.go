package security

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateRSATestCert generates a test RSA certificate
func generateRSATestCert(t *testing.T, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Organization"},
			CommonName:   "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

func TestRSASigner_SignAndVerifyEnvelope(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	publicKey := &privateKey.PublicKey

	// Generate test certificate
	cert := generateRSATestCert(t, publicKey, privateKey)

	// Create RSA signer with SHA-256
	signer, err := NewRSASigner(privateKey, cert, crypto.SHA256)
	require.NoError(t, err)
	require.NotNil(t, signer)

	// Test SOAP envelope
	envelopeXML := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
    <soap:Header>
    </soap:Header>
    <soap:Body>
        <eb:Messaging>
            <eb:UserMessage>
                <eb:MessageInfo>
                    <eb:MessageId>test-message-123</eb:MessageId>
                    <eb:Timestamp>2024-01-01T00:00:00Z</eb:Timestamp>
                </eb:MessageInfo>
            </eb:UserMessage>
        </eb:Messaging>
    </soap:Body>
</soap:Envelope>`)

	// Sign the envelope
	signedXML, err := signer.SignEnvelope(envelopeXML)
	require.NoError(t, err)
	assert.NotEmpty(t, signedXML)

	// Verify signed XML contains signature elements
	signedStr := string(signedXML)
	assert.Contains(t, signedStr, "Signature")
	assert.Contains(t, signedStr, "SignatureValue")
	assert.Contains(t, signedStr, "BinarySecurityToken")
	assert.Contains(t, signedStr, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")

	// Verify the signature
	err = signer.VerifyEnvelope(signedXML)
	require.NoError(t, err, "Signature verification should succeed")
}

func TestRSASigner_DifferentHashAlgorithms(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cert := generateRSATestCert(t, &privateKey.PublicKey, privateKey)

	envelopeXML := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
    <soap:Header></soap:Header>
    <soap:Body><test>Test</test></soap:Body>
</soap:Envelope>`)

	testCases := []struct {
		name     string
		hashAlgo crypto.Hash
		algoURI  string
	}{
		{"SHA-256", crypto.SHA256, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"},
		{"SHA-384", crypto.SHA384, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"},
		{"SHA-512", crypto.SHA512, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := NewRSASigner(privateKey, cert, tc.hashAlgo)
			require.NoError(t, err)

			signedXML, err := signer.SignEnvelope(envelopeXML)
			require.NoError(t, err)
			assert.Contains(t, string(signedXML), tc.algoURI)

			err = signer.VerifyEnvelope(signedXML)
			require.NoError(t, err)
		})
	}
}

func TestRSAEncryptor_EncryptDecrypt(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cert := generateRSATestCert(t, &privateKey.PublicKey, privateKey)

	// Test data
	plaintext := []byte("Sensitive data to encrypt with RSA-OAEP and AES-GCM")

	// Test AES-128-GCM
	t.Run("AES-128-GCM", func(t *testing.T) {
		// Create encryptor
		encryptor, err := NewRSAEncryptor(cert, AlgorithmAES128GCM)
		require.NoError(t, err)

		// Encrypt
		encrypted, metadata, err := encryptor.EncryptPayload(plaintext)
		require.NoError(t, err)
		assert.NotEmpty(t, encrypted)
		assert.NotEmpty(t, metadata)
		assert.Contains(t, metadata, "EncryptedKey")
		assert.Contains(t, metadata, "Nonce")

		// Create decryptor
		decryptor, err := NewRSADecryptor(privateKey, AlgorithmAES128GCM)
		require.NoError(t, err)

		// Decrypt
		decrypted, err := decryptor.DecryptPayload(encrypted, metadata)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	// Test AES-256-GCM
	t.Run("AES-256-GCM", func(t *testing.T) {
		encryptor, err := NewRSAEncryptor(cert, AlgorithmAES256GCM)
		require.NoError(t, err)

		encrypted, metadata, err := encryptor.EncryptPayload(plaintext)
		require.NoError(t, err)

		decryptor, err := NewRSADecryptor(privateKey, AlgorithmAES256GCM)
		require.NoError(t, err)

		decrypted, err := decryptor.DecryptPayload(encrypted, metadata)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})
}

func TestRSAEncryptor_InvalidKeySize(t *testing.T) {
	// Generate a small RSA key (too small for OAEP)
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	cert := generateRSATestCert(t, &privateKey.PublicKey, privateKey)

	encryptor, err := NewRSAEncryptor(cert, AlgorithmAES256GCM)
	require.NoError(t, err)

	// Try to encrypt - should succeed with small data
	plaintext := []byte("test")
	encrypted, metadata, err := encryptor.EncryptPayload(plaintext)
	require.NoError(t, err)

	// Verify decryption works
	decryptor, err := NewRSADecryptor(privateKey, AlgorithmAES256GCM)
	require.NoError(t, err)

	decrypted, err := decryptor.DecryptPayload(encrypted, metadata)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestRSASigner_SignEnvelopeWithAttachments(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cert := generateRSATestCert(t, &privateKey.PublicKey, privateKey)

	// Create RSA signer
	signer, err := NewRSASigner(privateKey, cert, crypto.SHA256)
	require.NoError(t, err)

	// Test SOAP envelope
	envelopeXML := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
    <soap:Header></soap:Header>
    <soap:Body>
        <eb:Messaging xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
            <eb:UserMessage>
                <eb:MessageInfo>
                    <eb:MessageId>test-msg-123</eb:MessageId>
                </eb:MessageInfo>
            </eb:UserMessage>
        </eb:Messaging>
    </soap:Body>
</soap:Envelope>`)

	// Create test attachments
	attachments := []Attachment{
		{
			ContentID:   "<payload-1@as4.siros.org>",
			ContentType: "application/xml",
			Data:        []byte("<Document>Attachment 1 content</Document>"),
		},
		{
			ContentID:   "<payload-2@as4.siros.org>",
			ContentType: "application/pdf",
			Data:        []byte("PDF binary data here..."),
		},
	}

	// Sign envelope with attachments
	signedXML, err := signer.SignEnvelopeWithAttachments(envelopeXML, attachments)
	require.NoError(t, err)
	assert.NotEmpty(t, signedXML)

	// Verify signed XML contains signature elements
	signedStr := string(signedXML)
	assert.Contains(t, signedStr, "Signature")
	assert.Contains(t, signedStr, "SignatureValue")
	assert.Contains(t, signedStr, "BinarySecurityToken")

	// Verify attachment references are present
	assert.Contains(t, signedStr, "cid:payload-1@as4.siros.org")
	assert.Contains(t, signedStr, "cid:payload-2@as4.siros.org")
	assert.Contains(t, signedStr, "Attachment-Content-Signature-Transform")

	// Verify the signature (basic verification)
	err = signer.VerifyEnvelopeWithAttachments(signedXML, attachments)
	require.NoError(t, err, "Signature verification should succeed")
}
