// Package eu_as4_v2 implements EU eDelivery AS4 2.0 Interoperability compliance tests.
//
// These tests validate compliance with the eDelivery AS4 2.0 Common Usage Profile
// as documented at:
// https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/eDelivery+AS4+-+2.0
//
// Test cases based on:
// https://ec.europa.eu/digital-building-blocks/sites/spaces/EDELCOMMUNITY/pages/909706852/eDelivery+AS4+2.0+Interoperability+Event+technical+guidance
//
// Required cryptographic algorithms (Common Usage Profile):
// - Signature algorithm: http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519
// - Digest algorithm: http://www.w3.org/2001/04/xmlenc#sha256
// - Payload encryption: http://www.w3.org/2009/xmlenc11#aes128-gcm
// - Key agreement method: http://www.w3.org/2021/04/xmldsig-more#x25519
// - Key derivation function: http://www.w3.org/2021/04/xmldsig-more#hkdf
// - Key wrapping algorithm: http://www.w3.org/2001/04/xmlenc#kw-aes128
package eu_as4_v2

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/leifj/signedxml/xmlenc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// EU AS4 2.0 Algorithm URIs
const (
	// Signature
	AlgorithmEd25519Signature = "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519"
	AlgorithmSHA256           = "http://www.w3.org/2001/04/xmlenc#sha256"

	// Encryption
	AlgorithmX25519     = "http://www.w3.org/2021/04/xmldsig-more#x25519"
	AlgorithmHKDF       = "http://www.w3.org/2021/04/xmldsig-more#hkdf"
	AlgorithmAES128KW   = "http://www.w3.org/2001/04/xmlenc#kw-aes128"
	AlgorithmAES128GCM  = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	AlgorithmHMACSHA256 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"

	// Alternative Elliptic Curve Cryptography Option (secp256r1)
	AlgorithmECDSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	AlgorithmECDHES      = "http://www.w3.org/2009/xmlenc11#ECDH-ES"
)

// Test P-Mode values from EU interoperability event guidance
const (
	PModeService     = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/service"
	PModeAction      = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/test"
	PModePartyIDType = "urn:oasis:names:tc:ebcore:partyid-type:unregistered"
)

// generateEd25519TestCert creates a self-signed Ed25519 certificate for testing
func generateEd25519TestCert(cn string) (*x509.Certificate, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"EU AS4 2.0 Test"},
			CommonName:   cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

// generateMessageID generates a unique message ID for testing
func generateMessageID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ============================================================================
// TC02 - ENTSOG Sample Message with Single Payload (Signature + Encryption)
// ============================================================================

// TestTC02_EncryptionAlgorithmCompliance verifies X25519+HKDF+AES-128-GCM compliance
func TestTC02_EncryptionAlgorithmCompliance(t *testing.T) {
	// Generate X25519 key pair for recipient
	recipientPrivate, err := xmlenc.GenerateX25519KeyPair()
	require.NoError(t, err)
	recipientPublic := recipientPrivate.PublicKey()

	// Test payload (simulating ENTSOG XML payload)
	payload := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<entsog:Message xmlns:entsog="urn:entsog:communication">
    <entsog:Service>A06</entsog:Service>
    <entsog:Content>Test ENTSOG payload for TC02</entsog:Content>
</entsog:Message>`)

	// Create XML element to encrypt
	doc := etree.NewDocument()
	err = doc.ReadFromBytes(payload)
	require.NoError(t, err)

	// Create HKDF params per EU AS4 2.0
	hkdfParams := &xmlenc.HKDFParams{
		PRF:       AlgorithmHMACSHA256,
		Info:      []byte("EU eDelivery AS4 2.0"),
		KeyLength: 128, // bits for AES-128
	}

	// Create X25519 key agreement
	senderKA, err := xmlenc.NewX25519KeyAgreement(recipientPublic, hkdfParams)
	require.NoError(t, err)

	// Create encryptor with EU AS4 2.0 required algorithms
	encryptor := xmlenc.NewEncryptor(xmlenc.AlgorithmAES128GCM, senderKA)

	// Encrypt the payload
	encData, err := encryptor.EncryptElement(doc.Root())
	require.NoError(t, err)

	// Verify algorithm URIs match EU AS4 2.0 requirements
	assert.Equal(t, xmlenc.AlgorithmAES128GCM, encData.EncryptionMethod.Algorithm,
		"TC02: Content encryption MUST use AES-128-GCM")

	encKey := encData.KeyInfo.EncryptedKey
	assert.Equal(t, xmlenc.AlgorithmAES128KW, encKey.EncryptionMethod.Algorithm,
		"TC02: Key wrapping MUST use AES-128-KW")

	am := encKey.KeyInfo.AgreementMethod
	assert.Equal(t, xmlenc.AlgorithmX25519, am.Algorithm,
		"TC02: Key agreement MUST use X25519")
	assert.NotNil(t, am.KeyDerivationMethod,
		"TC02: KeyDerivationMethod MUST be present")
	assert.Equal(t, xmlenc.AlgorithmHKDF, am.KeyDerivationMethod.Algorithm,
		"TC02: Key derivation MUST use HKDF")

	t.Log("TC02 PASSED: Encryption algorithm compliance verified")
}

// TestTC02_EncryptDecryptRoundTrip tests full encryption/decryption cycle
func TestTC02_EncryptDecryptRoundTrip(t *testing.T) {
	// Generate X25519 key pair for recipient
	recipientPrivate, err := xmlenc.GenerateX25519KeyPair()
	require.NoError(t, err)
	recipientPublic := recipientPrivate.PublicKey()

	// ENTSOG-style payload
	payload := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<entsog:Message xmlns:entsog="urn:entsog:communication">
    <entsog:Service>A06</entsog:Service>
    <entsog:Sender>21Y001100000000B</entsog:Sender>
    <entsog:Receiver>21Y001100000001C</entsog:Receiver>
    <entsog:Content>Confidential gas transmission data</entsog:Content>
</entsog:Message>`)

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(payload))

	// Encrypt
	hkdfParams := xmlenc.DefaultHKDFParams([]byte("EU eDelivery AS4 2.0 TC02"))
	senderKA, err := xmlenc.NewX25519KeyAgreement(recipientPublic, hkdfParams)
	require.NoError(t, err)

	encryptor := xmlenc.NewEncryptor(xmlenc.AlgorithmAES128GCM, senderKA)
	encData, err := encryptor.EncryptElement(doc.Root())
	require.NoError(t, err)

	// Generate XML (for logging/debugging)
	encDoc := xmlenc.NewEncryptedDataDocument(encData)
	encXML, _ := encDoc.WriteToString()
	t.Logf("Encrypted payload (%d bytes)", len(encXML))

	// Verify encrypted data doesn't contain plaintext
	assert.NotContains(t, encXML, "Confidential gas transmission data",
		"TC02: Encrypted data MUST NOT contain plaintext")

	// Decrypt
	ephemeralPubBytes := encData.KeyInfo.EncryptedKey.KeyInfo.AgreementMethod.
		OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey
	ephemeralPublic, err := xmlenc.ParseX25519PublicKey(ephemeralPubBytes)
	require.NoError(t, err)

	recipientKA := xmlenc.NewX25519KeyAgreementForDecrypt(recipientPrivate, ephemeralPublic, hkdfParams)
	decryptor := xmlenc.NewDecryptor(recipientKA)
	decryptedElem, err := decryptor.DecryptElement(encData)
	require.NoError(t, err)

	// Verify decrypted content
	assert.Equal(t, "Message", decryptedElem.Tag)
	contentElem := decryptedElem.FindElement("./Content")
	require.NotNil(t, contentElem)
	assert.Equal(t, "Confidential gas transmission data", contentElem.Text())

	t.Log("TC02 PASSED: Encrypt/decrypt round-trip successful")
}

// ============================================================================
// TC03 - OOTS Sample Message with Two Payloads
// ============================================================================

// TestTC03_MultiPayloadEncryption tests encrypting multiple payloads
func TestTC03_MultiPayloadEncryption(t *testing.T) {
	// Generate X25519 key pair for recipient
	recipientPrivate, err := xmlenc.GenerateX25519KeyPair()
	require.NoError(t, err)
	recipientPublic := recipientPrivate.PublicKey()

	// OOTS payload 1 (XML)
	payload1 := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<oots:QueryResponse xmlns:oots="urn:oasis:names:tc:ebcore:ebrs:ebms:binding:1.0">
    <oots:ResponseID>oots-response-001</oots:ResponseID>
    <oots:Status>Success</oots:Status>
</oots:QueryResponse>`)

	// OOTS payload 2 (binary PDF simulation - use base64 for test)
	payload2 := []byte("Binary PDF content for OOTS document")

	// Encrypt payload 1 (XML)
	doc1 := etree.NewDocument()
	require.NoError(t, doc1.ReadFromBytes(payload1))

	hkdfParams := xmlenc.DefaultHKDFParams([]byte("EU eDelivery AS4 2.0 TC03"))

	senderKA1, err := xmlenc.NewX25519KeyAgreement(recipientPublic, hkdfParams)
	require.NoError(t, err)
	encryptor1 := xmlenc.NewEncryptor(xmlenc.AlgorithmAES128GCM, senderKA1)
	encData1, err := encryptor1.EncryptElement(doc1.Root())
	require.NoError(t, err)

	// Encrypt payload 2 (binary)
	doc2 := etree.NewDocument()
	root2 := doc2.CreateElement("Binary")
	root2.SetText(base64.StdEncoding.EncodeToString(payload2))

	senderKA2, err := xmlenc.NewX25519KeyAgreement(recipientPublic, hkdfParams)
	require.NoError(t, err)
	encryptor2 := xmlenc.NewEncryptor(xmlenc.AlgorithmAES128GCM, senderKA2)
	encData2, err := encryptor2.EncryptElement(root2)
	require.NoError(t, err)

	// Verify both use correct algorithms
	assert.Equal(t, xmlenc.AlgorithmAES128GCM, encData1.EncryptionMethod.Algorithm)
	assert.Equal(t, xmlenc.AlgorithmAES128GCM, encData2.EncryptionMethod.Algorithm)

	// Decrypt payload 1
	ephPub1, _ := xmlenc.ParseX25519PublicKey(
		encData1.KeyInfo.EncryptedKey.KeyInfo.AgreementMethod.OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey)
	decryptKA1 := xmlenc.NewX25519KeyAgreementForDecrypt(recipientPrivate, ephPub1, hkdfParams)
	decryptor1 := xmlenc.NewDecryptor(decryptKA1)
	dec1, err := decryptor1.DecryptElement(encData1)
	require.NoError(t, err)
	assert.Equal(t, "QueryResponse", dec1.Tag)

	// Decrypt payload 2
	ephPub2, _ := xmlenc.ParseX25519PublicKey(
		encData2.KeyInfo.EncryptedKey.KeyInfo.AgreementMethod.OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey)
	decryptKA2 := xmlenc.NewX25519KeyAgreementForDecrypt(recipientPrivate, ephPub2, hkdfParams)
	decryptor2 := xmlenc.NewDecryptor(decryptKA2)
	dec2, err := decryptor2.DecryptElement(encData2)
	require.NoError(t, err)
	decBytes, err := base64.StdEncoding.DecodeString(dec2.Text())
	require.NoError(t, err)
	assert.Equal(t, payload2, decBytes)

	t.Log("TC03 PASSED: Multi-payload encryption/decryption successful")
}

// ============================================================================
// Cryptographic Algorithm Compliance Tests
// ============================================================================

// TestEUAS4v2_SignatureAlgorithms validates signature algorithm URIs
func TestEUAS4v2_SignatureAlgorithms(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected string
		required bool
	}{
		{
			name:     "Ed25519 Signature",
			uri:      AlgorithmEd25519Signature,
			expected: "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519",
			required: true,
		},
		{
			name:     "SHA-256 Digest",
			uri:      AlgorithmSHA256,
			expected: "http://www.w3.org/2001/04/xmlenc#sha256",
			required: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.uri)
			if tc.required {
				t.Logf("REQUIRED for EU AS4 2.0 Common Usage Profile: %s", tc.uri)
			}
		})
	}
}

// TestEUAS4v2_EncryptionAlgorithms validates encryption algorithm URIs
func TestEUAS4v2_EncryptionAlgorithms(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected string
		required bool
	}{
		{
			name:     "X25519 Key Agreement",
			uri:      xmlenc.AlgorithmX25519,
			expected: "http://www.w3.org/2021/04/xmldsig-more#x25519",
			required: true,
		},
		{
			name:     "HKDF Key Derivation",
			uri:      xmlenc.AlgorithmHKDF,
			expected: "http://www.w3.org/2021/04/xmldsig-more#hkdf",
			required: true,
		},
		{
			name:     "AES-128-KW Key Wrapping",
			uri:      xmlenc.AlgorithmAES128KW,
			expected: "http://www.w3.org/2001/04/xmlenc#kw-aes128",
			required: true,
		},
		{
			name:     "AES-128-GCM Content Encryption",
			uri:      xmlenc.AlgorithmAES128GCM,
			expected: "http://www.w3.org/2009/xmlenc11#aes128-gcm",
			required: true,
		},
		{
			name:     "HMAC-SHA256 PRF",
			uri:      xmlenc.AlgorithmHMACSHA256,
			expected: "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
			required: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.uri)
			if tc.required {
				t.Logf("REQUIRED for EU AS4 2.0 Common Usage Profile: %s", tc.uri)
			}
		})
	}
}

// TestEUAS4v2_XMLEncryptionStructure validates XML Encryption 1.1 structure
func TestEUAS4v2_XMLEncryptionStructure(t *testing.T) {
	recipientPrivate, _ := xmlenc.GenerateX25519KeyPair()
	recipientPublic := recipientPrivate.PublicKey()

	// Create test element
	doc := etree.NewDocument()
	root := doc.CreateElement("TestPayload")
	root.SetText("Confidential data")

	// Encrypt
	hkdfParams := xmlenc.DefaultHKDFParams([]byte("EU AS4 2.0"))
	ka, _ := xmlenc.NewX25519KeyAgreement(recipientPublic, hkdfParams)
	encryptor := xmlenc.NewEncryptor(xmlenc.AlgorithmAES128GCM, ka)
	encData, err := encryptor.EncryptElement(root)
	require.NoError(t, err)

	// Convert to XML
	elem := encData.ToElement()
	encDoc := etree.NewDocument()
	encDoc.SetRoot(elem)
	xmlBytes, _ := encDoc.WriteToBytes()
	xmlStr := string(xmlBytes)

	// Validate required XML structure per W3C XML Encryption 1.1
	requiredElements := []string{
		"EncryptedData",
		"EncryptionMethod",
		"KeyInfo",
		"EncryptedKey",
		"AgreementMethod",
		"KeyDerivationMethod",
		"HKDFParams",
		"OriginatorKeyInfo",
		"ECKeyValue",
		"PublicKey",
		"CipherData",
		"CipherValue",
	}

	for _, elem := range requiredElements {
		assert.Contains(t, xmlStr, elem,
			"EU AS4 2.0: XML Encryption structure MUST contain %s", elem)
	}

	// Validate required algorithm URIs in output
	requiredAlgorithms := []string{
		xmlenc.AlgorithmAES128GCM,
		xmlenc.AlgorithmAES128KW,
		xmlenc.AlgorithmX25519,
		xmlenc.AlgorithmHKDF,
	}

	for _, alg := range requiredAlgorithms {
		assert.Contains(t, xmlStr, alg,
			"EU AS4 2.0: XML output MUST contain algorithm URI %s", alg)
	}

	t.Log("EU AS4 2.0 XML Encryption structure validated")
}

// ============================================================================
// Security Error Case Tests
// ============================================================================

// TestEUAS4v2_TamperedCiphertext tests detection of tampered encrypted data
func TestEUAS4v2_TamperedCiphertext(t *testing.T) {
	recipientPrivate, _ := xmlenc.GenerateX25519KeyPair()
	recipientPublic := recipientPrivate.PublicKey()

	doc := etree.NewDocument()
	root := doc.CreateElement("Secret")
	root.SetText("Original data")

	hkdfParams := xmlenc.DefaultHKDFParams([]byte("Tamper test"))
	ka, _ := xmlenc.NewX25519KeyAgreement(recipientPublic, hkdfParams)
	encryptor := xmlenc.NewEncryptor(xmlenc.AlgorithmAES128GCM, ka)
	encData, _ := encryptor.EncryptElement(root)

	// Tamper with ciphertext
	originalCipher := encData.CipherData.CipherValue
	tamperedCipher := make([]byte, len(originalCipher))
	copy(tamperedCipher, originalCipher)
	tamperedCipher[len(tamperedCipher)/2] ^= 0xFF
	encData.CipherData.CipherValue = tamperedCipher

	// Attempt decryption
	ephPub, _ := xmlenc.ParseX25519PublicKey(
		encData.KeyInfo.EncryptedKey.KeyInfo.AgreementMethod.OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey)
	decryptKA := xmlenc.NewX25519KeyAgreementForDecrypt(recipientPrivate, ephPub, hkdfParams)
	decryptor := xmlenc.NewDecryptor(decryptKA)

	_, err := decryptor.DecryptElement(encData)
	assert.Error(t, err, "EU AS4 2.0: Tampered ciphertext MUST be detected by GCM authentication")
	t.Logf("Correctly rejected tampered ciphertext: %v", err)
}

// TestEUAS4v2_WrongRecipientKey tests that wrong key is rejected
func TestEUAS4v2_WrongRecipientKey(t *testing.T) {
	// Correct recipient
	recipientPrivate, _ := xmlenc.GenerateX25519KeyPair()
	recipientPublic := recipientPrivate.PublicKey()

	// Wrong recipient (attacker)
	wrongPrivate, _ := xmlenc.GenerateX25519KeyPair()

	doc := etree.NewDocument()
	root := doc.CreateElement("Secret")
	root.SetText("Confidential")

	hkdfParams := xmlenc.DefaultHKDFParams([]byte("Wrong key test"))
	ka, _ := xmlenc.NewX25519KeyAgreement(recipientPublic, hkdfParams)
	encryptor := xmlenc.NewEncryptor(xmlenc.AlgorithmAES128GCM, ka)
	encData, _ := encryptor.EncryptElement(root)

	// Attempt decryption with wrong key
	ephPub, _ := xmlenc.ParseX25519PublicKey(
		encData.KeyInfo.EncryptedKey.KeyInfo.AgreementMethod.OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey)
	wrongKA := xmlenc.NewX25519KeyAgreementForDecrypt(wrongPrivate, ephPub, hkdfParams)
	decryptor := xmlenc.NewDecryptor(wrongKA)

	_, err := decryptor.DecryptElement(encData)
	assert.Error(t, err, "EU AS4 2.0: Decryption with wrong key MUST fail")
	t.Logf("Correctly rejected wrong key: %v", err)
}
