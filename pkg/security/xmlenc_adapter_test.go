package security

import (
	"testing"

	"github.com/beevik/etree"
	"github.com/leifj/signedxml/xmlenc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestX25519Encryptor_EncryptElement(t *testing.T) {
	// Generate key pair
	privateKey, err := GenerateX25519KeyPair()
	require.NoError(t, err)
	publicKey := privateKey.PublicKey()

	// Create test element
	doc := etree.NewDocument()
	root := doc.CreateElement("Secret")
	root.SetText("This is confidential data")

	// Encrypt
	encryptor := NewX25519Encryptor(publicKey, []byte("Test HKDF Info"))
	encData, err := encryptor.EncryptElement(root)
	require.NoError(t, err)

	// Verify algorithm URIs
	assert.Equal(t, xmlenc.AlgorithmAES128GCM, encData.EncryptionMethod.Algorithm)
	assert.NotNil(t, encData.KeyInfo)
	assert.NotNil(t, encData.KeyInfo.EncryptedKey)

	// Decrypt
	decryptor := NewX25519Decryptor(privateKey, []byte("Test HKDF Info"))
	decrypted, err := decryptor.DecryptElement(encData)
	require.NoError(t, err)

	assert.Equal(t, "Secret", decrypted.Tag)
	assert.Equal(t, "This is confidential data", decrypted.Text())
}

func TestX25519Encryptor_EncryptBytes(t *testing.T) {
	// Generate key pair
	privateKey, err := GenerateX25519KeyPair()
	require.NoError(t, err)
	publicKey := privateKey.PublicKey()

	// Test data
	plaintext := []byte("Binary payload data for AS4 attachment")

	// Encrypt
	encryptor := NewX25519Encryptor(publicKey, nil) // Use default HKDF info
	encData, err := encryptor.EncryptBytes(plaintext)
	require.NoError(t, err)

	// Decrypt
	decryptor := NewX25519Decryptor(privateKey, nil) // Use default HKDF info
	decrypted, err := decryptor.DecryptBytes(encData)
	require.NoError(t, err)

	assert.Equal(t, plaintext, decrypted)
}

func TestAS4PayloadEncryptorDecryptor(t *testing.T) {
	// Generate key pair
	privateKey, err := GenerateX25519KeyPair()
	require.NoError(t, err)
	publicKey := privateKey.PublicKey()

	// Test payload
	payload := []byte("AS4 message payload")

	// Encrypt using AS4-specific API
	encryptor := NewAS4PayloadEncryptor(publicKey, []byte("EU eDelivery AS4 2.0"))
	encData, err := encryptor.EncryptPayload(payload)
	require.NoError(t, err)

	// Decrypt using AS4-specific API
	decryptor := NewAS4PayloadDecryptor(privateKey, []byte("EU eDelivery AS4 2.0"))
	decrypted, err := decryptor.DecryptPayload(encData)
	require.NoError(t, err)

	assert.Equal(t, payload, decrypted)
}

func TestEncryptedDataXMLRoundTrip(t *testing.T) {
	// Generate key pair
	privateKey, err := GenerateX25519KeyPair()
	require.NoError(t, err)
	publicKey := privateKey.PublicKey()

	// Create and encrypt
	doc := etree.NewDocument()
	root := doc.CreateElement("TestData")
	root.SetText("Round trip test")

	encryptor := NewX25519Encryptor(publicKey, nil)
	encData, err := encryptor.EncryptElement(root)
	require.NoError(t, err)

	// Convert to XML
	elem := EncryptedDataToXML(encData)
	xmlDoc := CreateEncryptedDataDocument(encData)
	xmlBytes, err := xmlDoc.WriteToBytes()
	require.NoError(t, err)

	t.Logf("Encrypted XML (%d bytes)", len(xmlBytes))

	// Verify XML structure contains required elements
	xmlStr := string(xmlBytes)
	assert.Contains(t, xmlStr, "EncryptedData")
	assert.Contains(t, xmlStr, "EncryptionMethod")
	assert.Contains(t, xmlStr, "KeyInfo")
	assert.Contains(t, xmlStr, "EncryptedKey")
	assert.Contains(t, xmlStr, "AgreementMethod")
	assert.Contains(t, xmlStr, xmlenc.AlgorithmX25519)
	assert.Contains(t, xmlStr, xmlenc.AlgorithmHKDF)
	assert.Contains(t, xmlStr, xmlenc.AlgorithmAES128KW)
	assert.Contains(t, xmlStr, xmlenc.AlgorithmAES128GCM)

	// Parse back from XML
	parsedDoc := etree.NewDocument()
	err = parsedDoc.ReadFromBytes(xmlBytes)
	require.NoError(t, err)

	parsedEncData, err := ParseEncryptedDataFromXML(parsedDoc.Root())
	require.NoError(t, err)

	// Decrypt parsed data
	decryptor := NewX25519Decryptor(privateKey, nil)
	decrypted, err := decryptor.DecryptElement(parsedEncData)
	require.NoError(t, err)

	assert.Equal(t, "TestData", decrypted.Tag)
	assert.Equal(t, "Round trip test", decrypted.Text())

	// Verify element is the same
	assert.NotNil(t, elem) // Just verify it was created
}

func TestGenerateX25519KeyPair_Unique(t *testing.T) {
	key1, err := GenerateX25519KeyPair()
	require.NoError(t, err)

	key2, err := GenerateX25519KeyPair()
	require.NoError(t, err)

	// Keys should be different
	assert.NotEqual(t, key1.PublicKey().Bytes(), key2.PublicKey().Bytes())
}
