package security

import (
	"bytes"
	"crypto/ecdh"
	"testing"

	"github.com/beevik/etree"
	"github.com/leifj/signedxml/xmlenc"
)

func TestWSSEncryptorDecryptor(t *testing.T) {
	// Generate recipient key pair
	recipientPrivate, err := xmlenc.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	recipientPublic := recipientPrivate.PublicKey()

	// Create test payloads
	payloads := []PayloadData{
		{
			ContentID: "payload-1@example.com",
			MimeType:  "application/xml",
			Data:      []byte(`<?xml version="1.0"?><test>Hello World</test>`),
		},
		{
			ContentID: "payload-2@example.com",
			MimeType:  "application/pdf",
			Data:      []byte("PDF binary content here..."),
		},
	}

	// Test encryption
	encryptor := NewWSSEncryptor(recipientPublic, nil)
	result, err := encryptor.EncryptPayloads(payloads)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify EncryptedKey structure
	if result.EncryptedKey == nil {
		t.Fatal("EncryptedKey is nil")
	}
	if result.EncryptedKey.EncryptionMethod == nil {
		t.Fatal("EncryptionMethod is nil")
	}
	if result.EncryptedKey.EncryptionMethod.Algorithm != xmlenc.AlgorithmAES128KW {
		t.Errorf("Expected AES-128-KW algorithm, got %s", result.EncryptedKey.EncryptionMethod.Algorithm)
	}
	if len(result.EncryptedKey.ReferenceList) != len(payloads) {
		t.Errorf("Expected %d data references, got %d", len(payloads), len(result.EncryptedKey.ReferenceList))
	}

	// Verify encrypted payloads
	if len(result.EncryptedPayloads) != len(payloads) {
		t.Fatalf("Expected %d encrypted payloads, got %d", len(payloads), len(result.EncryptedPayloads))
	}

	// Test decryption
	decryptor := NewWSSDecryptor(recipientPrivate, nil)

	// Prepare encrypted payload inputs
	encryptedInputs := make([]EncryptedPayloadInput, len(result.EncryptedPayloads))
	for i, ep := range result.EncryptedPayloads {
		encryptedInputs[i] = EncryptedPayloadInput{
			ContentID:     ep.ContentID,
			EncryptedData: ep.EncryptedData,
			OriginalMime:  ep.OriginalMime,
		}
	}

	decResult, err := decryptor.DecryptPayloads(result.EncryptedKey, encryptedInputs)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify decrypted content
	for i, dp := range decResult.DecryptedPayloads {
		if !bytes.Equal(dp.Data, payloads[i].Data) {
			t.Errorf("Payload %d mismatch: expected %s, got %s",
				i, string(payloads[i].Data), string(dp.Data))
		}
		if dp.ContentID != payloads[i].ContentID {
			t.Errorf("ContentID %d mismatch: expected %s, got %s",
				i, payloads[i].ContentID, dp.ContentID)
		}
	}
}

func TestWSSEncryptorWithCustomHKDFInfo(t *testing.T) {
	// Generate recipient key pair
	recipientPrivate, err := xmlenc.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	customInfo := []byte("Custom HKDF Context Info")
	opts := &WSSEncryptionOptions{
		HKDFInfo: customInfo,
	}

	encryptor := NewWSSEncryptor(recipientPrivate.PublicKey(), opts)

	payloads := []PayloadData{
		{
			ContentID: "test@example.com",
			MimeType:  "text/plain",
			Data:      []byte("Test data"),
		},
	}

	result, err := encryptor.EncryptPayloads(payloads)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify HKDF params are in the EncryptedKey
	if result.EncryptedKey.KeyInfo == nil ||
		result.EncryptedKey.KeyInfo.AgreementMethod == nil ||
		result.EncryptedKey.KeyInfo.AgreementMethod.KeyDerivationMethod == nil ||
		result.EncryptedKey.KeyInfo.AgreementMethod.KeyDerivationMethod.HKDFParams == nil {
		t.Fatal("HKDF params not found in EncryptedKey")
	}

	hkdfParams := result.EncryptedKey.KeyInfo.AgreementMethod.KeyDerivationMethod.HKDFParams
	if !bytes.Equal(hkdfParams.Info, customInfo) {
		t.Error("Custom HKDF info not preserved in EncryptedKey")
	}

	// Decrypt with matching HKDF info - decryptor uses params from EncryptedKey
	decryptor := NewWSSDecryptor(recipientPrivate, customInfo)
	encryptedInputs := []EncryptedPayloadInput{
		{
			ContentID:     result.EncryptedPayloads[0].ContentID,
			EncryptedData: result.EncryptedPayloads[0].EncryptedData,
		},
	}

	decResult, err := decryptor.DecryptPayloads(result.EncryptedKey, encryptedInputs)
	if err != nil {
		t.Fatalf("Decryption with matching info failed: %v", err)
	}

	if !bytes.Equal(decResult.DecryptedPayloads[0].Data, payloads[0].Data) {
		t.Error("Decrypted data mismatch")
	}
}

func TestAddEncryptedKeyToSecurityHeader(t *testing.T) {
	// Create a mock Security element
	doc := etree.NewDocument()
	security := doc.CreateElement("wsse:Security")
	security.CreateAttr("xmlns:wsse", NSSecurityExt)

	// Add a Signature element first
	sig := security.CreateElement("ds:Signature")
	sig.CreateAttr("xmlns:ds", NSXMLDSig)

	// Generate test EncryptedKey
	recipientPrivate, _ := xmlenc.GenerateX25519KeyPair()
	encryptor := NewWSSEncryptor(recipientPrivate.PublicKey(), nil)

	payloads := []PayloadData{
		{ContentID: "test@example.com", MimeType: "text/plain", Data: []byte("test")},
	}
	result, err := encryptor.EncryptPayloads(payloads)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Add EncryptedKey to Security header
	err = AddEncryptedKeyToSecurityHeader(security, result.EncryptedKey)
	if err != nil {
		t.Fatalf("Failed to add EncryptedKey: %v", err)
	}

	// Verify structure
	encKeyElem := security.FindElement("./EncryptedKey")
	if encKeyElem == nil {
		encKeyElem = security.FindElement("./*[local-name()='EncryptedKey']")
	}
	if encKeyElem == nil {
		t.Fatal("EncryptedKey element not found in Security header")
	}

	// Verify EncryptedKey has Id attribute
	if encKeyElem.SelectAttrValue("Id", "") == "" {
		t.Error("EncryptedKey missing Id attribute")
	}

	// Verify EncryptedKey has EncryptionMethod
	encMethod := encKeyElem.FindElement("./EncryptionMethod")
	if encMethod == nil {
		encMethod = encKeyElem.FindElement("./*[local-name()='EncryptionMethod']")
	}
	if encMethod == nil {
		t.Error("EncryptionMethod not found in EncryptedKey")
	}

	// Verify EncryptedKey has ReferenceList
	refList := encKeyElem.FindElement("./ReferenceList")
	if refList == nil {
		refList = encKeyElem.FindElement("./*[local-name()='ReferenceList']")
	}
	if refList == nil {
		t.Error("ReferenceList not found in EncryptedKey")
	}
}

func TestEncryptedKeyParsing(t *testing.T) {
	// Generate and encrypt
	recipientPrivate, _ := xmlenc.GenerateX25519KeyPair()
	encryptor := NewWSSEncryptor(recipientPrivate.PublicKey(), nil)

	payloads := []PayloadData{
		{ContentID: "test@example.com", MimeType: "application/xml", Data: []byte("<test/>")},
	}
	result, err := encryptor.EncryptPayloads(payloads)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Convert to XML and back
	doc := etree.NewDocument()
	security := doc.CreateElement("wsse:Security")
	security.CreateAttr("xmlns:wsse", NSSecurityExt)

	err = AddEncryptedKeyToSecurityHeader(security, result.EncryptedKey)
	if err != nil {
		t.Fatalf("Failed to add EncryptedKey: %v", err)
	}

	// Parse back
	parsedKey, dataRefs, err := ExtractEncryptedKey(security)
	if err != nil {
		t.Fatalf("Failed to extract EncryptedKey: %v", err)
	}

	if len(dataRefs) != 1 {
		t.Errorf("Expected 1 data reference, got %d", len(dataRefs))
	}

	// Decrypt using parsed key
	decryptor := NewWSSDecryptor(recipientPrivate, nil)
	encryptedInputs := []EncryptedPayloadInput{
		{
			ContentID:     result.EncryptedPayloads[0].ContentID,
			EncryptedData: result.EncryptedPayloads[0].EncryptedData,
		},
	}

	decResult, err := decryptor.DecryptPayloads(parsedKey, encryptedInputs)
	if err != nil {
		t.Fatalf("Decryption with parsed key failed: %v", err)
	}

	if !bytes.Equal(decResult.DecryptedPayloads[0].Data, payloads[0].Data) {
		t.Error("Decrypted data mismatch after round-trip")
	}
}

func TestCreateEncryptedDataElement(t *testing.T) {
	elem := CreateEncryptedDataElement("ED-123", "application/xml", "cid:attachment@example.com")

	if elem == nil {
		t.Fatal("CreateEncryptedDataElement returned nil")
	}

	// Verify attributes
	if elem.SelectAttrValue("Id", "") != "ED-123" {
		t.Error("Wrong Id attribute")
	}
	if elem.SelectAttrValue("MimeType", "") != "application/xml" {
		t.Error("Wrong MimeType attribute")
	}

	// Verify CipherReference
	cipherRef := elem.FindElement("./CipherData/CipherReference")
	if cipherRef == nil {
		cipherRef = elem.FindElement("./*[local-name()='CipherData']/*[local-name()='CipherReference']")
	}
	if cipherRef == nil {
		t.Fatal("CipherReference not found")
	}
	if cipherRef.SelectAttrValue("URI", "") != "cid:attachment@example.com" {
		t.Error("Wrong CipherReference URI")
	}
}

func TestIsMessageEncrypted(t *testing.T) {
	// Encrypted message
	encryptedEnvelope := []byte(`<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Id="EK-123">
        <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes128"/>
        <xenc:CipherData><xenc:CipherValue>abc123</xenc:CipherValue></xenc:CipherData>
      </xenc:EncryptedKey>
    </wsse:Security>
  </soap:Header>
  <soap:Body/>
</soap:Envelope>`)

	encrypted, err := IsMessageEncrypted(encryptedEnvelope)
	if err != nil {
		t.Fatalf("IsMessageEncrypted failed: %v", err)
	}
	if !encrypted {
		t.Error("Expected message to be detected as encrypted")
	}

	// Non-encrypted message
	nonEncryptedEnvelope := []byte(`<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>
    </wsse:Security>
  </soap:Header>
  <soap:Body/>
</soap:Envelope>`)

	encrypted, err = IsMessageEncrypted(nonEncryptedEnvelope)
	if err != nil {
		t.Fatalf("IsMessageEncrypted failed: %v", err)
	}
	if encrypted {
		t.Error("Expected message to be detected as not encrypted")
	}
}

func TestEmptyPayloadsError(t *testing.T) {
	recipientPrivate, _ := xmlenc.GenerateX25519KeyPair()
	encryptor := NewWSSEncryptor(recipientPrivate.PublicKey(), nil)

	_, err := encryptor.EncryptPayloads([]PayloadData{})
	if err == nil {
		t.Error("Expected error for empty payloads")
	}
}

// Helper to get private key for testing
func generateTestKeyPair(t *testing.T) (*ecdh.PrivateKey, *ecdh.PublicKey) {
	priv, err := xmlenc.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	return priv, priv.PublicKey()
}
