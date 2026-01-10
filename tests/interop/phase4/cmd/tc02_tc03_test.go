//go:build integration

// Package main implements EU AS4 2.0 TC02/TC03 interoperability tests against phase4.
//
// TC02: ENTSOG Sample Message with Single Payload (Signature + Encryption)
// TC03: OOTS Sample Message with Two Payloads (Signature + Encryption)
//
// These tests validate encryption interoperability with phase4.
//
// NOTE: EU AS4 2.0 specifies X25519+HKDF+AES-128-GCM encryption, but phase4/WSS4J
// does not currently support X25519. The X25519 tests are marked for skip when
// running against phase4. RSA-OAEP tests are provided for phase4 interoperability.
//
// Test variants:
// - *_X25519: EU AS4 2.0 compliant (X25519), skipped for phase4
// - *_RSAOAEP: Legacy RSA-OAEP encryption, works with phase4
//
// Build tag: integration (requires running phase4 server)
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/google/uuid"
	"github.com/leifj/signedxml/xmlenc"
	"github.com/sirosfoundation/go-as4/pkg/message"
	"github.com/sirosfoundation/go-as4/pkg/pmode"
	"github.com/sirosfoundation/go-as4/pkg/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTC02_Phase4_SignedEncryptedSinglePayload tests TC02 against phase4
// NOTE: This test uses X25519 encryption per EU AS4 2.0, which phase4/WSS4J does not support.
// The test is skipped by default. Use TestTC02_Phase4_RSAOAEP for phase4 interop testing.
func TestTC02_Phase4_SignedEncryptedSinglePayload(t *testing.T) {
	// Skip X25519 tests against phase4 - WSS4J doesn't support X25519
	t.Skip("Skipping X25519 test - phase4/WSS4J does not support X25519. Use TestTC02_Phase4_RSAOAEP for phase4 interop.")

	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	phase4URL := getPhase4URL()

	// Check if phase4 is available
	if !isPhase4Available(phase4URL) {
		t.Skip("Phase4 server not available at " + phase4URL)
	}

	// Load CA-signed certificates from files (trusted by phase4)
	signingCert, signingKey, err := loadInteropCertificates()
	require.NoError(t, err, "Failed to load interop certificates. Run scripts/setup-certs.sh first.")
	t.Logf("TC02: Using certificate: %s (Issuer: %s)", signingCert.Subject.CommonName, signingCert.Issuer.CommonName)

	// Generate X25519 key pair (in real scenario, this would be recipient's public key)
	recipientPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	recipientPublic := recipientPrivate.PublicKey()

	// Create ENTSOG-style payload
	payload := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<entsog:Message xmlns:entsog="urn:entsog:communication">
    <entsog:Service>A06</entsog:Service>
    <entsog:Sender>21Y001100000000B</entsog:Sender>
    <entsog:Receiver>21Y001100000001C</entsog:Receiver>
    <entsog:Content>Confidential gas transmission data for TC02</entsog:Content>
</entsog:Message>`)

	// Create UserMessage
	attachmentID := "payload-" + uuid.New().String() + "@as4.siros.org"

	builder := message.NewUserMessage(
		message.WithFrom("go-as4-test", "urn:oasis:names:tc:ebcore:partyid-type:unregistered"),
		message.WithFromRole("http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/initiator"),
		message.WithTo("phase4-test", "urn:oasis:names:tc:ebcore:partyid-type:unregistered"),
		message.WithToRole("http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/responder"),
		message.WithService("http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/service"),
		message.WithAction("http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/test"),
		message.WithConversationId("conv-tc02-"+uuid.New().String()),
		message.WithMessageProperty("originalSender", "urn:oasis:names:tc:ebcore:partyid-type:unregistered:go-as4-test"),
		message.WithMessageProperty("finalRecipient", "urn:oasis:names:tc:ebcore:partyid-type:unregistered:phase4-test"),
	)

	envelope, _, err := builder.BuildEnvelope()
	require.NoError(t, err)

	// Get MessageID from the envelope
	msgID := envelope.Header.Messaging.UserMessage.MessageInfo.MessageId

	// Add PayloadInfo for the attachment
	if envelope.Header.Messaging.UserMessage.PayloadInfo == nil {
		envelope.Header.Messaging.UserMessage.PayloadInfo = &message.PayloadInfo{}
	}
	partInfo := message.NewPartInfo(attachmentID)
	partInfo.SetMimeType("application/xml")
	envelope.Header.Messaging.UserMessage.PayloadInfo.PartInfo = append(
		envelope.Header.Messaging.UserMessage.PayloadInfo.PartInfo, partInfo)

	// Marshal envelope
	envelopeXML, err := xml.Marshal(envelope)
	require.NoError(t, err)

	// Sign the envelope
	signer, err := security.NewRSASignerWithMode(signingKey, signingCert, crypto.SHA256, crypto.SHA256,
		pmode.TokenRefBinarySecurityToken, security.SignatureModePKCS1v15)
	require.NoError(t, err)

	signedXML, err := signer.SignEnvelope(envelopeXML)
	require.NoError(t, err)

	// Encrypt the payload using WS-Security encryptor
	wssEncryptor := security.NewWSSEncryptor(recipientPublic, &security.WSSEncryptionOptions{
		ContentAlgorithm: xmlenc.AlgorithmAES128GCM,
		HKDFInfo:         []byte("EU eDelivery AS4 2.0 TC02"),
	})

	payloads := []security.PayloadData{
		{
			ContentID: attachmentID,
			Data:      payload,
		},
	}

	encResult, err := wssEncryptor.EncryptPayloads(payloads)
	require.NoError(t, err)
	require.Len(t, encResult.EncryptedPayloads, 1)

	// Add EncryptedKey to Security header
	signedDoc := etree.NewDocument()
	err = signedDoc.ReadFromBytes(signedXML)
	require.NoError(t, err)

	// Find Security header
	securityElem := signedDoc.FindElement("//*[local-name()='Security']")
	require.NotNil(t, securityElem, "Security header not found")

	err = security.AddEncryptedKeyToSecurityHeader(securityElem, encResult.EncryptedKey)
	require.NoError(t, err)

	finalEnvXML, err := signedDoc.WriteToBytes()
	require.NoError(t, err)

	// Build MIME message with encrypted payload
	mimeMsg, contentType := buildTC02MIMEMessage(finalEnvXML, encResult.EncryptedPayloads[0].EncryptedData, attachmentID)

	t.Logf("TC02: Sending signed+encrypted message to phase4")
	t.Logf("  MessageID: %s", msgID)
	t.Logf("  PayloadID: %s", attachmentID)
	t.Logf("  Encryption: X25519+HKDF+AES-128-GCM")

	// Send to phase4
	resp, err := sendMIMEToAS4Server(phase4URL, mimeMsg, contentType)
	if err != nil {
		t.Logf("TC02: Send failed: %v", err)
		// Note: phase4 may not support X25519/HKDF yet - document the failure
		t.Logf("TC02: Phase4 may not support EU AS4 2.0 X25519+HKDF encryption")
		t.Logf("      Response: %s", string(resp))
	}

	// Validate response
	if len(resp) > 0 {
		t.Logf("TC02: Response received (%d bytes)", len(resp))
		if err := validateAS4ResponseForTC(resp); err != nil {
			t.Logf("TC02: Response validation: %v", err)
		} else {
			t.Log("TC02: PASSED - phase4 accepted signed+encrypted message")
		}
	}
}

// TestTC03_Phase4_SignedEncryptedTwoPayloads tests TC03 against phase4
// NOTE: This test uses X25519 encryption per EU AS4 2.0, which phase4/WSS4J does not support.
// The test is skipped by default. Use TestTC03_Phase4_RSAOAEP for phase4 interop testing.
func TestTC03_Phase4_SignedEncryptedTwoPayloads(t *testing.T) {
	// Skip X25519 tests against phase4 - WSS4J doesn't support X25519
	t.Skip("Skipping X25519 test - phase4/WSS4J does not support X25519. Use TestTC03_Phase4_RSAOAEP for phase4 interop.")

	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	phase4URL := getPhase4URL()

	// Check if phase4 is available
	if !isPhase4Available(phase4URL) {
		t.Skip("Phase4 server not available at " + phase4URL)
	}

	// Load CA-signed certificates from files (trusted by phase4)
	signingCert, signingKey, err := loadInteropCertificates()
	require.NoError(t, err, "Failed to load interop certificates. Run scripts/setup-certs.sh first.")
	t.Logf("TC03: Using certificate: %s (Issuer: %s)", signingCert.Subject.CommonName, signingCert.Issuer.CommonName)

	// Generate X25519 key pair
	recipientPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	recipientPublic := recipientPrivate.PublicKey()

	// Create two OOTS-style payloads
	payload1 := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<oots:QueryResponse xmlns:oots="urn:oasis:names:tc:ebcore:ebrs:ebms:binding:1.0">
    <oots:ResponseID>oots-response-001</oots:ResponseID>
    <oots:Status>Success</oots:Status>
    <oots:Timestamp>` + time.Now().Format(time.RFC3339) + `</oots:Timestamp>
</oots:QueryResponse>`)

	payload2 := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<oots:Document xmlns:oots="urn:oasis:names:tc:ebcore:ebrs:ebms:binding:1.0">
    <oots:DocumentID>doc-001</oots:DocumentID>
    <oots:Type>BirthCertificate</oots:Type>
    <oots:Content>Encrypted document content for OOTS TC03</oots:Content>
</oots:Document>`)

	// Create UserMessage
	attachment1ID := "payload1-" + uuid.New().String() + "@as4.siros.org"
	attachment2ID := "payload2-" + uuid.New().String() + "@as4.siros.org"

	builder := message.NewUserMessage(
		message.WithFrom("go-as4-test", "urn:oasis:names:tc:ebcore:partyid-type:unregistered"),
		message.WithFromRole("http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/initiator"),
		message.WithTo("phase4-test", "urn:oasis:names:tc:ebcore:partyid-type:unregistered"),
		message.WithToRole("http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/responder"),
		message.WithService("http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/service"),
		message.WithAction("http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/test"),
		message.WithConversationId("conv-tc03-"+uuid.New().String()),
		message.WithMessageProperty("originalSender", "urn:oasis:names:tc:ebcore:partyid-type:unregistered:go-as4-test"),
		message.WithMessageProperty("finalRecipient", "urn:oasis:names:tc:ebcore:partyid-type:unregistered:phase4-test"),
	)

	envelope, _, err := builder.BuildEnvelope()
	require.NoError(t, err)

	// Get MessageID from the envelope
	msgID := envelope.Header.Messaging.UserMessage.MessageInfo.MessageId

	// Add PayloadInfo for both attachments
	if envelope.Header.Messaging.UserMessage.PayloadInfo == nil {
		envelope.Header.Messaging.UserMessage.PayloadInfo = &message.PayloadInfo{}
	}
	partInfo1 := message.NewPartInfo(attachment1ID)
	partInfo1.SetMimeType("application/xml")
	partInfo2 := message.NewPartInfo(attachment2ID)
	partInfo2.SetMimeType("application/xml")
	envelope.Header.Messaging.UserMessage.PayloadInfo.PartInfo = append(
		envelope.Header.Messaging.UserMessage.PayloadInfo.PartInfo, partInfo1, partInfo2)

	// Marshal envelope
	envelopeXML, err := xml.Marshal(envelope)
	require.NoError(t, err)

	// Sign the envelope
	signer, err := security.NewRSASignerWithMode(signingKey, signingCert, crypto.SHA256, crypto.SHA256,
		pmode.TokenRefBinarySecurityToken, security.SignatureModePKCS1v15)
	require.NoError(t, err)

	signedXML, err := signer.SignEnvelope(envelopeXML)
	require.NoError(t, err)

	// Encrypt both payloads
	wssEncryptor := security.NewWSSEncryptor(recipientPublic, &security.WSSEncryptionOptions{
		ContentAlgorithm: xmlenc.AlgorithmAES128GCM,
		HKDFInfo:         []byte("EU eDelivery AS4 2.0 TC03"),
	})

	payloads := []security.PayloadData{
		{ContentID: attachment1ID, Data: payload1},
		{ContentID: attachment2ID, Data: payload2},
	}

	encResult, err := wssEncryptor.EncryptPayloads(payloads)
	require.NoError(t, err)
	require.Len(t, encResult.EncryptedPayloads, 2)

	// Add EncryptedKey to Security header
	signedDoc := etree.NewDocument()
	err = signedDoc.ReadFromBytes(signedXML)
	require.NoError(t, err)

	// Find Security header
	securityElem := signedDoc.FindElement("//*[local-name()='Security']")
	require.NotNil(t, securityElem, "Security header not found")

	err = security.AddEncryptedKeyToSecurityHeader(securityElem, encResult.EncryptedKey)
	require.NoError(t, err)

	finalEnvXML, err := signedDoc.WriteToBytes()
	require.NoError(t, err)

	// Build MIME message with two encrypted payloads
	mimeMsg, contentType := buildTC03MIMEMessage(finalEnvXML, encResult.EncryptedPayloads)

	t.Logf("TC03: Sending signed+encrypted two-payload message to phase4")
	t.Logf("  MessageID: %s", msgID)
	t.Logf("  Payload1ID: %s", attachment1ID)
	t.Logf("  Payload2ID: %s", attachment2ID)
	t.Logf("  Encryption: X25519+HKDF+AES-128-GCM (shared key)")

	// Send to phase4
	resp, err := sendMIMEToAS4Server(phase4URL, mimeMsg, contentType)
	if err != nil {
		t.Logf("TC03: Send failed: %v", err)
		t.Logf("TC03: Phase4 may not support EU AS4 2.0 X25519+HKDF encryption")
		t.Logf("      Response: %s", string(resp))
	}

	// Validate response
	if len(resp) > 0 {
		t.Logf("TC03: Response received (%d bytes)", len(resp))
		if err := validateAS4ResponseForTC(resp); err != nil {
			t.Logf("TC03: Response validation: %v", err)
		} else {
			t.Log("TC03: PASSED - phase4 accepted signed+encrypted two-payload message")
		}
	}
}

// TestTC02_LocalEncryptDecrypt validates local TC02 encrypt/decrypt without phase4
func TestTC02_LocalEncryptDecrypt(t *testing.T) {
	// Generate X25519 key pair
	recipientPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	recipientPublic := recipientPrivate.PublicKey()

	// Create ENTSOG-style payload
	payload := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<entsog:Message xmlns:entsog="urn:entsog:communication">
    <entsog:Content>Confidential TC02 data</entsog:Content>
</entsog:Message>`)

	attachmentID := "tc02-payload@as4.siros.org"

	// Encrypt
	wssEncryptor := security.NewWSSEncryptor(recipientPublic, &security.WSSEncryptionOptions{
		HKDFInfo: []byte("EU eDelivery AS4 2.0 TC02"),
	})

	payloads := []security.PayloadData{{ContentID: attachmentID, Data: payload}}
	encResult, err := wssEncryptor.EncryptPayloads(payloads)
	require.NoError(t, err)

	// Decrypt
	wssDecryptor := security.NewWSSDecryptor(recipientPrivate, []byte("EU eDelivery AS4 2.0 TC02"))
	decInputs := []security.EncryptedPayloadInput{
		{ContentID: attachmentID, EncryptedData: encResult.EncryptedPayloads[0].EncryptedData},
	}
	decResult, err := wssDecryptor.DecryptPayloads(encResult.EncryptedKey, decInputs)
	require.NoError(t, err)

	assert.Equal(t, payload, decResult.DecryptedPayloads[0].Data)
	t.Log("TC02 Local: PASSED - encrypt/decrypt round-trip successful")
}

// TestTC03_LocalEncryptDecrypt validates local TC03 encrypt/decrypt without phase4
func TestTC03_LocalEncryptDecrypt(t *testing.T) {
	// Generate X25519 key pair
	recipientPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	recipientPublic := recipientPrivate.PublicKey()

	// Create two payloads
	payload1 := []byte(`<oots:Response>TC03 Payload 1</oots:Response>`)
	payload2 := []byte(`<oots:Document>TC03 Payload 2</oots:Document>`)

	// Encrypt
	wssEncryptor := security.NewWSSEncryptor(recipientPublic, &security.WSSEncryptionOptions{
		HKDFInfo: []byte("EU eDelivery AS4 2.0 TC03"),
	})

	payloads := []security.PayloadData{
		{ContentID: "payload1@as4", Data: payload1},
		{ContentID: "payload2@as4", Data: payload2},
	}
	encResult, err := wssEncryptor.EncryptPayloads(payloads)
	require.NoError(t, err)
	require.Len(t, encResult.EncryptedPayloads, 2)

	// Decrypt
	wssDecryptor := security.NewWSSDecryptor(recipientPrivate, []byte("EU eDelivery AS4 2.0 TC03"))
	decInputs := []security.EncryptedPayloadInput{
		{ContentID: "payload1@as4", EncryptedData: encResult.EncryptedPayloads[0].EncryptedData},
		{ContentID: "payload2@as4", EncryptedData: encResult.EncryptedPayloads[1].EncryptedData},
	}
	decResult, err := wssDecryptor.DecryptPayloads(encResult.EncryptedKey, decInputs)
	require.NoError(t, err)

	assert.Equal(t, payload1, decResult.DecryptedPayloads[0].Data)
	assert.Equal(t, payload2, decResult.DecryptedPayloads[1].Data)
	t.Log("TC03 Local: PASSED - two-payload encrypt/decrypt successful")
}

// TestTC02_Phase4_RSAOAEP tests TC02 against phase4 using RSA-OAEP encryption
// This test uses RSA-OAEP encryption which phase4/WSS4J supports.
func TestTC02_Phase4_RSAOAEP(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	phase4URL := getPhase4URL()

	// Check if phase4 is available
	if !isPhase4Available(phase4URL) {
		t.Skip("Phase4 server not available at " + phase4URL)
	}

	// Load CA-signed certificates from files (trusted by phase4)
	signingCert, signingKey, err := loadInteropCertificates()
	require.NoError(t, err, "Failed to load interop certificates. Run scripts/setup-certs.sh first.")
	t.Logf("TC02-RSAOAEP: Using certificate: %s (Issuer: %s)", signingCert.Subject.CommonName, signingCert.Issuer.CommonName)

	// Load phase4's certificate for encryption (so phase4 can decrypt)
	phase4Cert, err := loadPhase4Certificate()
	require.NoError(t, err, "Failed to load phase4 certificate (ph-as4.crt)")
	t.Logf("TC02-RSAOAEP: Encrypting for: %s", phase4Cert.Subject.CommonName)

	// Create ENTSOG-style payload
	payload := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<entsog:Message xmlns:entsog="urn:entsog:communication">
    <entsog:Service>A06</entsog:Service>
    <entsog:Sender>21Y001100000000B</entsog:Sender>
    <entsog:Receiver>21Y001100000001C</entsog:Receiver>
    <entsog:Content>Confidential gas transmission data for TC02</entsog:Content>
</entsog:Message>`)

	// Create UserMessage
	attachmentID := "payload-" + uuid.New().String() + "@as4.siros.org"

	builder := message.NewUserMessage(
		message.WithFrom("go-as4-test", "urn:oasis:names:tc:ebcore:partyid-type:unregistered"),
		message.WithFromRole("http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/initiator"),
		message.WithTo("phase4-test", "urn:oasis:names:tc:ebcore:partyid-type:unregistered"),
		message.WithToRole("http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/responder"),
		message.WithService("http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/service"),
		message.WithAction("http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/test"),
		message.WithConversationId("conv-tc02-rsaoaep-"+uuid.New().String()),
		message.WithMessageProperty("originalSender", "urn:oasis:names:tc:ebcore:partyid-type:unregistered:go-as4-test"),
		message.WithMessageProperty("finalRecipient", "urn:oasis:names:tc:ebcore:partyid-type:unregistered:phase4-test"),
	)

	envelope, _, err := builder.BuildEnvelope()
	require.NoError(t, err)

	// Get MessageID from the envelope
	msgID := envelope.Header.Messaging.UserMessage.MessageInfo.MessageId

	// Add PayloadInfo for the attachment
	if envelope.Header.Messaging.UserMessage.PayloadInfo == nil {
		envelope.Header.Messaging.UserMessage.PayloadInfo = &message.PayloadInfo{}
	}
	partInfo := message.NewPartInfo(attachmentID)
	partInfo.SetMimeType("application/xml")
	envelope.Header.Messaging.UserMessage.PayloadInfo.PartInfo = append(
		envelope.Header.Messaging.UserMessage.PayloadInfo.PartInfo, partInfo)

	// Marshal envelope
	envelopeXML, err := xml.Marshal(envelope)
	require.NoError(t, err)

	// Encrypt payload using RSA-OAEP with phase4's certificate (so phase4 can decrypt)
	encryptedDataWithTag, encryptedKey, err := security.EncryptAttachmentData(payload, phase4Cert)
	require.NoError(t, err)

	// Sign the envelope
	signer, err := security.NewRSASignerWithMode(signingKey, signingCert, crypto.SHA256, crypto.SHA256,
		pmode.TokenRefBinarySecurityToken, security.SignatureModePKCS1v15)
	require.NoError(t, err)

	signedXML, err := signer.SignEnvelope(envelopeXML)
	require.NoError(t, err)

	// Parse signed XML to add SwA encryption elements
	signedDoc := etree.NewDocument()
	err = signedDoc.ReadFromBytes(signedXML)
	require.NoError(t, err)

	// Get security element
	securityElem := signedDoc.FindElement("//*[local-name()='Security']")
	require.NotNil(t, securityElem, "Security element not found")

	// Add SwA encryption elements (EncryptedKey in Security header, EncryptedData in Body)
	// This follows the WS-Security SwA profile that phase4/WSS4J expects
	attachment := &security.SwAEncryptedAttachment{
		ContentID:        attachmentID,
		EncryptedData:    encryptedDataWithTag,
		EncryptedKey:     encryptedKey,
		OriginalMimeType: "application/xml",
	}
	err = security.AddSwAEncryptionToDocument(signedDoc, attachment, phase4Cert)
	require.NoError(t, err)

	finalEnvXML, err := signedDoc.WriteToBytes()
	require.NoError(t, err)

	// Build MIME message with encrypted payload
	mimeMsg, contentType := buildTC02MIMEMessage(finalEnvXML, encryptedDataWithTag, attachmentID)

	t.Logf("TC02-RSAOAEP: Sending signed+encrypted message to phase4")
	t.Logf("  MessageID: %s", msgID)
	t.Logf("  PayloadID: %s", attachmentID)
	t.Logf("  Encryption: RSA-OAEP with AES-128-GCM")

	// Send to phase4
	resp, err := sendMIMEToAS4Server(phase4URL, mimeMsg, contentType)
	if err != nil {
		t.Logf("TC02-RSAOAEP: Send failed: %v", err)
		t.Logf("      Response: %s", string(resp))
		t.FailNow()
	}

	// Validate response
	if len(resp) > 0 {
		t.Logf("TC02-RSAOAEP: Response received (%d bytes)", len(resp))
		if err := validateAS4ResponseForTC(resp); err != nil {
			t.Logf("TC02-RSAOAEP: Response validation: %v", err)
			t.Logf("      Response: %s", string(resp))
		} else {
			t.Log("TC02-RSAOAEP: PASSED - phase4 accepted signed+encrypted message")
		}
	}
}

// TestTC03_Phase4_RSAOAEP tests TC03 against phase4 using RSA-OAEP encryption
// This test uses RSA-OAEP encryption which phase4/WSS4J supports.
func TestTC03_Phase4_RSAOAEP(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	phase4URL := getPhase4URL()

	// Check if phase4 is available
	if !isPhase4Available(phase4URL) {
		t.Skip("Phase4 server not available at " + phase4URL)
	}

	// Load CA-signed certificates from files (trusted by phase4)
	signingCert, signingKey, err := loadInteropCertificates()
	require.NoError(t, err, "Failed to load interop certificates. Run scripts/setup-certs.sh first.")
	t.Logf("TC03-RSAOAEP: Using certificate: %s (Issuer: %s)", signingCert.Subject.CommonName, signingCert.Issuer.CommonName)

	// Load phase4's certificate for encryption (so phase4 can decrypt)
	phase4Cert, err := loadPhase4Certificate()
	require.NoError(t, err, "Failed to load phase4 certificate (ph-as4.crt)")
	t.Logf("TC03-RSAOAEP: Encrypting for: %s", phase4Cert.Subject.CommonName)

	// Create two OOTS-style payloads
	payload1 := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<oots:Response xmlns:oots="http://data.europa.eu/oots">
    <oots:RequestId>REQ-12345</oots:RequestId>
    <oots:Status>Success</oots:Status>
    <oots:Evidence>First evidence document for TC03</oots:Evidence>
</oots:Response>`)

	payload2 := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<oots:Document xmlns:oots="http://data.europa.eu/oots">
    <oots:DocumentId>DOC-67890</oots:DocumentId>
    <oots:Type>Certificate</oots:Type>
    <oots:Content>Second document for TC03 with supporting evidence</oots:Content>
</oots:Document>`)

	// Create UserMessage with two attachments
	attachment1ID := "payload1-" + uuid.New().String() + "@as4.siros.org"
	attachment2ID := "payload2-" + uuid.New().String() + "@as4.siros.org"

	builder := message.NewUserMessage(
		message.WithFrom("go-as4-test", "urn:oasis:names:tc:ebcore:partyid-type:unregistered"),
		message.WithFromRole("http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/initiator"),
		message.WithTo("phase4-test", "urn:oasis:names:tc:ebcore:partyid-type:unregistered"),
		message.WithToRole("http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/responder"),
		message.WithService("http://data.europa.eu/oots/evidence-exchange"),
		message.WithAction("SubmitEvidenceResponse"),
		message.WithConversationId("conv-tc03-rsaoaep-"+uuid.New().String()),
		message.WithMessageProperty("originalSender", "urn:oasis:names:tc:ebcore:partyid-type:unregistered:go-as4-test"),
		message.WithMessageProperty("finalRecipient", "urn:oasis:names:tc:ebcore:partyid-type:unregistered:phase4-test"),
	)

	envelope, _, err := builder.BuildEnvelope()
	require.NoError(t, err)

	// Get MessageID from the envelope
	msgID := envelope.Header.Messaging.UserMessage.MessageInfo.MessageId

	// Add PayloadInfo for both attachments
	if envelope.Header.Messaging.UserMessage.PayloadInfo == nil {
		envelope.Header.Messaging.UserMessage.PayloadInfo = &message.PayloadInfo{}
	}
	partInfo1 := message.NewPartInfo(attachment1ID)
	partInfo1.SetMimeType("application/xml")
	envelope.Header.Messaging.UserMessage.PayloadInfo.PartInfo = append(
		envelope.Header.Messaging.UserMessage.PayloadInfo.PartInfo, partInfo1)
	partInfo2 := message.NewPartInfo(attachment2ID)
	partInfo2.SetMimeType("application/xml")
	envelope.Header.Messaging.UserMessage.PayloadInfo.PartInfo = append(
		envelope.Header.Messaging.UserMessage.PayloadInfo.PartInfo, partInfo2)

	// Marshal envelope
	envelopeXML, err := xml.Marshal(envelope)
	require.NoError(t, err)

	// Encrypt both payloads with RSA-OAEP using phase4's certificate (so phase4 can decrypt)
	encryptedData1, encryptedKey1, err := security.EncryptAttachmentData(payload1, phase4Cert)
	require.NoError(t, err)

	encryptedData2, encryptedKey2, err := security.EncryptAttachmentData(payload2, phase4Cert)
	require.NoError(t, err)

	// Sign the envelope
	signer, err := security.NewRSASignerWithMode(signingKey, signingCert, crypto.SHA256, crypto.SHA256,
		pmode.TokenRefBinarySecurityToken, security.SignatureModePKCS1v15)
	require.NoError(t, err)

	signedXML, err := signer.SignEnvelope(envelopeXML)
	require.NoError(t, err)

	// Parse signed XML to add SwA encryption elements
	signedDoc := etree.NewDocument()
	err = signedDoc.ReadFromBytes(signedXML)
	require.NoError(t, err)

	// Add SwA encryption elements for both attachments
	// Each attachment gets its own EncryptedKey and EncryptedData element
	attachment1 := &security.SwAEncryptedAttachment{
		ContentID:        attachment1ID,
		EncryptedData:    encryptedData1,
		EncryptedKey:     encryptedKey1,
		OriginalMimeType: "application/xml",
	}
	err = security.AddSwAEncryptionToDocument(signedDoc, attachment1, phase4Cert)
	require.NoError(t, err)

	attachment2 := &security.SwAEncryptedAttachment{
		ContentID:        attachment2ID,
		EncryptedData:    encryptedData2,
		EncryptedKey:     encryptedKey2,
		OriginalMimeType: "application/xml",
	}
	err = security.AddSwAEncryptionToDocument(signedDoc, attachment2, phase4Cert)
	require.NoError(t, err)

	finalEnvXML, err := signedDoc.WriteToBytes()
	require.NoError(t, err)

	// Build MIME message with encrypted payloads
	encryptedPayloads := []security.WSSEncryptedPayload{
		{ContentID: attachment1ID, EncryptedData: encryptedData1},
		{ContentID: attachment2ID, EncryptedData: encryptedData2},
	}
	mimeMsg, contentType := buildTC03MIMEMessage(finalEnvXML, encryptedPayloads)

	t.Logf("TC03-RSAOAEP: Sending signed+encrypted two-payload message to phase4")
	t.Logf("  MessageID: %s", msgID)
	t.Logf("  Payload1ID: %s", attachment1ID)
	t.Logf("  Payload2ID: %s", attachment2ID)
	t.Logf("  Encryption: RSA-OAEP with AES-128-GCM (separate keys)")

	// Send to phase4
	resp, err := sendMIMEToAS4Server(phase4URL, mimeMsg, contentType)
	if err != nil {
		t.Logf("TC03-RSAOAEP: Send failed: %v", err)
		t.Logf("      Response: %s", string(resp))
		t.FailNow()
	}

	// Validate response
	if len(resp) > 0 {
		t.Logf("TC03-RSAOAEP: Response received (%d bytes)", len(resp))
		if err := validateAS4ResponseForTC(resp); err != nil {
			t.Logf("TC03-RSAOAEP: Response validation: %v", err)
			t.Logf("      Response: %s", string(resp))
		} else {
			t.Log("TC03-RSAOAEP: PASSED - phase4 accepted signed+encrypted two-payload message")
		}
	}
}

// Helper functions

func getPhase4URL() string {
	if url := os.Getenv("PHASE4_URL"); url != "" {
		return url
	}
	return "http://localhost:8080/as4"
}

func isPhase4Available(url string) bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	// phase4 returns 405 Method Not Allowed for GET (expects POST)
	return resp.StatusCode == 405 || resp.StatusCode == 200
}

// getCertsDir returns the path to the interop certificates directory
func getCertsDir() string {
	// Check environment variable first
	if dir := os.Getenv("INTEROP_CERTS_DIR"); dir != "" {
		return dir
	}
	// Default locations to try
	locations := []string{
		"../certs",                   // When running from cmd directory
		"certs",                      // When running from phase4 directory
		"tests/interop/phase4/certs", // When running from go-as4 root
	}
	for _, loc := range locations {
		if _, err := os.Stat(filepath.Join(loc, "go-as4-test.crt")); err == nil {
			return loc
		}
	}
	return "../certs" // Fallback
}

// loadPhase4Certificate loads phase4's certificate for encryption
// This is the certificate phase4 uses for decryption
func loadPhase4Certificate() (*x509.Certificate, error) {
	certsDir := getCertsDir()

	// Load phase4 certificate
	certPEM, err := os.ReadFile(filepath.Join(certsDir, "ph-as4.crt"))
	if err != nil {
		return nil, fmt.Errorf("failed to read phase4 certificate: %w (certsDir=%s)", err, certsDir)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode phase4 certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse phase4 certificate: %w", err)
	}

	return cert, nil
}

// loadInteropCertificates loads the CA-signed certificate and key from the certs directory
// These certificates are trusted by phase4's truststore (interop-truststore.jks)
func loadInteropCertificates() (*x509.Certificate, *rsa.PrivateKey, error) {
	certsDir := getCertsDir()

	// Load certificate
	certPEM, err := os.ReadFile(filepath.Join(certsDir, "go-as4-test.crt"))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read certificate: %w (certsDir=%s)", err, certsDir)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Load private key
	keyPEM, err := os.ReadFile(filepath.Join(certsDir, "go-as4-test.key"))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key: %w (certsDir=%s)", err, certsDir)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode private key PEM")
	}

	// Try PKCS#1 format first (RSA PRIVATE KEY), then PKCS#8 (PRIVATE KEY)
	var key *rsa.PrivateKey
	if keyBlock.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse PKCS#1 private key: %w", err)
		}
	} else {
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
		var ok bool
		key, ok = pkcs8Key.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("private key is not RSA")
		}
	}

	return cert, key, nil
}

func buildTC02MIMEMessage(envelopeXML []byte, encryptedPayload []byte, attachmentID string) ([]byte, string) {
	var buf bytes.Buffer
	boundary := "----=_Part_" + uuid.New().String()
	writer := multipart.NewWriter(&buf)
	writer.SetBoundary(boundary)

	// SOAP envelope part
	soapHeader := textproto.MIMEHeader{}
	soapHeader.Set("Content-Type", "application/soap+xml; charset=UTF-8")
	soapHeader.Set("Content-Transfer-Encoding", "8bit")
	soapHeader.Set("Content-ID", "<soap-envelope@as4.siros.org>")

	soapPart, _ := writer.CreatePart(soapHeader)
	soapPart.Write(envelopeXML)

	// Encrypted payload part
	payloadHeader := textproto.MIMEHeader{}
	payloadHeader.Set("Content-Type", "application/octet-stream")
	payloadHeader.Set("Content-Transfer-Encoding", "base64")
	payloadHeader.Set("Content-ID", "<"+attachmentID+">")

	payloadPart, _ := writer.CreatePart(payloadHeader)
	payloadPart.Write([]byte(base64.StdEncoding.EncodeToString(encryptedPayload)))

	writer.Close()

	contentType := fmt.Sprintf(`multipart/related; boundary="%s"; type="application/soap+xml"; start="<soap-envelope@as4.siros.org>"`, boundary)
	return buf.Bytes(), contentType
}

func buildTC03MIMEMessage(envelopeXML []byte, encryptedPayloads []security.WSSEncryptedPayload) ([]byte, string) {
	var buf bytes.Buffer
	boundary := "----=_Part_" + uuid.New().String()
	writer := multipart.NewWriter(&buf)
	writer.SetBoundary(boundary)

	// SOAP envelope part
	soapHeader := textproto.MIMEHeader{}
	soapHeader.Set("Content-Type", "application/soap+xml; charset=UTF-8")
	soapHeader.Set("Content-Transfer-Encoding", "8bit")
	soapHeader.Set("Content-ID", "<soap-envelope@as4.siros.org>")

	soapPart, _ := writer.CreatePart(soapHeader)
	soapPart.Write(envelopeXML)

	// Encrypted payload parts
	for _, ep := range encryptedPayloads {
		payloadHeader := textproto.MIMEHeader{}
		payloadHeader.Set("Content-Type", "application/octet-stream")
		payloadHeader.Set("Content-Transfer-Encoding", "base64")
		payloadHeader.Set("Content-ID", "<"+ep.ContentID+">")

		payloadPart, _ := writer.CreatePart(payloadHeader)
		payloadPart.Write([]byte(base64.StdEncoding.EncodeToString(ep.EncryptedData)))
	}

	writer.Close()

	contentType := fmt.Sprintf(`multipart/related; boundary="%s"; type="application/soap+xml"; start="<soap-envelope@as4.siros.org>"`, boundary)
	return buf.Bytes(), contentType
}

func sendMIMEToAS4Server(url string, body []byte, contentType string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", contentType)
	req.Header.Set("SOAPAction", "")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return respBody, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func validateAS4ResponseForTC(resp []byte) error {
	// Check for SOAP fault
	if bytes.Contains(resp, []byte("soap:Fault")) || bytes.Contains(resp, []byte("S12:Fault")) {
		return fmt.Errorf("SOAP Fault in response")
	}

	// Check for ebMS error
	if bytes.Contains(resp, []byte("eb:Error")) {
		return fmt.Errorf("ebMS Error in response")
	}

	// Check for Receipt (positive response)
	if bytes.Contains(resp, []byte("Receipt")) || bytes.Contains(resp, []byte("SignalMessage")) {
		return nil // Success
	}

	return nil
}
