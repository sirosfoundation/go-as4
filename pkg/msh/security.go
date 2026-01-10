// Copyright (c) 2025 SIROS Foundation
// SPDX-License-Identifier: BSD-2-Clause

package msh

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/xml"
	"fmt"

	"github.com/beevik/etree"
	"github.com/sirosfoundation/go-as4/pkg/message"
	"github.com/sirosfoundation/go-as4/pkg/security"
)

// SecurityProcessor handles signing and encryption for MSH
// It provides an adapter layer between MSH and the security package implementations
type SecurityProcessor struct {
	signer       security.Signer           // Uses the Signer interface (RSASigner or AS4Signer)
	encryptor    *security.AESEncryptor    // Legacy encryptor (deprecated)
	wssEncryptor *security.WSSEncryptor    // WS-Security compliant encryptor
	wssDecryptor *security.WSSDecryptor    // WS-Security compliant decryptor
}

// NewSecurityProcessor creates a new security processor
func NewSecurityProcessor(signer security.Signer, encryptor *security.AESEncryptor) *SecurityProcessor {
	return &SecurityProcessor{
		signer:    signer,
		encryptor: encryptor,
	}
}

// NewSecurityProcessorWithWSS creates a security processor with WS-Security encryption
func NewSecurityProcessorWithWSS(signer security.Signer, recipientPublicKey *ecdh.PublicKey, privateKey *ecdh.PrivateKey) *SecurityProcessor {
	sp := &SecurityProcessor{
		signer: signer,
	}
	if recipientPublicKey != nil {
		sp.wssEncryptor = security.NewWSSEncryptor(recipientPublicKey, nil)
	}
	if privateKey != nil {
		sp.wssDecryptor = security.NewWSSDecryptor(privateKey, nil)
	}
	return sp
}

// SignEnvelope signs an AS4 SOAP envelope using the configured signer
func (sp *SecurityProcessor) SignEnvelope(env *message.Envelope) ([]byte, error) {
	if sp.signer == nil {
		return nil, fmt.Errorf("no signer configured")
	}

	// Marshal envelope to XML
	envXML, err := xml.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal envelope: %w", err)
	}

	// Add XML declaration
	fullXML := append([]byte(xml.Header), envXML...)

	// Sign the envelope
	signedXML, err := sp.signer.SignEnvelope(fullXML)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return signedXML, nil
}

// VerifyEnvelope verifies the signature on an AS4 SOAP envelope
func (sp *SecurityProcessor) VerifyEnvelope(envelopeXML []byte) error {
	if sp.signer == nil {
		return fmt.Errorf("no signer configured")
	}

	if err := sp.signer.VerifyEnvelope(envelopeXML); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// EncryptPayloads encrypts message payloads using X25519 key agreement and AES-128-GCM
func (sp *SecurityProcessor) EncryptPayloads(payloads []Payload) error {
	if sp.encryptor == nil {
		return nil // Encryption not configured, skip
	}

	for i := range payloads {
		// Encrypt the payload data
		ciphertext, ephemeralPubKey, nonce, err := sp.encryptor.Encrypt(payloads[i].Data)
		if err != nil {
			return fmt.Errorf("encryption failed for payload %d: %w", i, err)
		}

		// Store encrypted data
		payloads[i].Data = ciphertext

		// Store encryption metadata in properties
		if payloads[i].Properties == nil {
			payloads[i].Properties = make(map[string]string)
		}
		payloads[i].Properties["EphemeralPublicKey"] = base64.StdEncoding.EncodeToString(ephemeralPubKey)
		payloads[i].Properties["Nonce"] = base64.StdEncoding.EncodeToString(nonce)
		payloads[i].Properties["EncryptionAlgorithm"] = "AES-128-GCM"
	}

	return nil
}

// DecryptPayloads decrypts message payloads
func (sp *SecurityProcessor) DecryptPayloads(payloads []Payload, privateKey [32]byte) error {
	for i := range payloads {
		// Check if payload is encrypted
		ephemKeyStr, hasEphemKey := payloads[i].Properties["EphemeralPublicKey"]
		nonceStr, hasNonce := payloads[i].Properties["Nonce"]

		if !hasEphemKey || !hasNonce {
			continue // Not encrypted, skip
		}

		// Decode encryption metadata
		ephemeralPubKey, err := base64.StdEncoding.DecodeString(ephemKeyStr)
		if err != nil {
			return fmt.Errorf("failed to decode ephemeral public key for payload %d: %w", i, err)
		}

		nonce, err := base64.StdEncoding.DecodeString(nonceStr)
		if err != nil {
			return fmt.Errorf("failed to decode nonce for payload %d: %w", i, err)
		}

		// Create decryptor with private key
		decryptor := &security.AESEncryptor{}
		// Note: In production, we'd need to properly initialize this with the private key
		// For now, use the AESEncryptor's Decrypt method directly
		plaintext, err := decryptor.Decrypt(payloads[i].Data, ephemeralPubKey, nonce)
		if err != nil {
			return fmt.Errorf("decryption failed for payload %d: %w", i, err)
		}

		// Replace encrypted data with plaintext
		payloads[i].Data = plaintext

		// Clean up encryption metadata
		delete(payloads[i].Properties, "EphemeralPublicKey")
		delete(payloads[i].Properties, "Nonce")
		delete(payloads[i].Properties, "EncryptionAlgorithm")
	}

	return nil
}

// HasSigner returns true if a signer is configured
func (sp *SecurityProcessor) HasSigner() bool {
	return sp.signer != nil
}

// HasEncryptor returns true if an encryptor is configured
func (sp *SecurityProcessor) HasEncryptor() bool {
	return sp.encryptor != nil || sp.wssEncryptor != nil
}

// HasWSSEncryptor returns true if WS-Security encryption is configured
func (sp *SecurityProcessor) HasWSSEncryptor() bool {
	return sp.wssEncryptor != nil
}

// SignAndEncryptEnvelope signs and optionally encrypts an AS4 message.
// This method handles the complete WS-Security flow for outbound messages:
// 1. Marshal envelope to XML
// 2. Sign the envelope (adds Signature to Security header)
// 3. Encrypt payloads if encryption is configured (adds EncryptedKey to Security header)
// Returns the signed envelope XML and encrypted payloads if encryption was applied.
func (sp *SecurityProcessor) SignAndEncryptEnvelope(env *message.Envelope, payloads []Payload) ([]byte, []Payload, error) {
	// First, sign the envelope
	signedXML, err := sp.SignEnvelope(env)
	if err != nil {
		return nil, nil, fmt.Errorf("signing failed: %w", err)
	}

	// If WS-Security encryption is not configured, return signed message as-is
	if sp.wssEncryptor == nil {
		return signedXML, payloads, nil
	}

	// Convert payloads to encryption input format
	payloadData := make([]security.PayloadData, len(payloads))
	for i, p := range payloads {
		payloadData[i] = security.PayloadData{
			ContentID: p.ContentID,
			MimeType:  p.ContentType,
			Data:      p.Data,
		}
	}

	// Encrypt payloads
	encResult, err := sp.wssEncryptor.EncryptPayloads(payloadData)
	if err != nil {
		return nil, nil, fmt.Errorf("encryption failed: %w", err)
	}

	// Parse the signed envelope to add EncryptedKey
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(signedXML); err != nil {
		return nil, nil, fmt.Errorf("failed to parse signed envelope: %w", err)
	}

	// Find Security header
	securityElem := doc.FindElement("//Security")
	if securityElem == nil {
		securityElem = doc.FindElement("//*[local-name()='Security']")
	}
	if securityElem == nil {
		return nil, nil, fmt.Errorf("Security header not found in signed envelope")
	}

	// Add EncryptedKey to Security header
	if err := security.AddEncryptedKeyToSecurityHeader(securityElem, encResult.EncryptedKey); err != nil {
		return nil, nil, fmt.Errorf("failed to add EncryptedKey: %w", err)
	}

	// Convert encrypted payloads back
	encryptedPayloads := make([]Payload, len(encResult.EncryptedPayloads))
	for i, ep := range encResult.EncryptedPayloads {
		encryptedPayloads[i] = Payload{
			ContentID:   ep.ContentID,
			ContentType: ep.EncryptedMime,
			Data:        ep.EncryptedData,
		}
		// Preserve original MIME type in properties for receiver
		if encryptedPayloads[i].Properties == nil {
			encryptedPayloads[i].Properties = make(map[string]string)
		}
		encryptedPayloads[i].Properties["OriginalMimeType"] = ep.OriginalMime
		encryptedPayloads[i].Properties["DataReferenceID"] = ep.DataReferenceID
	}

	// Serialize modified envelope
	doc.Indent(2)
	modifiedXML, err := doc.WriteToBytes()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize modified envelope: %w", err)
	}

	return modifiedXML, encryptedPayloads, nil
}

// VerifyAndDecryptEnvelope verifies signature and decrypts an AS4 message.
// This method handles the complete WS-Security flow for inbound messages:
// 1. Check if message is encrypted
// 2. Extract EncryptedKey and decrypt payloads if encrypted
// 3. Verify the signature
// Returns the envelope XML (after processing) and decrypted payloads.
func (sp *SecurityProcessor) VerifyAndDecryptEnvelope(envelopeXML []byte, payloads []Payload) ([]byte, []Payload, error) {
	// First verify the signature
	if err := sp.VerifyEnvelope(envelopeXML); err != nil {
		return nil, nil, err
	}

	// Check if message has encryption
	isEncrypted, err := security.IsMessageEncrypted(envelopeXML)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to check encryption: %w", err)
	}

	if !isEncrypted || sp.wssDecryptor == nil {
		// No encryption or no decryptor configured
		return envelopeXML, payloads, nil
	}

	// Parse envelope to extract EncryptedKey
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(envelopeXML); err != nil {
		return nil, nil, fmt.Errorf("failed to parse envelope: %w", err)
	}

	securityElem := doc.FindElement("//Security")
	if securityElem == nil {
		securityElem = doc.FindElement("//*[local-name()='Security']")
	}
	if securityElem == nil {
		return nil, nil, fmt.Errorf("Security header not found")
	}

	// Extract EncryptedKey
	encKey, _, err := security.ExtractEncryptedKey(securityElem)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract EncryptedKey: %w", err)
	}

	// Convert payloads to decryption input
	encryptedInputs := make([]security.EncryptedPayloadInput, len(payloads))
	for i, p := range payloads {
		origMime := ""
		if p.Properties != nil {
			origMime = p.Properties["OriginalMimeType"]
		}
		encryptedInputs[i] = security.EncryptedPayloadInput{
			ContentID:     p.ContentID,
			EncryptedData: p.Data,
			OriginalMime:  origMime,
		}
	}

	// Decrypt payloads
	decResult, err := sp.wssDecryptor.DecryptPayloads(encKey, encryptedInputs)
	if err != nil {
		return nil, nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Convert decrypted payloads back
	decryptedPayloads := make([]Payload, len(decResult.DecryptedPayloads))
	for i, dp := range decResult.DecryptedPayloads {
		// Get original MIME type
		mimeType := dp.OriginalMime
		if mimeType == "" && i < len(payloads) && payloads[i].Properties != nil {
			mimeType = payloads[i].Properties["OriginalMimeType"]
		}
		if mimeType == "" {
			mimeType = "application/octet-stream"
		}

		decryptedPayloads[i] = Payload{
			ContentID:   dp.ContentID,
			ContentType: mimeType,
			Data:        dp.Data,
		}
	}

	return envelopeXML, decryptedPayloads, nil
}
