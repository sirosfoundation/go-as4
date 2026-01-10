// Package security implements WS-Security encryption for AS4 messages.
// This file provides WS-Security level encryption that integrates with
// SOAP message security headers per WS-Security 1.1.1 and SwA Profile.
package security

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/beevik/etree"
	"github.com/leifj/signedxml/xmlenc"
)

// WSSEncryptor handles WS-Security XML encryption for AS4 messages.
// It creates EncryptedKey elements in the Security header and encrypts
// MIME attachment payloads using X25519 key agreement and AES-128-GCM.
type WSSEncryptor struct {
	recipientPublicKey *ecdh.PublicKey
	hkdfInfo           []byte
	contentAlgorithm   string
}

// WSSEncryptionOptions configures encryption behavior
type WSSEncryptionOptions struct {
	// ContentAlgorithm is the content encryption algorithm (default: AES-128-GCM)
	ContentAlgorithm string
	// HKDFInfo is context info for HKDF key derivation
	HKDFInfo []byte
}

// DefaultWSSEncryptionOptions returns default encryption options for EU AS4 2.0
func DefaultWSSEncryptionOptions() *WSSEncryptionOptions {
	return &WSSEncryptionOptions{
		ContentAlgorithm: xmlenc.AlgorithmAES128GCM,
		HKDFInfo:         []byte("EU eDelivery AS4 2.0"),
	}
}

// NewWSSEncryptor creates a new WS-Security encryptor.
// recipientPublicKey is the recipient's X25519 public key for key agreement.
// opts can be nil to use default options.
func NewWSSEncryptor(recipientPublicKey *ecdh.PublicKey, opts *WSSEncryptionOptions) *WSSEncryptor {
	if opts == nil {
		opts = DefaultWSSEncryptionOptions()
	}
	if opts.ContentAlgorithm == "" {
		opts.ContentAlgorithm = xmlenc.AlgorithmAES128GCM
	}
	if opts.HKDFInfo == nil {
		opts.HKDFInfo = []byte("EU eDelivery AS4 2.0")
	}
	return &WSSEncryptor{
		recipientPublicKey: recipientPublicKey,
		hkdfInfo:           opts.HKDFInfo,
		contentAlgorithm:   opts.ContentAlgorithm,
	}
}

// WSSEncryptedPayload represents an encrypted MIME payload for WS-Security
type WSSEncryptedPayload struct {
	ContentID       string // Original Content-ID (cid:xxx)
	EncryptedData   []byte // AES-GCM encrypted content
	Nonce           []byte // GCM nonce (prepended to ciphertext by AESGCMEncrypt)
	OriginalMime    string // Original MIME type
	EncryptedMime   string // Always "application/octet-stream" for encrypted
	DataReferenceID string // ID for xenc:DataReference (without # prefix)
}

// EncryptionResult contains the results of encrypting payloads
type EncryptionResult struct {
	// EncryptedKey is the xenc:EncryptedKey element for the Security header
	EncryptedKey *xmlenc.EncryptedKey
	// EncryptedPayloads are the encrypted MIME parts
	EncryptedPayloads []WSSEncryptedPayload
	// CEK is the content encryption key (for reference, should not be stored)
	CEK []byte
}

// EncryptPayloads encrypts MIME payloads and generates an EncryptedKey for the Security header.
// Each payload is encrypted with the same CEK (Content Encryption Key).
// Returns the EncryptedKey structure to add to the Security header and encrypted payload data.
func (e *WSSEncryptor) EncryptPayloads(payloads []PayloadData) (*EncryptionResult, error) {
	if len(payloads) == 0 {
		return nil, fmt.Errorf("no payloads to encrypt")
	}

	// Determine CEK size from content algorithm
	keySize := xmlenc.KeySize(e.contentAlgorithm)
	if keySize == 0 {
		return nil, fmt.Errorf("unsupported content encryption algorithm: %s", e.contentAlgorithm)
	}

	// Generate Content Encryption Key (CEK)
	cek := make([]byte, keySize)
	if _, err := rand.Read(cek); err != nil {
		return nil, fmt.Errorf("failed to generate CEK: %w", err)
	}

	// Create X25519 key agreement for wrapping the CEK
	hkdfParams := xmlenc.DefaultHKDFParams(e.hkdfInfo)
	keyAgreement, err := xmlenc.NewX25519KeyAgreement(e.recipientPublicKey, hkdfParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create key agreement: %w", err)
	}

	// Wrap the CEK
	wrapAlgorithm := xmlenc.KeyWrapAlgorithmForContentAlgorithm(e.contentAlgorithm)
	encryptedKey, err := keyAgreement.WrapKey(cek, wrapAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap CEK: %w", err)
	}

	// Encrypt each payload
	encryptedPayloads := make([]WSSEncryptedPayload, len(payloads))
	dataReferences := make([]xmlenc.DataReference, len(payloads))

	for i, payload := range payloads {
		// Generate unique ID for the encrypted data
		dataRefID := fmt.Sprintf("ED-%s", generateID())

		// Encrypt payload data with AES-GCM
		// AESGCMEncrypt prepends the nonce to the ciphertext
		ciphertext, err := xmlenc.AESGCMEncrypt(cek, payload.Data, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt payload %s: %w", payload.ContentID, err)
		}

		encryptedPayloads[i] = WSSEncryptedPayload{
			ContentID:       payload.ContentID,
			EncryptedData:   ciphertext, // Includes prepended nonce
			OriginalMime:    payload.MimeType,
			EncryptedMime:   "application/octet-stream",
			DataReferenceID: dataRefID,
		}

		// Add data reference to EncryptedKey's ReferenceList
		dataReferences[i] = xmlenc.DataReference{
			URI: "#" + dataRefID,
		}
	}

	// Add ReferenceList to EncryptedKey
	encryptedKey.ReferenceList = dataReferences

	return &EncryptionResult{
		EncryptedKey:      encryptedKey,
		EncryptedPayloads: encryptedPayloads,
		CEK:               cek,
	}, nil
}

// PayloadData represents a payload to be encrypted
type PayloadData struct {
	ContentID string // Content-ID header value (without angle brackets)
	MimeType  string // MIME type of the payload
	Data      []byte // Raw payload data
}

// AddEncryptedKeyToSecurityHeader adds an EncryptedKey element to the WS-Security header.
// The EncryptedKey should be added after the Signature element per WS-Security guidelines.
func AddEncryptedKeyToSecurityHeader(security *etree.Element, encKey *xmlenc.EncryptedKey) error {
	if security == nil {
		return fmt.Errorf("security element is nil")
	}
	if encKey == nil {
		return fmt.Errorf("encrypted key is nil")
	}

	// Generate unique ID for the EncryptedKey
	encKeyID := "EK-" + generateID()

	// Convert EncryptedKey to XML element
	encKeyElem := encryptedKeyToElement(encKey, encKeyID)

	// Add to Security header (after Signature if present)
	sig := security.FindElement("./Signature")
	if sig == nil {
		sig = security.FindElement("./*[local-name()='Signature']")
	}

	if sig != nil {
		// Insert after Signature
		sigIndex := -1
		for i, child := range security.ChildElements() {
			if child == sig {
				sigIndex = i
				break
			}
		}
		if sigIndex >= 0 && sigIndex < len(security.ChildElements())-1 {
			// Insert after signature
			security.InsertChildAt(sigIndex+1, encKeyElem)
		} else {
			security.AddChild(encKeyElem)
		}
	} else {
		// No signature, just append
		security.AddChild(encKeyElem)
	}

	return nil
}

// encryptedKeyToElement converts an xmlenc.EncryptedKey to an etree.Element
func encryptedKeyToElement(ek *xmlenc.EncryptedKey, id string) *etree.Element {
	// Create xenc:EncryptedKey element
	encKeyElem := etree.NewElement("xenc:EncryptedKey")
	encKeyElem.CreateAttr("xmlns:xenc", NSXMLEnc)
	encKeyElem.CreateAttr("xmlns:xenc11", "http://www.w3.org/2009/xmlenc11#")
	encKeyElem.CreateAttr("xmlns:dsig-more", "http://www.w3.org/2021/04/xmldsig-more#")
	encKeyElem.CreateAttr("xmlns:dsig11", "http://www.w3.org/2009/xmldsig11#")
	encKeyElem.CreateAttr("Id", id)

	// Add EncryptionMethod
	if ek.EncryptionMethod != nil {
		encMethod := encKeyElem.CreateElement("xenc:EncryptionMethod")
		encMethod.CreateAttr("Algorithm", ek.EncryptionMethod.Algorithm)
	}

	// Add KeyInfo with AgreementMethod
	if ek.KeyInfo != nil {
		keyInfo := encKeyElem.CreateElement("ds:KeyInfo")
		keyInfo.CreateAttr("xmlns:ds", NSXMLDSig)

		if ek.KeyInfo.AgreementMethod != nil {
			am := ek.KeyInfo.AgreementMethod
			agreementMethod := keyInfo.CreateElement("xenc:AgreementMethod")
			agreementMethod.CreateAttr("Algorithm", am.Algorithm)

			// Add KeyDerivationMethod (xenc11:KeyDerivationMethod)
			if am.KeyDerivationMethod != nil {
				kdm := am.KeyDerivationMethod
				kdfElem := agreementMethod.CreateElement("xenc11:KeyDerivationMethod")
				kdfElem.CreateAttr("Algorithm", kdm.Algorithm)

				// Add HKDF parameters
				if kdm.HKDFParams != nil {
					hkdfElem := kdfElem.CreateElement("dsig-more:HKDFParams")
					if kdm.HKDFParams.PRF != "" {
						prfElem := hkdfElem.CreateElement("dsig-more:PRF")
						prfElem.CreateAttr("Algorithm", kdm.HKDFParams.PRF)
					}
					if kdm.HKDFParams.Salt != nil {
						saltElem := hkdfElem.CreateElement("dsig-more:Salt")
						saltElem.CreateElement("dsig-more:Specified").SetText(
							base64.StdEncoding.EncodeToString(kdm.HKDFParams.Salt))
					}
					if kdm.HKDFParams.Info != nil {
						infoElem := hkdfElem.CreateElement("dsig-more:Info")
						infoElem.SetText(base64.StdEncoding.EncodeToString(kdm.HKDFParams.Info))
					}
					if kdm.HKDFParams.KeyLength > 0 {
						keyLenElem := hkdfElem.CreateElement("dsig-more:KeyLength")
						keyLenElem.SetText(fmt.Sprintf("%d", kdm.HKDFParams.KeyLength))
					}
				}
			}

			// Add OriginatorKeyInfo with ephemeral public key
			if am.OriginatorKeyInfo != nil && am.OriginatorKeyInfo.KeyValue != nil &&
				am.OriginatorKeyInfo.KeyValue.ECKeyValue != nil {
				origKeyInfo := agreementMethod.CreateElement("xenc:OriginatorKeyInfo")
				keyValue := origKeyInfo.CreateElement("ds:KeyValue")
				ecKeyValue := keyValue.CreateElement("dsig11:ECKeyValue")

				// Named curve
				namedCurve := ecKeyValue.CreateElement("dsig11:NamedCurve")
				namedCurve.CreateAttr("URI", am.OriginatorKeyInfo.KeyValue.ECKeyValue.NamedCurve)

				// Public key
				pubKey := ecKeyValue.CreateElement("dsig11:PublicKey")
				pubKey.SetText(base64.StdEncoding.EncodeToString(
					am.OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey))
			}

			// Add RecipientKeyInfo with recipient's static public key
			if am.RecipientKeyInfo != nil && am.RecipientKeyInfo.KeyValue != nil &&
				am.RecipientKeyInfo.KeyValue.ECKeyValue != nil {
				recipKeyInfo := agreementMethod.CreateElement("xenc:RecipientKeyInfo")
				keyValue := recipKeyInfo.CreateElement("ds:KeyValue")
				ecKeyValue := keyValue.CreateElement("dsig11:ECKeyValue")

				// Named curve
				namedCurve := ecKeyValue.CreateElement("dsig11:NamedCurve")
				namedCurve.CreateAttr("URI", am.RecipientKeyInfo.KeyValue.ECKeyValue.NamedCurve)

				// Public key
				pubKey := ecKeyValue.CreateElement("dsig11:PublicKey")
				pubKey.SetText(base64.StdEncoding.EncodeToString(
					am.RecipientKeyInfo.KeyValue.ECKeyValue.PublicKey))
			}
		}
	}

	// Add CipherData
	if ek.CipherData != nil && ek.CipherData.CipherValue != nil {
		cipherData := encKeyElem.CreateElement("xenc:CipherData")
		cipherValue := cipherData.CreateElement("xenc:CipherValue")
		cipherValue.SetText(base64.StdEncoding.EncodeToString(ek.CipherData.CipherValue))
	}

	// Add ReferenceList
	if len(ek.ReferenceList) > 0 {
		refList := encKeyElem.CreateElement("xenc:ReferenceList")
		for _, ref := range ek.ReferenceList {
			dataRef := refList.CreateElement("xenc:DataReference")
			dataRef.CreateAttr("URI", ref.URI)
		}
	}

	return encKeyElem
}

// CreateEncryptedDataElement creates an xenc:EncryptedData element for MIME part metadata.
// This is used in the SOAP body or as a reference element, not for the actual encrypted bytes.
// The actual encrypted bytes are in the MIME part itself.
func CreateEncryptedDataElement(id string, mimeType string, cipherRef string) *etree.Element {
	ed := etree.NewElement("xenc:EncryptedData")
	ed.CreateAttr("xmlns:xenc", NSXMLEnc)
	ed.CreateAttr("Id", id)
	ed.CreateAttr("MimeType", mimeType)
	ed.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Content")

	// EncryptionMethod
	encMethod := ed.CreateElement("xenc:EncryptionMethod")
	encMethod.CreateAttr("Algorithm", xmlenc.AlgorithmAES128GCM)

	// CipherData with CipherReference (pointing to MIME part)
	cipherData := ed.CreateElement("xenc:CipherData")
	cipherReference := cipherData.CreateElement("xenc:CipherReference")
	cipherReference.CreateAttr("URI", cipherRef)

	// Add SwA transform to indicate attachment content
	transforms := cipherReference.CreateElement("xenc:Transforms")
	transform := transforms.CreateElement("ds:Transform")
	transform.CreateAttr("xmlns:ds", NSXMLDSig)
	transform.CreateAttr("Algorithm", "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Ciphertext-Transform")

	return ed
}
