// Package security implements WS-Security decryption for AS4 messages.
// This file provides WS-Security level decryption that works with
// SOAP message security headers per WS-Security 1.1.1 and SwA Profile.
package security

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"

	"github.com/beevik/etree"
	"github.com/leifj/signedxml/xmlenc"
)

// WSSDecryptor handles WS-Security XML decryption for AS4 messages.
// It extracts EncryptedKey from the Security header and decrypts
// MIME attachment payloads using X25519 key agreement and AES-GCM.
type WSSDecryptor struct {
	privateKey *ecdh.PrivateKey
	hkdfInfo   []byte
}

// NewWSSDecryptor creates a new WS-Security decryptor.
// privateKey is the recipient's X25519 private key for key unwrapping.
// hkdfInfo should match the sender's HKDF info (default: "EU eDelivery AS4 2.0").
func NewWSSDecryptor(privateKey *ecdh.PrivateKey, hkdfInfo []byte) *WSSDecryptor {
	if hkdfInfo == nil {
		hkdfInfo = []byte("EU eDelivery AS4 2.0")
	}
	return &WSSDecryptor{
		privateKey: privateKey,
		hkdfInfo:   hkdfInfo,
	}
}

// DecryptionResult contains the results of decrypting payloads
type DecryptionResult struct {
	// DecryptedPayloads are the decrypted MIME parts
	DecryptedPayloads []DecryptedPayload
}

// DecryptedPayload represents a decrypted MIME payload
type DecryptedPayload struct {
	ContentID     string // Original Content-ID
	Data          []byte // Decrypted content
	OriginalMime  string // Original MIME type (from PartProperties)
}

// ExtractEncryptedKey extracts the xenc:EncryptedKey element from a WS-Security header.
// Returns the parsed EncryptedKey structure and the list of DataReference URIs.
func ExtractEncryptedKey(security *etree.Element) (*xmlenc.EncryptedKey, []string, error) {
	if security == nil {
		return nil, nil, fmt.Errorf("security element is nil")
	}

	// Find EncryptedKey element
	encKeyElem := security.FindElement("./EncryptedKey")
	if encKeyElem == nil {
		encKeyElem = security.FindElement("./*[local-name()='EncryptedKey']")
	}
	if encKeyElem == nil {
		return nil, nil, fmt.Errorf("EncryptedKey not found in Security header")
	}

	// Parse the EncryptedKey
	encKey, err := parseEncryptedKeyElement(encKeyElem)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse EncryptedKey: %w", err)
	}

	// Extract DataReference URIs
	var dataRefs []string
	refList := encKeyElem.FindElement("./ReferenceList")
	if refList == nil {
		refList = encKeyElem.FindElement("./*[local-name()='ReferenceList']")
	}
	if refList != nil {
		for _, dataRef := range refList.SelectElements("DataReference") {
			if uri := dataRef.SelectAttrValue("URI", ""); uri != "" {
				dataRefs = append(dataRefs, uri)
			}
		}
		// Also check with local-name
		for _, dataRef := range refList.FindElements("./*[local-name()='DataReference']") {
			if uri := dataRef.SelectAttrValue("URI", ""); uri != "" {
				// Avoid duplicates
				found := false
				for _, existing := range dataRefs {
					if existing == uri {
						found = true
						break
					}
				}
				if !found {
					dataRefs = append(dataRefs, uri)
				}
			}
		}
	}

	return encKey, dataRefs, nil
}

// parseEncryptedKeyElement parses an etree.Element into an xmlenc.EncryptedKey
func parseEncryptedKeyElement(elem *etree.Element) (*xmlenc.EncryptedKey, error) {
	ek := &xmlenc.EncryptedKey{}

	// Parse EncryptionMethod
	encMethodElem := elem.FindElement("./EncryptionMethod")
	if encMethodElem == nil {
		encMethodElem = elem.FindElement("./*[local-name()='EncryptionMethod']")
	}
	if encMethodElem != nil {
		ek.EncryptionMethod = &xmlenc.EncryptionMethod{
			Algorithm: encMethodElem.SelectAttrValue("Algorithm", ""),
		}
	}

	// Parse KeyInfo
	keyInfoElem := elem.FindElement("./KeyInfo")
	if keyInfoElem == nil {
		keyInfoElem = elem.FindElement("./*[local-name()='KeyInfo']")
	}
	if keyInfoElem != nil {
		ek.KeyInfo = &xmlenc.KeyInfo{}

		// Parse AgreementMethod
		amElem := keyInfoElem.FindElement("./AgreementMethod")
		if amElem == nil {
			amElem = keyInfoElem.FindElement("./*[local-name()='AgreementMethod']")
		}
		if amElem != nil {
			ek.KeyInfo.AgreementMethod = &xmlenc.AgreementMethod{
				Algorithm: amElem.SelectAttrValue("Algorithm", ""),
			}

			// Parse KeyDerivationMethod
			kdmElem := amElem.FindElement("./KeyDerivationMethod")
			if kdmElem == nil {
				kdmElem = amElem.FindElement("./*[local-name()='KeyDerivationMethod']")
			}
			if kdmElem != nil {
				ek.KeyInfo.AgreementMethod.KeyDerivationMethod = &xmlenc.KeyDerivationMethod{
					Algorithm: kdmElem.SelectAttrValue("Algorithm", ""),
				}

				// Parse HKDFParams
				hkdfElem := kdmElem.FindElement("./HKDFParams")
				if hkdfElem == nil {
					hkdfElem = kdmElem.FindElement("./*[local-name()='HKDFParams']")
				}
				if hkdfElem != nil {
					hkdfParams := &xmlenc.HKDFParams{}

					// PRF
					prfElem := hkdfElem.FindElement("./PRF")
					if prfElem == nil {
						prfElem = hkdfElem.FindElement("./*[local-name()='PRF']")
					}
					if prfElem != nil {
						hkdfParams.PRF = prfElem.SelectAttrValue("Algorithm", "")
					}

					// Salt
					saltElem := hkdfElem.FindElement("./Salt")
					if saltElem == nil {
						saltElem = hkdfElem.FindElement("./*[local-name()='Salt']")
					}
					if saltElem != nil {
						specifiedElem := saltElem.FindElement("./Specified")
						if specifiedElem == nil {
							specifiedElem = saltElem.FindElement("./*[local-name()='Specified']")
						}
						if specifiedElem != nil {
							salt, err := base64.StdEncoding.DecodeString(specifiedElem.Text())
							if err == nil {
								hkdfParams.Salt = salt
							}
						}
					}

					// Info
					infoElem := hkdfElem.FindElement("./Info")
					if infoElem == nil {
						infoElem = hkdfElem.FindElement("./*[local-name()='Info']")
					}
					if infoElem != nil {
						info, err := base64.StdEncoding.DecodeString(infoElem.Text())
						if err == nil {
							hkdfParams.Info = info
						}
					}

					// KeyLength
					keyLenElem := hkdfElem.FindElement("./KeyLength")
					if keyLenElem == nil {
						keyLenElem = hkdfElem.FindElement("./*[local-name()='KeyLength']")
					}
					if keyLenElem != nil {
						var keyLen int
						fmt.Sscanf(keyLenElem.Text(), "%d", &keyLen)
						hkdfParams.KeyLength = keyLen
					}

					ek.KeyInfo.AgreementMethod.KeyDerivationMethod.HKDFParams = hkdfParams
				}
			}

			// Parse OriginatorKeyInfo (contains ephemeral public key)
			origKeyInfoElem := amElem.FindElement("./OriginatorKeyInfo")
			if origKeyInfoElem == nil {
				origKeyInfoElem = amElem.FindElement("./*[local-name()='OriginatorKeyInfo']")
			}
			if origKeyInfoElem != nil {
				ek.KeyInfo.AgreementMethod.OriginatorKeyInfo = &xmlenc.KeyInfo{}

				// Parse KeyValue
				keyValueElem := origKeyInfoElem.FindElement("./KeyValue")
				if keyValueElem == nil {
					keyValueElem = origKeyInfoElem.FindElement("./*[local-name()='KeyValue']")
				}
				if keyValueElem != nil {
					ek.KeyInfo.AgreementMethod.OriginatorKeyInfo.KeyValue = &xmlenc.KeyValue{}

					// Parse ECKeyValue
					ecKeyElem := keyValueElem.FindElement("./ECKeyValue")
					if ecKeyElem == nil {
						ecKeyElem = keyValueElem.FindElement("./*[local-name()='ECKeyValue']")
					}
					if ecKeyElem != nil {
						ecKeyValue := &xmlenc.ECKeyValue{}

						// NamedCurve
						ncElem := ecKeyElem.FindElement("./NamedCurve")
						if ncElem == nil {
							ncElem = ecKeyElem.FindElement("./*[local-name()='NamedCurve']")
						}
						if ncElem != nil {
							ecKeyValue.NamedCurve = ncElem.SelectAttrValue("URI", "")
						}

						// PublicKey
						pkElem := ecKeyElem.FindElement("./PublicKey")
						if pkElem == nil {
							pkElem = ecKeyElem.FindElement("./*[local-name()='PublicKey']")
						}
						if pkElem != nil {
							pubKey, err := base64.StdEncoding.DecodeString(pkElem.Text())
							if err == nil {
								ecKeyValue.PublicKey = pubKey
							}
						}

						ek.KeyInfo.AgreementMethod.OriginatorKeyInfo.KeyValue.ECKeyValue = ecKeyValue
					}
				}
			}
		}
	}

	// Parse CipherData
	cipherDataElem := elem.FindElement("./CipherData")
	if cipherDataElem == nil {
		cipherDataElem = elem.FindElement("./*[local-name()='CipherData']")
	}
	if cipherDataElem != nil {
		cipherValueElem := cipherDataElem.FindElement("./CipherValue")
		if cipherValueElem == nil {
			cipherValueElem = cipherDataElem.FindElement("./*[local-name()='CipherValue']")
		}
		if cipherValueElem != nil {
			cipherValue, err := base64.StdEncoding.DecodeString(cipherValueElem.Text())
			if err != nil {
				return nil, fmt.Errorf("failed to decode CipherValue: %w", err)
			}
			ek.CipherData = &xmlenc.CipherData{
				CipherValue: cipherValue,
			}
		}
	}

	return ek, nil
}

// DecryptPayloads decrypts MIME payloads using the EncryptedKey from the Security header.
// The encryptedData should be the raw encrypted bytes from each MIME part.
func (d *WSSDecryptor) DecryptPayloads(encKey *xmlenc.EncryptedKey, encryptedPayloads []EncryptedPayloadInput) (*DecryptionResult, error) {
	if encKey == nil {
		return nil, fmt.Errorf("EncryptedKey is nil")
	}

	// Extract ephemeral public key from EncryptedKey
	if encKey.KeyInfo == nil || encKey.KeyInfo.AgreementMethod == nil ||
		encKey.KeyInfo.AgreementMethod.OriginatorKeyInfo == nil ||
		encKey.KeyInfo.AgreementMethod.OriginatorKeyInfo.KeyValue == nil ||
		encKey.KeyInfo.AgreementMethod.OriginatorKeyInfo.KeyValue.ECKeyValue == nil {
		return nil, fmt.Errorf("EncryptedKey missing ephemeral public key")
	}

	ephemeralPubBytes := encKey.KeyInfo.AgreementMethod.OriginatorKeyInfo.KeyValue.ECKeyValue.PublicKey
	ephemeralPublic, err := xmlenc.ParseX25519PublicKey(ephemeralPubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ephemeral public key: %w", err)
	}

	// Get HKDF parameters from EncryptedKey or use defaults
	hkdfParams := xmlenc.DefaultHKDFParams(d.hkdfInfo)
	if encKey.KeyInfo.AgreementMethod.KeyDerivationMethod != nil &&
		encKey.KeyInfo.AgreementMethod.KeyDerivationMethod.HKDFParams != nil {
		hkdfParams = encKey.KeyInfo.AgreementMethod.KeyDerivationMethod.HKDFParams
	}

	// Create key agreement for decryption
	keyAgreement := xmlenc.NewX25519KeyAgreementForDecrypt(d.privateKey, ephemeralPublic, hkdfParams)

	// Unwrap the CEK
	cek, err := keyAgreement.UnwrapKey(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap CEK: %w", err)
	}

	// Decrypt each payload
	decryptedPayloads := make([]DecryptedPayload, len(encryptedPayloads))

	for i, payload := range encryptedPayloads {
		// Decrypt with AES-GCM (ciphertext includes prepended nonce)
		plaintext, err := xmlenc.AESGCMDecrypt(cek, payload.EncryptedData, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt payload %s: %w", payload.ContentID, err)
		}

		decryptedPayloads[i] = DecryptedPayload{
			ContentID:    payload.ContentID,
			Data:         plaintext,
			OriginalMime: payload.OriginalMime,
		}
	}

	return &DecryptionResult{
		DecryptedPayloads: decryptedPayloads,
	}, nil
}

// EncryptedPayloadInput represents an encrypted payload to decrypt
type EncryptedPayloadInput struct {
	ContentID     string // Content-ID of the MIME part
	EncryptedData []byte // Raw encrypted bytes (with prepended nonce)
	OriginalMime  string // Original MIME type (from PartProperties if available)
}

// IsMessageEncrypted checks if an AS4 message has encryption in the Security header
func IsMessageEncrypted(envelopeXML []byte) (bool, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(envelopeXML); err != nil {
		return false, fmt.Errorf("failed to parse envelope: %w", err)
	}

	// Find Security header
	security := doc.FindElement("//Security")
	if security == nil {
		security = doc.FindElement("//*[local-name()='Security']")
	}
	if security == nil {
		return false, nil
	}

	// Check for EncryptedKey
	encKey := security.FindElement("./EncryptedKey")
	if encKey == nil {
		encKey = security.FindElement("./*[local-name()='EncryptedKey']")
	}

	return encKey != nil, nil
}
