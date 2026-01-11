// Package sdk provides SMP extension parsing for Swedish SDK certificate publishing.
package sdk

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
)

// SMPExtension represents an SMP extension element
type SMPExtension struct {
	ExtensionID         string `xml:"ExtensionID"`
	ExtensionName       string `xml:"ExtensionName"`
	ExtensionAgencyID   string `xml:"ExtensionAgencyID"`
	ExtensionAgencyName string `xml:"ExtensionAgencyName"`
	ExtensionAgencyURI  string `xml:"ExtensionAgencyURI"`
	ExtensionVersionID  string `xml:"ExtensionVersionID"`
	Content             []byte `xml:",innerxml"` // Raw XML content
}

// CertificateExtension represents an SDK certificate publishing extension
type CertificateExtension struct {
	// Type is the certificate type (signing or encryption)
	Type string
	// Certificate is the parsed X.509 certificate
	Certificate *x509.Certificate
	// RawCertificate is the base64-encoded DER certificate
	RawCertificate string
}

// CertificatePublishingInfo contains certificates published in SMP for an endpoint
type CertificatePublishingInfo struct {
	// SigningCertificate for XML signatures
	SigningCertificate *x509.Certificate
	// EncryptionCertificate for XML encryption
	EncryptionCertificate *x509.Certificate
	// Extensions contains all parsed extensions
	Extensions []CertificateExtension
}

// ParseCertificateExtensions parses SDK certificate publishing extensions from SMP data
func ParseCertificateExtensions(extensionsXML []byte) (*CertificatePublishingInfo, error) {
	// The extension XML structure expected:
	// <Extension>
	//   <ExtensionID>urn:fdc:digg.se:edelivery:certpub</ExtensionID>
	//   ...
	//   <CertificateList>
	//     <Certificate type="urn:fdc:digg.se:edelivery:certpub:signing-cert">BASE64...</Certificate>
	//     <Certificate type="urn:fdc:digg.se:edelivery:certpub:encryption-cert">BASE64...</Certificate>
	//   </CertificateList>
	// </Extension>

	info := &CertificatePublishingInfo{
		Extensions: make([]CertificateExtension, 0),
	}

	// Parse the wrapper structure
	type certListEntry struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	}
	type extensionWrapper struct {
		ExtensionID     string          `xml:"ExtensionID"`
		CertificateList []certListEntry `xml:"CertificateList>Certificate"`
	}

	var wrapper extensionWrapper
	if err := xml.Unmarshal(extensionsXML, &wrapper); err != nil {
		// Try alternate structure where certificates are directly in extension content
		return parseAlternateCertFormat(extensionsXML)
	}

	// Check if this is a certificate publishing extension
	if wrapper.ExtensionID != ExtensionCertPub {
		return nil, fmt.Errorf("not a certificate publishing extension: %s", wrapper.ExtensionID)
	}

	for _, entry := range wrapper.CertificateList {
		cert, err := parseCertificateFromBase64(entry.Value)
		if err != nil {
			continue // Skip malformed certificates
		}

		ext := CertificateExtension{
			Type:           entry.Type,
			Certificate:    cert,
			RawCertificate: entry.Value,
		}
		info.Extensions = append(info.Extensions, ext)

		// Assign to appropriate field
		switch entry.Type {
		case ExtensionSigningCert:
			info.SigningCertificate = cert
		case ExtensionEncryptionCert:
			info.EncryptionCertificate = cert
		}
	}

	return info, nil
}

// parseAlternateCertFormat handles alternate certificate extension formats
func parseAlternateCertFormat(data []byte) (*CertificatePublishingInfo, error) {
	// Try parsing as a list of Extension elements
	type extensionList struct {
		Extensions []struct {
			ExtensionID string `xml:"ExtensionID"`
			Content     string `xml:",chardata"`
		} `xml:"Extension"`
	}

	var list extensionList
	if err := xml.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("failed to parse extension: %w", err)
	}

	info := &CertificatePublishingInfo{
		Extensions: make([]CertificateExtension, 0),
	}

	for _, ext := range list.Extensions {
		switch ext.ExtensionID {
		case ExtensionSigningCert:
			cert, err := parseCertificateFromBase64(ext.Content)
			if err == nil {
				info.SigningCertificate = cert
				info.Extensions = append(info.Extensions, CertificateExtension{
					Type:           ExtensionSigningCert,
					Certificate:    cert,
					RawCertificate: ext.Content,
				})
			}
		case ExtensionEncryptionCert:
			cert, err := parseCertificateFromBase64(ext.Content)
			if err == nil {
				info.EncryptionCertificate = cert
				info.Extensions = append(info.Extensions, CertificateExtension{
					Type:           ExtensionEncryptionCert,
					Certificate:    cert,
					RawCertificate: ext.Content,
				})
			}
		}
	}

	return info, nil
}

// parseCertificateFromBase64 decodes and parses a base64-encoded DER certificate
func parseCertificateFromBase64(b64 string) (*x509.Certificate, error) {
	// Remove any whitespace
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// EncodeCertificateForSMP encodes an X.509 certificate for SMP publishing
func EncodeCertificateForSMP(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Raw)
}

// GenerateCertificatePublishingExtension creates an SMP extension for certificate publishing
func GenerateCertificatePublishingExtension(signingCert, encryptionCert *x509.Certificate) ([]byte, error) {
	type certEntry struct {
		XMLName xml.Name `xml:"Certificate"`
		Type    string   `xml:"type,attr"`
		Value   string   `xml:",chardata"`
	}

	type extension struct {
		XMLName             xml.Name    `xml:"Extension"`
		ExtensionID         string      `xml:"ExtensionID"`
		ExtensionName       string      `xml:"ExtensionName"`
		ExtensionAgencyID   string      `xml:"ExtensionAgencyID"`
		ExtensionAgencyName string      `xml:"ExtensionAgencyName"`
		ExtensionAgencyURI  string      `xml:"ExtensionAgencyURI"`
		ExtensionVersionID  string      `xml:"ExtensionVersionID"`
		CertificateList     []certEntry `xml:"CertificateList>Certificate"`
	}

	ext := extension{
		ExtensionID:         ExtensionCertPub,
		ExtensionName:       "CertificatePub",
		ExtensionAgencyID:   "DIGG",
		ExtensionAgencyName: "Myndigheten för digital förvaltning",
		ExtensionAgencyURI:  "https://www.digg.se",
		ExtensionVersionID:  "1.0",
		CertificateList:     make([]certEntry, 0, 2),
	}

	if signingCert != nil {
		ext.CertificateList = append(ext.CertificateList, certEntry{
			Type:  ExtensionSigningCert,
			Value: EncodeCertificateForSMP(signingCert),
		})
	}

	if encryptionCert != nil {
		ext.CertificateList = append(ext.CertificateList, certEntry{
			Type:  ExtensionEncryptionCert,
			Value: EncodeCertificateForSMP(encryptionCert),
		})
	}

	return xml.MarshalIndent(ext, "", "  ")
}
