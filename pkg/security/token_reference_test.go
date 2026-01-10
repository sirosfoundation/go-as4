package security

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/sirosfoundation/go-as4/pkg/pmode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCertWithSKI generates an RSA certificate with SubjectKeyIdentifier extension
func generateTestCertWithSKI(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create a certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Org"},
			Country:       []string{"US"},
			Province:      []string{"CA"},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"123 Test St"},
			PostalCode:    []string{"94105"},
			CommonName:    "test.example.com",
		},
		Issuer: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA Root",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Use Go's built-in SubjectKeyId field instead of manual extension
	// This will be properly encoded by x509.CreateCertificate
	template.SubjectKeyId = []byte("01234567890123456789") // 20 bytes

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return privateKey, cert
}

func TestRSASigner_TokenReferenceMethods(t *testing.T) {
	privateKey, cert := generateTestCertWithSKI(t)

	soapEnvelope := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
	<soap:Header/>
	<soap:Body>
		<TestMessage>Hello World</TestMessage>
	</soap:Body>
</soap:Envelope>`)

	testCases := []struct {
		name          string
		tokenRef      pmode.TokenReferenceMethod
		expectBST     bool
		expectElement string
		expectAttr    string
		expectAttrVal string
	}{
		{
			name:          "BinarySecurityToken",
			tokenRef:      pmode.TokenRefBinarySecurityToken,
			expectBST:     true,
			expectElement: "wsse:Reference",
			expectAttr:    "URI",
			expectAttrVal: "#X509-", // Will check prefix
		},
		{
			name:          "KeyIdentifier",
			tokenRef:      pmode.TokenRefKeyIdentifier,
			expectBST:     false,
			expectElement: "wsse:KeyIdentifier",
			expectAttr:    "ValueType",
			expectAttrVal: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier",
		},
		{
			name:          "IssuerSerial",
			tokenRef:      pmode.TokenRefIssuerSerial,
			expectBST:     false,
			expectElement: "ds:X509IssuerSerial",
			expectAttr:    "",
			expectAttrVal: "",
		},
		{
			name:          "Thumbprint",
			tokenRef:      pmode.TokenRefThumbprint,
			expectBST:     false,
			expectElement: "wsse:KeyIdentifier",
			expectAttr:    "ValueType",
			expectAttrVal: "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create signer with specific token reference method
			signer, err := NewRSASignerWithTokenRef(privateKey, cert, crypto.SHA256, crypto.SHA256, tc.tokenRef)
			require.NoError(t, err)

			// Sign envelope
			signedXML, err := signer.SignEnvelope(soapEnvelope)
			require.NoError(t, err)

			// Parse signed XML
			doc := etree.NewDocument()
			err = doc.ReadFromBytes(signedXML)
			require.NoError(t, err)

			// Check for BinarySecurityToken presence
			bst := doc.FindElement("//wsse:BinarySecurityToken")
			if tc.expectBST {
				assert.NotNil(t, bst, "BinarySecurityToken should be present")
			} else {
				assert.Nil(t, bst, "BinarySecurityToken should NOT be present")
			}

			// Find SecurityTokenReference
			secTokenRef := doc.FindElement("//wsse:SecurityTokenReference")
			require.NotNil(t, secTokenRef, "SecurityTokenReference should be present")

			// Find expected element
			elem := secTokenRef.FindElement(".//" + tc.expectElement)
			require.NotNil(t, elem, "Expected element %s should be present", tc.expectElement)

			// Check attribute if specified
			if tc.expectAttr != "" {
				attrVal := elem.SelectAttrValue(tc.expectAttr, "")
				if strings.HasPrefix(tc.expectAttrVal, "#X509-") {
					// For BinarySecurityToken, just check prefix
					assert.True(t, strings.HasPrefix(attrVal, "#X509-"), "URI should reference X509 token")
				} else {
					assert.Equal(t, tc.expectAttrVal, attrVal, "Attribute value should match")
				}
			}

			// Verify signature is valid
			err = signer.VerifyEnvelope(signedXML)
			assert.NoError(t, err, "Signature should be valid")
		})
	}
}

func TestRSASigner_KeyIdentifier_SKIExtraction(t *testing.T) {
	privateKey, cert := generateTestCertWithSKI(t)

	signer, err := NewRSASignerWithTokenRef(privateKey, cert, crypto.SHA256, crypto.SHA256, pmode.TokenRefKeyIdentifier)
	require.NoError(t, err)

	soapEnvelope := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
	<soap:Header/>
	<soap:Body>
		<TestMessage>Test</TestMessage>
	</soap:Body>
</soap:Envelope>`)

	signedXML, err := signer.SignEnvelope(soapEnvelope)
	require.NoError(t, err)

	// Parse and verify SKI value
	doc := etree.NewDocument()
	err = doc.ReadFromBytes(signedXML)
	require.NoError(t, err)

	keyID := doc.FindElement("//wsse:KeyIdentifier")
	require.NotNil(t, keyID)

	skiBase64 := keyID.Text()
	skiBytes, err := base64.StdEncoding.DecodeString(skiBase64)
	require.NoError(t, err)

	// Should be the value from our certificate extension
	assert.Equal(t, []byte("01234567890123456789"), skiBytes, "SKI should match certificate extension")
}

func TestRSASigner_IssuerSerial_Format(t *testing.T) {
	privateKey, cert := generateTestCertWithSKI(t)

	signer, err := NewRSASignerWithTokenRef(privateKey, cert, crypto.SHA256, crypto.SHA256, pmode.TokenRefIssuerSerial)
	require.NoError(t, err)

	soapEnvelope := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
	<soap:Header/>
	<soap:Body>
		<TestMessage>Test</TestMessage>
	</soap:Body>
</soap:Envelope>`)

	signedXML, err := signer.SignEnvelope(soapEnvelope)
	require.NoError(t, err)

	// Parse and verify IssuerSerial structure
	doc := etree.NewDocument()
	err = doc.ReadFromBytes(signedXML)
	require.NoError(t, err)

	issuerSerial := doc.FindElement("//ds:X509IssuerSerial")
	require.NotNil(t, issuerSerial)

	issuerName := issuerSerial.FindElement(".//ds:X509IssuerName")
	require.NotNil(t, issuerName)
	// For self-signed cert, issuer equals subject which contains "Test Org"
	assert.Contains(t, issuerName.Text(), "Test", "Issuer name should contain Test")

	serialNumber := issuerSerial.FindElement(".//ds:X509SerialNumber")
	require.NotNil(t, serialNumber)
	assert.Equal(t, cert.SerialNumber.String(), serialNumber.Text(), "Serial number should match")
}

func TestRSASigner_WithAttachments_TokenReference(t *testing.T) {
	privateKey, cert := generateTestCertWithSKI(t)

	signer, err := NewRSASignerWithTokenRef(privateKey, cert, crypto.SHA256, crypto.SHA256, pmode.TokenRefKeyIdentifier)
	require.NoError(t, err)

	soapEnvelope := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
	<soap:Header/>
	<soap:Body>
		<TestMessage>Test</TestMessage>
	</soap:Body>
</soap:Envelope>`)

	attachments := []Attachment{
		{
			ContentID:   "<payload-1@as4.siros.org>",
			ContentType: "text/xml",
			Data:        []byte("<Document>Test Payload</Document>"),
		},
	}

	signedXML, err := signer.SignEnvelopeWithAttachments(soapEnvelope, attachments)
	require.NoError(t, err)

	// Parse and verify KeyIdentifier is used (not BinarySecurityToken)
	doc := etree.NewDocument()
	err = doc.ReadFromBytes(signedXML)
	require.NoError(t, err)

	// BinarySecurityToken should NOT be present
	bst := doc.FindElement("//wsse:BinarySecurityToken")
	assert.Nil(t, bst, "BinarySecurityToken should NOT be present with KeyIdentifier method")

	// KeyIdentifier should be present
	keyID := doc.FindElement("//wsse:KeyIdentifier")
	assert.NotNil(t, keyID, "KeyIdentifier should be present")

	// Check for attachment reference
	refs := doc.FindElements("//ds:Reference")
	var attachmentRef *etree.Element
	for _, ref := range refs {
		uri := ref.SelectAttrValue("URI", "")
		if strings.HasPrefix(uri, "cid:") {
			attachmentRef = ref
			break
		}
	}
	require.NotNil(t, attachmentRef, "Attachment reference should be present")
}

func TestFactory_CreatesSignerWithTokenReference(t *testing.T) {
	privateKey, cert := generateTestCertWithSKI(t)

	config := &pmode.SignConfig{
		Algorithm:      pmode.AlgoRSASHA256,
		HashFunction:   pmode.HashSHA256,
		TokenReference: pmode.TokenRefIssuerSerial,
	}

	factory := &SignerFactory{}
	signer, err := factory.NewSigner(config, privateKey, cert)
	require.NoError(t, err)

	rsaSigner, ok := signer.(*RSASigner)
	require.True(t, ok, "Should return RSASigner")

	assert.Equal(t, pmode.TokenRefIssuerSerial, rsaSigner.tokenReference, "Token reference should be configured")

	// Test signing
	soapEnvelope := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
	<soap:Header/>
	<soap:Body>
		<TestMessage>Test</TestMessage>
	</soap:Body>
</soap:Envelope>`)

	signedXML, err := signer.SignEnvelope(soapEnvelope)
	require.NoError(t, err)

	// Verify IssuerSerial is used
	doc := etree.NewDocument()
	err = doc.ReadFromBytes(signedXML)
	require.NoError(t, err)

	issuerSerial := doc.FindElement("//ds:X509IssuerSerial")
	assert.NotNil(t, issuerSerial, "X509IssuerSerial should be present")
}
