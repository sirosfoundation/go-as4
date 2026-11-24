package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/sirosfoundation/go-as4/pkg/pmode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateECDSATestCert generates a self-signed test ECDSA certificate on the given curve
func generateECDSATestCert(t *testing.T, curve elliptic.Curve) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

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

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return privateKey, cert
}

// generateECDSATestCertWithSKI generates a self-signed P-256 certificate with a
// SubjectKeyIdentifier extension (20 bytes) for KeyIdentifier token-ref tests
func generateECDSATestCertWithSKI(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte("01234567890123456789"), // 20 bytes
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return privateKey, cert
}

const ecdsaTestEnvelope = `<?xml version="1.0" encoding="UTF-8"?>
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
</soap:Envelope>`

func TestECDSASigner_SignAndVerifyEnvelope(t *testing.T) {
	privateKey, cert := generateECDSATestCert(t, elliptic.P256())

	signer, err := NewECDSASigner(privateKey, cert)
	require.NoError(t, err)
	require.NotNil(t, signer)

	signedXML, err := signer.SignEnvelope([]byte(ecdsaTestEnvelope))
	require.NoError(t, err)
	assert.NotEmpty(t, signedXML)

	signedStr := string(signedXML)
	assert.Contains(t, signedStr, "Signature")
	assert.Contains(t, signedStr, "SignatureValue")
	assert.Contains(t, signedStr, "BinarySecurityToken")
	assert.Contains(t, signedStr, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256")
	assert.Contains(t, signedStr, "http://www.w3.org/2001/10/xml-exc-c14n#")

	// Verify the signature (uses signedxml's validator: raw r||s -> ASN.1)
	err = signer.VerifyEnvelope(signedXML)
	require.NoError(t, err, "Signature verification should succeed")

	// The ECDSA signature value must be the raw r||s form:
	// 64 bytes (2 x 32) for P-256, not ASN.1 DER
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(signedXML))
	sigValue := doc.FindElement(".//SignatureValue")
	require.NotNil(t, sigValue)
	assert.NotContains(t, sigValue.Text(), "MIIB", "ECDSA signature must not be DER-encoded")
}

func TestECDSASigner_TamperDetection(t *testing.T) {
	privateKey, cert := generateECDSATestCert(t, elliptic.P256())

	signer, err := NewECDSASigner(privateKey, cert)
	require.NoError(t, err)

	signedXML, err := signer.SignEnvelope([]byte(ecdsaTestEnvelope))
	require.NoError(t, err)

	// Tamper with the signed content: change the message id text
	tampered := strings.Replace(string(signedXML), "test-message-123", "tampered-message", 1)
	require.NotEqual(t, string(signedXML), tampered)

	err = signer.VerifyEnvelope([]byte(tampered))
	require.Error(t, err, "Tampered message must fail verification")
	assert.Contains(t, err.Error(), "digest")

	// Tamper with the signature value itself
	flipByte := strings.Replace(string(signedXML), "<ds:SignatureValue>", "<ds:SignatureValue>A", 1)
	err = signer.VerifyEnvelope([]byte(flipByte))
	require.Error(t, err, "Modified signature value must fail verification")
}

func TestECDSASigner_WrongKeyVerification(t *testing.T) {
	privateKey, cert := generateECDSATestCert(t, elliptic.P256())
	otherKey, otherCert := generateECDSATestCert(t, elliptic.P256())

	signer, err := NewECDSASigner(privateKey, cert)
	require.NoError(t, err)

	signedXML, err := signer.SignEnvelope([]byte(ecdsaTestEnvelope))
	require.NoError(t, err)

	// Verify with a different certificate - must fail
	verifier, err := NewECDSAVerifier(otherCert)
	require.NoError(t, err)
	_ = otherKey

	err = verifier.VerifyEnvelope(signedXML)
	require.Error(t, err, "Verification with wrong certificate must fail")
}

func TestECDSASigner_CurveSelection(t *testing.T) {
	testCases := []struct {
		name    string
		curve   elliptic.Curve
		algoURI string
	}{
		{"P-256", elliptic.P256(), "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"},
		{"P-384", elliptic.P384(), "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"},
		{"P-521", elliptic.P521(), "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			privateKey, cert := generateECDSATestCert(t, tc.curve)

			signer, err := NewECDSASigner(privateKey, cert)
			require.NoError(t, err)

			signedXML, err := signer.SignEnvelope([]byte(ecdsaTestEnvelope))
			require.NoError(t, err)
			assert.Contains(t, string(signedXML), tc.algoURI)

			err = signer.VerifyEnvelope(signedXML)
			require.NoError(t, err)
		})
	}
}

func TestECDSASigner_RejectsUnsupportedCurve(t *testing.T) {
	// P-224 is a valid ECDSA curve that we deliberately do not support
	privateKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "p224.example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	_, err = NewECDSASigner(privateKey, cert)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported ECDSA curve")
	assert.Contains(t, err.Error(), "P-224")
}

func TestECDSASigner_TokenReferenceMethods(t *testing.T) {
	privateKey, cert := generateECDSATestCertWithSKI(t)

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
			expectAttrVal: "#X509-",
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
			signer, err := NewECDSASignerWithTokenRef(privateKey, cert, tc.tokenRef)
			require.NoError(t, err)

			signedXML, err := signer.SignEnvelope([]byte(ecdsaTestEnvelope))
			require.NoError(t, err)

			doc := etree.NewDocument()
			require.NoError(t, doc.ReadFromBytes(signedXML))

			// Check BinarySecurityToken presence
			bst := doc.FindElement(".//BinarySecurityToken")
			if tc.expectBST {
				require.NotNil(t, bst, "BinarySecurityToken expected")
			} else {
				assert.Nil(t, bst, "BinarySecurityToken not expected")
			}

			// Check the expected KeyInfo element
			elem := doc.FindElement(".//" + tc.expectElement)
			require.NotNil(t, elem, "Expected element %s", tc.expectElement)
			if tc.expectAttr != "" {
				assert.Contains(t, elem.SelectAttrValue(tc.expectAttr, ""), tc.expectAttrVal)
			}

			// Every token-ref mode must produce a verifiable signature
			err = signer.VerifyEnvelope(signedXML)
			require.NoError(t, err, "Signature with %s token reference must verify", tc.name)
		})
	}
}

func TestECDSASigner_SignEnvelopeWithAttachments(t *testing.T) {
	privateKey, cert := generateECDSATestCert(t, elliptic.P256())

	signer, err := NewECDSASigner(privateKey, cert)
	require.NoError(t, err)

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

	signedXML, err := signer.SignEnvelopeWithAttachments([]byte(ecdsaTestEnvelope), attachments)
	require.NoError(t, err)

	signedStr := string(signedXML)
	assert.Contains(t, signedStr, "cid:payload-1@as4.siros.org")
	assert.Contains(t, signedStr, "cid:payload-2@as4.siros.org")
	assert.Contains(t, signedStr, "Attachment-Content-Signature-Transform")

	// cid: references carry pre-computed digests (not "placeholder")
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(signedXML))
	for _, ref := range doc.FindElements(".//Reference") {
		uri := ref.SelectAttrValue("URI", "")
		if strings.HasPrefix(uri, "cid:") {
			digest := ref.SelectElement("DigestValue")
			require.NotNil(t, digest)
			assert.NotEqual(t, "placeholder", digest.Text())
			assert.NotEmpty(t, digest.Text())
		}
	}

	err = signer.VerifyEnvelopeWithAttachments(signedXML, attachments)
	require.NoError(t, err, "Signature with attachments must verify")
}

func TestECDSASigner_RejectsRSACertAndKey(t *testing.T) {
	privateKey, cert := generateECDSATestCert(t, elliptic.P256())

	// RSA cert with ECDSA key must fail
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaCert := generateRSATestCert(t, &rsaKey.PublicKey, rsaKey)

	_, err = NewECDSASigner(privateKey, rsaCert)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ECDSA public key")

	// nil key must fail
	_, err = NewECDSASigner(nil, cert)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "private key is required")

	// nil cert must fail
	_, err = NewECDSASigner(privateKey, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate is required")
}

func TestFactory_ECDSASigner(t *testing.T) {
	privateKey, cert := generateECDSATestCert(t, elliptic.P256())

	factory := &SignerFactory{}
	config := &pmode.SignConfig{
		Algorithm:      pmode.AlgoECDSASHA256,
		TokenReference: pmode.TokenRefKeyIdentifier,
	}

	signer, err := factory.NewSigner(config, privateKey, cert)
	require.NoError(t, err)
	require.NotNil(t, signer)

	signedXML, err := signer.SignEnvelope([]byte(ecdsaTestEnvelope))
	require.NoError(t, err)
	assert.Contains(t, string(signedXML), "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256")

	err = signer.VerifyEnvelope(signedXML)
	require.NoError(t, err)
}

func TestFactory_ECDSA_RejectsNonP256(t *testing.T) {
	privateKey, cert := generateECDSATestCert(t, elliptic.P384())

	factory := &SignerFactory{}
	config := &pmode.SignConfig{
		Algorithm:      pmode.AlgoECDSASHA256,
		TokenReference: pmode.TokenRefBinarySecurityToken,
	}

	_, err := factory.NewSigner(config, privateKey, cert)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "P-256")
	assert.Contains(t, err.Error(), "P-384")

	// Wrong key type must fail with a clear message
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, err = factory.NewSigner(config, rsaKey, cert)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected *ecdsa.PrivateKey")
}

func TestFactory_ECDSA_RejectsNilConfig(t *testing.T) {
	privateKey, cert := generateECDSATestCert(t, elliptic.P256())
	factory := &SignerFactory{}
	_, err := factory.NewSigner(nil, privateKey, cert)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sign config is required")
}
