package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

// generateEd25519TestCert creates a self-signed Ed25519 certificate for testing
func generateEd25519TestCert() (*x509.Certificate, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "Ed25519 Test Certificate",
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

// TestEd25519SignerCreation tests creating an Ed25519 signer
func TestEd25519SignerCreation(t *testing.T) {
	cert, privKey, err := generateEd25519TestCert()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	signer, err := NewEd25519Signer(privKey, cert)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	if signer == nil {
		t.Fatal("signer is nil")
	}

	if signer.privateKey == nil {
		t.Error("private key not set")
	}

	if signer.cert == nil {
		t.Error("certificate not set")
	}
}

// TestEd25519SignEnvelope tests signing a SOAP envelope with Ed25519
func TestEd25519SignEnvelope(t *testing.T) {
	cert, privKey, err := generateEd25519TestCert()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	signer, err := NewEd25519Signer(privKey, cert)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Simple SOAP envelope
	envelope := `<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope">
    <env:Header>
        <eb3:Messaging xmlns:eb3="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
            <eb3:UserMessage>
                <eb3:MessageInfo>
                    <eb3:Timestamp>2026-01-09T12:00:00.000Z</eb3:Timestamp>
                    <eb3:MessageId>test-message-id@as4.test</eb3:MessageId>
                </eb3:MessageInfo>
            </eb3:UserMessage>
        </eb3:Messaging>
    </env:Header>
    <env:Body>
        <Payload>Test payload content</Payload>
    </env:Body>
</env:Envelope>`

	signedXML, err := signer.SignEnvelope([]byte(envelope))
	if err != nil {
		t.Fatalf("failed to sign envelope: %v", err)
	}

	signedStr := string(signedXML)

	// Verify the signed XML contains Ed25519 algorithm
	if !strings.Contains(signedStr, Ed25519SignatureAlgorithmURI) {
		t.Error("signed XML does not contain Ed25519 signature algorithm URI")
	}

	// Verify the signed XML contains SignatureValue
	if !strings.Contains(signedStr, "SignatureValue") {
		t.Error("signed XML does not contain SignatureValue")
	}

	// Verify the signed XML contains Security element
	if !strings.Contains(signedStr, "Security") {
		t.Error("signed XML does not contain Security element")
	}

	// Verify the signed XML contains BinarySecurityToken
	if !strings.Contains(signedStr, "BinarySecurityToken") {
		t.Error("signed XML does not contain BinarySecurityToken")
	}

	// Verify the signed XML contains Timestamp
	if !strings.Contains(signedStr, "Timestamp") {
		t.Error("signed XML does not contain Timestamp")
	}

	t.Logf("Signed XML length: %d bytes", len(signedXML))
}

// TestEd25519SignAndVerifyEnvelope tests signing and then verifying
func TestEd25519SignAndVerifyEnvelope(t *testing.T) {
	cert, privKey, err := generateEd25519TestCert()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	signer, err := NewEd25519Signer(privKey, cert)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Simple SOAP envelope
	envelope := `<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope">
    <env:Header>
        <eb3:Messaging xmlns:eb3="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
            <eb3:UserMessage>
                <eb3:MessageInfo>
                    <eb3:Timestamp>2026-01-09T12:00:00.000Z</eb3:Timestamp>
                    <eb3:MessageId>test-message-id@as4.test</eb3:MessageId>
                </eb3:MessageInfo>
            </eb3:UserMessage>
        </eb3:Messaging>
    </env:Header>
    <env:Body>
        <Payload>Test payload content</Payload>
    </env:Body>
</env:Envelope>`

	// Sign the envelope
	signedXML, err := signer.SignEnvelope([]byte(envelope))
	if err != nil {
		t.Fatalf("failed to sign envelope: %v", err)
	}

	// Verify the signature
	verifier, err := NewEd25519Verifier(cert)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	err = verifier.VerifyEnvelope(signedXML)
	if err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

// TestEd25519TamperedEnvelope tests that tampered envelopes are rejected
func TestEd25519TamperedEnvelope(t *testing.T) {
	cert, privKey, err := generateEd25519TestCert()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	signer, err := NewEd25519Signer(privKey, cert)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	envelope := `<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope">
    <env:Header>
        <eb3:Messaging xmlns:eb3="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
            <eb3:UserMessage>
                <eb3:MessageInfo>
                    <eb3:Timestamp>2026-01-09T12:00:00.000Z</eb3:Timestamp>
                    <eb3:MessageId>test-message-id@as4.test</eb3:MessageId>
                </eb3:MessageInfo>
            </eb3:UserMessage>
        </eb3:Messaging>
    </env:Header>
    <env:Body>
        <Payload>Original content</Payload>
    </env:Body>
</env:Envelope>`

	// Sign the envelope
	signedXML, err := signer.SignEnvelope([]byte(envelope))
	if err != nil {
		t.Fatalf("failed to sign envelope: %v", err)
	}

	// Tamper with the content
	tamperedXML := strings.Replace(string(signedXML), "Original content", "Tampered content", 1)

	// Verify should fail
	verifier, err := NewEd25519Verifier(cert)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	err = verifier.VerifyEnvelope([]byte(tamperedXML))
	if err == nil {
		t.Error("expected verification to fail for tampered envelope")
	}
}
