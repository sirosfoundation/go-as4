package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzenclient"
	"github.com/sirosfoundation/go-trust/pkg/testserver"
)

// generateTestCertificate creates a self-signed certificate for testing
func generateTestCertificate(commonName string) (*x509.Certificate, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

func TestAuthZENTrustValidator_AcceptAll(t *testing.T) {
	// Create test server that accepts all requests
	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	// Create client pointing to test server
	client := authzenclient.New(srv.URL())

	// Create validator using the test client
	validator := NewAuthZENTrustValidatorWithClient(client)

	// Generate a test certificate
	cert, err := generateTestCertificate("test.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Validate - should succeed
	err = validator.ValidateCertificate(cert, nil, "signing")
	if err != nil {
		t.Errorf("Expected validation to succeed, got: %v", err)
	}
}

func TestAuthZENTrustValidator_RejectAll(t *testing.T) {
	// Create test server that rejects all requests
	srv := testserver.New(testserver.WithRejectAll())
	defer srv.Close()

	// Create client pointing to test server
	client := authzenclient.New(srv.URL())

	// Create validator using the test client
	validator := NewAuthZENTrustValidatorWithClient(client)

	// Generate a test certificate
	cert, err := generateTestCertificate("untrusted.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Validate - should fail
	err = validator.ValidateCertificate(cert, nil, "signing")
	if err == nil {
		t.Error("Expected validation to fail, but it succeeded")
	}
}

func TestAuthZENTrustValidator_NilCertificate(t *testing.T) {
	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	validator := NewAuthZENTrustValidatorWithClient(client)

	err := validator.ValidateCertificate(nil, nil, "")
	if err == nil {
		t.Error("Expected error for nil certificate")
	}
}

func TestAuthZENTrustValidator_EmptyChain(t *testing.T) {
	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	validator := NewAuthZENTrustValidatorWithClient(client)

	err := validator.ValidateCertificateChain(nil, "signing")
	if err == nil {
		t.Error("Expected error for empty certificate chain")
	}
}

func TestAuthZENTrustValidator_WithDefaultAction(t *testing.T) {
	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	validator := NewAuthZENTrustValidatorWithClient(client).WithDefaultAction("tls-server")

	cert, err := generateTestCertificate("server.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Validate with default action
	err = validator.ValidateCertificate(cert, nil, "")
	if err != nil {
		t.Errorf("Expected validation to succeed, got: %v", err)
	}
}

func TestDefaultCertificateValidator_Expired(t *testing.T) {
	// Create an expired certificate
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "expired.example.com",
		},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour), // Already expired
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	validator := NewDefaultCertificateValidator(x509.NewCertPool())

	err = validator.ValidateCertificate(cert, nil, "")
	if err != ErrCertificateExpired {
		t.Errorf("Expected ErrCertificateExpired, got: %v", err)
	}
}

func TestDefaultCertificateValidator_NotYetValid(t *testing.T) {
	// Create a certificate that's not yet valid
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "future.example.com",
		},
		NotBefore:             time.Now().Add(24 * time.Hour), // In the future
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	validator := NewDefaultCertificateValidator(x509.NewCertPool())

	err = validator.ValidateCertificate(cert, nil, "")
	if err != ErrCertificateNotYetValid {
		t.Errorf("Expected ErrCertificateNotYetValid, got: %v", err)
	}
}
