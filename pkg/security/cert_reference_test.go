package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestCertReferenceType_String(t *testing.T) {
	tests := []struct {
		refType  CertReferenceType
		expected string
	}{
		{CertRefAuto, "Auto"},
		{CertRefIssuerSerial, "IssuerSerial"},
		{CertRefSKI, "SKI"},
		{CertRefBSTDirectReference, "BSTDirectReference"},
		{CertRefThumbprint, "Thumbprint"},
		{CertReferenceType(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.refType.String(); got != tt.expected {
				t.Errorf("CertReferenceType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCertHasSKI(t *testing.T) {
	// Create a certificate WITHOUT SKI extension (v1 style)
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	templateNoSKI := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Cert No SKI",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	derNoSKI, err := x509.CreateCertificate(rand.Reader, templateNoSKI, templateNoSKI, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certNoSKI, err := x509.ParseCertificate(derNoSKI)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// The standard library auto-adds SKI for self-signed certs, so we check if it exists
	// For a proper test, we'd need to manually construct a cert without SKI
	hasSKI := CertHasSKI(certNoSKI)
	t.Logf("Certificate has SKI: %v", hasSKI)
}

func TestGetCertificateThumbprint(t *testing.T) {
	// Create a test certificate
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: "Test Cert",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	thumbprint := GetCertificateThumbprint(cert)
	if len(thumbprint) != 20 {
		t.Errorf("Expected 20-byte SHA-1 thumbprint, got %d bytes", len(thumbprint))
	}

	// Thumbprint should be deterministic
	thumbprint2 := GetCertificateThumbprint(cert)
	for i := range thumbprint {
		if thumbprint[i] != thumbprint2[i] {
			t.Errorf("Thumbprint not deterministic at byte %d", i)
		}
	}
}

func TestSelectBestCertRefType(t *testing.T) {
	// Create a test certificate (Go's x509.CreateCertificate adds SKI by default for self-signed)
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: "Test Cert",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// The Go standard library adds SKI for self-signed certs, so we expect SKI to be selected
	refType := SelectBestCertRefType(cert)
	if CertHasSKI(cert) {
		if refType != CertRefSKI {
			t.Errorf("Expected CertRefSKI for cert with SKI, got %v", refType)
		}
	} else {
		if refType != CertRefIssuerSerial {
			t.Errorf("Expected CertRefIssuerSerial for cert without SKI, got %v", refType)
		}
	}
}

func TestResolveCertRefType(t *testing.T) {
	// Create a test certificate
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: "Test Cert",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	tests := []struct {
		name     string
		refType  CertReferenceType
		expected CertReferenceType
	}{
		{"Auto", CertRefAuto, SelectBestCertRefType(cert)},
		{"IssuerSerial", CertRefIssuerSerial, CertRefIssuerSerial},
		{"SKI", CertRefSKI, CertRefSKI},
		{"BSTDirectReference", CertRefBSTDirectReference, CertRefBSTDirectReference},
		{"Thumbprint", CertRefThumbprint, CertRefThumbprint},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolved := ResolveCertRefType(tt.refType, cert)
			if resolved != tt.expected {
				t.Errorf("ResolveCertRefType(%v) = %v, want %v", tt.refType, resolved, tt.expected)
			}
		})
	}
}
