package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/sirosfoundation/go-as4/pkg/security"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <signed-xml-file>")
		os.Exit(1)
	}

	signedXMLPath := os.Args[1]
	certPath := "certs/test.crt" // Use certs directory at root

	// Read signed XML
	signedXML, err := os.ReadFile(signedXMLPath)
	if err != nil {
		log.Fatalf("Failed to read signed XML: %v", err)
	}

	// Read certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		log.Fatalf("Failed to read certificate: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		log.Fatal("Failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}

	// Create verifier (try PKCS#1 v1.5 first) - no private key needed!
	log.Println("Attempting verification with PKCS#1 v1.5...")
	verifier, err := security.NewRSAVerifier(cert, crypto.SHA256, crypto.SHA256, security.SignatureModePKCS1v15)
	if err != nil {
		log.Fatalf("Failed to create verifier: %v", err)
	}

	err = verifier.VerifyEnvelope(signedXML)
	if err == nil {
		log.Println("✓ Signature verification PASSED with PKCS#1 v1.5")
		return
	}
	log.Printf("PKCS#1 v1.5 verification failed: %v", err)

	// Try PSS
	log.Println("Attempting verification with RSA-PSS...")
	verifier, err = security.NewRSAVerifier(cert, crypto.SHA256, crypto.SHA256, security.SignatureModePSS)
	if err != nil {
		log.Fatalf("Failed to create verifier: %v", err)
	}

	err = verifier.VerifyEnvelope(signedXML)
	if err == nil {
		log.Println("✓ Signature verification PASSED with RSA-PSS")
		return
	}
	log.Printf("RSA-PSS verification failed: %v", err)

	log.Fatal("✗ Both verification modes failed")
}
