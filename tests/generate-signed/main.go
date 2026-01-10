package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/sirosfoundation/go-as4/pkg/message"
	"github.com/sirosfoundation/go-as4/pkg/pmode"
	"github.com/sirosfoundation/go-as4/pkg/security"
)

// This is a standalone program to generate a signed AS4 message for comparison with phase4
func main() {
	// Generate test certificate and key for signing
	cert, key, err := generateTestCert()
	if err != nil {
		log.Fatalf("Failed to generate test cert: %v", err)
	}

	// Create signer with PKCS#1 v1.5 (matching phase4)
	signer, err := security.NewRSASignerWithMode(key, cert, crypto.SHA256, crypto.SHA256, pmode.TokenRefBinarySecurityToken, security.SignatureModePKCS1v15)
	if err != nil {
		log.Fatalf("Failed to create signer: %v", err)
	}

	// Create a basic UserMessage with same parameters as phase4
	builder := message.NewUserMessage(
		message.WithFrom("go-as4", ""),
		message.WithFromRole("http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/initiator"),
		message.WithTo("domibus", ""),
		message.WithToRole("http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/responder"),
		message.WithService("http://test.example.org/service"),
		message.WithAction("TestAction"),
		message.WithConversationId("conv-"+generateID()),
	)

	envelope, _, err := builder.BuildEnvelope()
	if err != nil {
		log.Fatalf("Failed to build envelope: %v", err)
	}

	// Serialize to XML
	xmlData, err := xml.Marshal(envelope)
	if err != nil {
		log.Fatalf("Failed to marshal envelope: %v", err)
	}

	// Add eb: prefix to ebMS elements (required for compatibility with WSS4J/Domibus)
	xmlData, err = message.AddEbMSPrefix(xmlData)
	if err != nil {
		log.Fatalf("Failed to add eb: prefix: %v", err)
	}

	// Sign the message
	signedXML, err := signer.SignEnvelope(xmlData)
	if err != nil {
		log.Fatalf("Failed to sign envelope: %v", err)
	}

	// Verify our own signature
	if err := signer.VerifyEnvelope(signedXML); err != nil {
		log.Printf("WARNING: Self-verification failed: %v", err)
	} else {
		log.Println("✓ Self-verification passed")
	}

	// Write to file
	outputFile := "/tmp/go-signed-message.xml"
	if err := os.WriteFile(outputFile, signedXML, 0644); err != nil {
		log.Fatalf("Failed to write output: %v", err)
	}

	fmt.Printf("Signed message written to: %s\n", outputFile)
	fmt.Printf("Message size: %d bytes\n", len(signedXML))
}

func generateTestCert() (*x509.Certificate, *rsa.PrivateKey, error) {
	// Load fixed test certificate from file
	certPath := "../../certs/test.crt"
	keyPath := "../../certs/test.key"

	// Read certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Read private key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode private key PEM")
	}

	// Try PKCS1 first, then PKCS8
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Try PKCS8 format
		keyInterface, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		var ok bool
		key, ok = keyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("key is not RSA private key")
		}
	}

	return cert, key, nil
}

func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
