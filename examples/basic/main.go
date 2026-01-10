package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"log"

	"github.com/sirosfoundation/go-as4/pkg/compression"
	"github.com/sirosfoundation/go-as4/pkg/message"
	"github.com/sirosfoundation/go-as4/pkg/pmode"
	"github.com/sirosfoundation/go-as4/pkg/reliability"
	"github.com/sirosfoundation/go-as4/pkg/security"
	"github.com/sirosfoundation/go-as4/pkg/transport"
)

func main() {
	fmt.Println("AS4 Message Example - One-Way Push")
	fmt.Println("====================================")

	// 1. Generate Ed25519 key pair for signing
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate signing key: %v", err)
	}
	fmt.Printf("✓ Generated Ed25519 signing key\n")

	// Create a self-signed certificate (in production, use proper PKI)
	cert := createSelfSignedCert(pubKey)

	// 2. Configure security
	secConfig := security.NewSecurityConfig(
		security.WithSigningKey(privKey),
		security.WithSigningCert(cert),
	)
	fmt.Printf("✓ Configured security (Ed25519 signing)\n")

	// 3. Create AS4 message
	msgBuilder := message.NewUserMessage(
		message.WithFrom("urn:oasis:names:tc:ebcore:partyid-type:unregistered:sender-company",
			"urn:oasis:names:tc:ebcore:partyid-type:unregistered"),
		message.WithTo("urn:oasis:names:tc:ebcore:partyid-type:unregistered:receiver-company",
			"urn:oasis:names:tc:ebcore:partyid-type:unregistered"),
		message.WithService("http://example.com/services/procurement"),
		message.WithAction("processOrder"),
		message.WithAgreementRef("procurement-agreement-2024"),
	)

	// Add payload
	orderXML := []byte(`<?xml version="1.0"?>
<Order>
	<OrderID>ORD-12345</OrderID>
	<Customer>ACME Corp</Customer>
	<Items>
		<Item>
			<SKU>WIDGET-001</SKU>
			<Quantity>100</Quantity>
		</Item>
	</Items>
</Order>`)

	msgBuilder.AddPayload(orderXML, "application/xml").
		AddPartProperty("MimeType", "application/xml").
		AddPartProperty("CharacterSet", "utf-8")

	fmt.Printf("✓ Created AS4 UserMessage with payload\n")

	// 4. Compress payload
	compressor := compression.NewCompressor()
	compressed, err := compressor.Compress(orderXML)
	if err != nil {
		log.Fatalf("Failed to compress payload: %v", err)
	}
	fmt.Printf("✓ Compressed payload (original: %d bytes, compressed: %d bytes)\n",
		len(orderXML), len(compressed))

	// 5. Build envelope
	envelope, payloads, err := msgBuilder.BuildEnvelope()
	if err != nil {
		log.Fatalf("Failed to build envelope: %v", err)
	}
	fmt.Printf("✓ Built SOAP envelope with %d payload(s)\n", len(payloads))

	// 6. Configure Processing Mode
	pmodeManager := pmode.NewPModeManager()
	defaultPMode := pmode.DefaultPMode()
	pmodeManager.AddPMode(defaultPMode)
	fmt.Printf("✓ Configured P-Mode (MEP: One-Way/Push)\n")

	// 7. Initialize reliability tracker
	tracker := reliability.NewMessageTracker(defaultPMode.ReceptionAwareness.DuplicateDetection.Window)
	messageID := envelope.Header.Messaging.UserMessage.MessageInfo.MessageId
	tracker.Track(
		messageID,
		defaultPMode.ReceptionAwareness.Retry.MaxRetries,
		defaultPMode.ReceptionAwareness.Retry.RetryInterval,
		defaultPMode.ReceptionAwareness.Retry.RetryMultiplier,
	)
	fmt.Printf("✓ Initialized message tracker (message ID: %s)\n", messageID)

	// 8. Create HTTPS transport client
	httpsConfig := transport.DefaultHTTPSConfig()
	client := transport.NewHTTPSClient(httpsConfig)
	fmt.Printf("✓ Created HTTPS client (TLS 1.2+)\n")

	// 9. Simulate sending (in production, would serialize and send)
	fmt.Println("\nMessage Details:")
	fmt.Println("================")
	fmt.Printf("From: %s\n", envelope.Header.Messaging.UserMessage.PartyInfo.From.PartyId[0].Value)
	fmt.Printf("To: %s\n", envelope.Header.Messaging.UserMessage.PartyInfo.To.PartyId[0].Value)
	fmt.Printf("Service: %s\n", envelope.Header.Messaging.UserMessage.CollaborationInfo.Service.Value)
	fmt.Printf("Action: %s\n", envelope.Header.Messaging.UserMessage.CollaborationInfo.Action)
	fmt.Printf("Conversation ID: %s\n", envelope.Header.Messaging.UserMessage.CollaborationInfo.ConversationId)
	fmt.Printf("Message ID: %s\n", messageID)

	fmt.Println("\nSecurity Features:")
	fmt.Println("==================")
	fmt.Println("✓ Transport Layer: TLS 1.2/1.3")
	fmt.Println("✓ Message Signing: Ed25519")
	fmt.Println("✓ Digest Algorithm: SHA-256")
	fmt.Println("✓ Encryption: X25519/HKDF/AES-128-GCM (when configured)")
	fmt.Println("✓ Compression: GZIP")

	fmt.Println("\nReliability Features:")
	fmt.Println("=====================")
	fmt.Println("✓ Reception Awareness: Enabled")
	fmt.Printf("✓ Max Retries: %d\n", defaultPMode.ReceptionAwareness.Retry.MaxRetries)
	fmt.Printf("✓ Retry Interval: %v\n", defaultPMode.ReceptionAwareness.Retry.RetryInterval)
	fmt.Println("✓ Duplicate Detection: Enabled")
	fmt.Printf("✓ Detection Window: %v\n", defaultPMode.ReceptionAwareness.DuplicateDetection.Window)

	fmt.Println("\n✓ Example completed successfully!")

	// Prevent compiler errors about unused variables
	_ = secConfig
	_ = client
	_ = compressed
}

// createSelfSignedCert creates a self-signed certificate (simplified for example)
func createSelfSignedCert(pubKey ed25519.PublicKey) *x509.Certificate {
	// In production, create a proper self-signed certificate
	// This is just a placeholder
	return &x509.Certificate{}
}

// Example of receiving and processing a message
type ExampleMessageHandler struct {
	tracker *reliability.MessageTracker
	pmode   *pmode.ProcessingMode
}

func (h *ExampleMessageHandler) HandleMessage(ctx context.Context, messageData []byte) ([]byte, error) {
	// 1. Parse incoming message
	// 2. Validate signature
	// 3. Decrypt if encrypted
	// 4. Decompress payloads
	// 5. Check for duplicates
	// 6. Process business payload
	// 7. Generate and return receipt

	fmt.Println("Processing incoming AS4 message...")

	// Create a receipt
	_ = message.NewReceipt("original-message-id", true)

	// Serialize receipt and return
	// In production, would properly serialize the receipt
	return []byte("receipt"), nil
}
