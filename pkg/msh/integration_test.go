// Copyright (c) 2025 SIROS Foundation
// SPDX-License-Identifier: BSD-2-Clause

package msh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/sirosfoundation/go-as4/pkg/message"
	"github.com/sirosfoundation/go-as4/pkg/pmode"
)

// TestKeyPair holds generated test keys and certificates
type TestKeyPair struct {
	PrivateKey  ed25519.PrivateKey
	PublicKey   ed25519.PublicKey
	Certificate *x509.Certificate
	CertPEM     []byte
}

// generateTestKeyPair creates a self-signed Ed25519 certificate for testing
func generateTestKeyPair(t *testing.T, commonName string) TestKeyPair {
	t.Helper()

	// Generate Ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Create self-signed certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return TestKeyPair{
		PrivateKey:  privKey,
		PublicKey:   pubKey,
		Certificate: cert,
		CertPEM:     certPEM,
	}
}

// TestIntegration_BasicMessageFlow tests basic message creation and queuing
func TestIntegration_BasicMessageFlow(t *testing.T) {
	// Create endpoint resolver
	resolver := NewStaticEndpointResolver()
	resolver.RegisterEndpoint("receiver", &EndpointInfo{
		URL:     "http://receiver.example.com/as4",
		PartyID: "receiver",
	})

	// Create MSH
	msh, err := NewMSH(MSHConfig{
		Resolver:         resolver,
		PModeRegistry:    make(map[string]*pmode.ProcessingMode),
		WorkerCount:      2,
		MaxQueueSize:     10,
		RetryMaxAttempts: 3,
		RetryDelay:       1 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to create MSH: %v", err)
	}

	// Start MSH
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := msh.Start(ctx); err != nil {
		t.Fatalf("Failed to start MSH: %v", err)
	}
	defer msh.Stop()

	// Create test envelope
	env := &message.Envelope{
		Header: &message.Header{
			Messaging: &message.Messaging{
				UserMessage: &message.UserMessage{
					MessageInfo: &message.MessageInfo{
						Timestamp: time.Now(),
						MessageId: "msg-001@test.example.com",
					},
					PartyInfo: &message.PartyInfo{
						From: &message.Party{
							PartyId: []message.PartyId{{Value: "sender"}},
							Role:    "Sender",
						},
						To: &message.Party{
							PartyId: []message.PartyId{{Value: "receiver"}},
							Role:    "Receiver",
						},
					},
					CollaborationInfo: &message.CollaborationInfo{
						Service:        message.Service{Value: "TestService"},
						Action:         "TestAction",
						ConversationId: "conv-001",
					},
				},
			},
		},
		Body: &message.Body{},
	}

	// Create outbound message
	outMsg := &OutboundMessage{
		MessageID:   "msg-001@test.example.com",
		FromPartyID: "sender",
		ToPartyID:   "receiver",
		Service:     "TestService",
		Action:      "TestAction",
		Envelope:    env,
		Payloads: []Payload{
			{
				ContentID:   "payload1@test.example.com",
				ContentType: "text/plain",
				Data:        []byte("Hello, AS4!"),
			},
		},
	}

	// Send message
	sendCtx, sendCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer sendCancel()

	err = msh.SendMessage(sendCtx, outMsg)
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Verify message metadata
	time.Sleep(100 * time.Millisecond) // Allow async processing
	status, err := msh.GetMessageStatus("msg-001@test.example.com")
	if err != nil {
		t.Fatalf("Failed to get message status: %v", err)
	}

	if status.MessageID != "msg-001@test.example.com" {
		t.Errorf("Expected MessageID msg-001@test.example.com, got %s", status.MessageID)
	}
	if status.Direction != MessageDirectionOutbound {
		t.Errorf("Expected direction OUTBOUND, got %s", status.Direction)
	}
}

// TestIntegration_SignedMessage tests message signing with Ed25519
func TestIntegration_SignedMessage(t *testing.T) {
	t.Skip("Ed25519 XML signing deprecated - use RSA signing via RSASigner")
}

// TestIntegration_EncryptedMessage tests message encryption with X25519
func TestIntegration_EncryptedMessage(t *testing.T) {
	t.Skip("NewX25519Encryptor removed - use AESEncryptor with KeyPairGenerator")
}

// TestIntegration_MultipleMessages tests concurrent message sending
func TestIntegration_MultipleMessages(t *testing.T) {
	// Create endpoint resolver
	resolver := NewStaticEndpointResolver()
	resolver.RegisterEndpoint("receiver", &EndpointInfo{
		URL:     "http://receiver.example.com/as4",
		PartyID: "receiver",
	})

	// Create MSH
	msh, err := NewMSH(MSHConfig{
		Resolver:      resolver,
		PModeRegistry: make(map[string]*pmode.ProcessingMode),
		WorkerCount:   4,
		MaxQueueSize:  20,
	})
	if err != nil {
		t.Fatalf("Failed to create MSH: %v", err)
	}

	// Start MSH
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := msh.Start(ctx); err != nil {
		t.Fatalf("Failed to start MSH: %v", err)
	}
	defer msh.Stop()

	// Send multiple messages concurrently
	const numMessages = 10
	var wg sync.WaitGroup
	wg.Add(numMessages)

	for i := 0; i < numMessages; i++ {
		go func(msgNum int) {
			defer wg.Done()

			msgID := time.Now().Format("msg-20060102-150405.000000") + "-" + string(rune('A'+msgNum))

			env := &message.Envelope{
				Header: &message.Header{
					Messaging: &message.Messaging{
						UserMessage: &message.UserMessage{
							MessageInfo: &message.MessageInfo{
								Timestamp: time.Now(),
								MessageId: msgID,
							},
							PartyInfo: &message.PartyInfo{
								From: &message.Party{
									PartyId: []message.PartyId{{Value: "sender"}},
									Role:    "Sender",
								},
								To: &message.Party{
									PartyId: []message.PartyId{{Value: "receiver"}},
									Role:    "Receiver",
								},
							},
							CollaborationInfo: &message.CollaborationInfo{
								Service:        message.Service{Value: "BulkService"},
								Action:         "BulkAction",
								ConversationId: "bulk-conv",
							},
						},
					},
				},
				Body: &message.Body{},
			}

			outMsg := &OutboundMessage{
				MessageID:   msgID,
				FromPartyID: "sender",
				ToPartyID:   "receiver",
				Service:     "BulkService",
				Action:      "BulkAction",
				Envelope:    env,
			}

			sendCtx, sendCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer sendCancel()

			if err := msh.SendMessage(sendCtx, outMsg); err != nil {
				t.Errorf("Failed to send message %d: %v", msgNum, err)
			}
		}(i)
	}

	wg.Wait()
}

// TestIntegration_MessageWithAttachments tests messages with multiple payloads
func TestIntegration_MessageWithAttachments(t *testing.T) {
	// Create endpoint resolver
	resolver := NewStaticEndpointResolver()
	resolver.RegisterEndpoint("receiver", &EndpointInfo{
		URL:     "http://receiver.example.com/as4",
		PartyID: "receiver",
	})

	// Create MSH
	msh, err := NewMSH(MSHConfig{
		Resolver:      resolver,
		PModeRegistry: make(map[string]*pmode.ProcessingMode),
		WorkerCount:   2,
		MaxQueueSize:  10,
	})
	if err != nil {
		t.Fatalf("Failed to create MSH: %v", err)
	}

	// Start MSH
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := msh.Start(ctx); err != nil {
		t.Fatalf("Failed to start MSH: %v", err)
	}
	defer msh.Stop()

	// Create envelope with multiple payload references
	env := &message.Envelope{
		Header: &message.Header{
			Messaging: &message.Messaging{
				UserMessage: &message.UserMessage{
					MessageInfo: &message.MessageInfo{
						Timestamp: time.Now(),
						MessageId: "multi-payload-001@test.example.com",
					},
					PartyInfo: &message.PartyInfo{
						From: &message.Party{
							PartyId: []message.PartyId{{Value: "sender"}},
							Role:    "Sender",
						},
						To: &message.Party{
							PartyId: []message.PartyId{{Value: "receiver"}},
							Role:    "Receiver",
						},
					},
					CollaborationInfo: &message.CollaborationInfo{
						Service:        message.Service{Value: "DocumentService"},
						Action:         "SubmitDocuments",
						ConversationId: "doc-conv-001",
					},
					PayloadInfo: &message.PayloadInfo{
						PartInfo: []message.PartInfo{
							{
								Href: "cid:document.pdf",
								PartProperties: &message.PartProperties{
									Property: []message.Property{
										{Name: "MimeType", Value: "application/pdf"},
									},
								},
							},
							{
								Href: "cid:metadata.xml",
								PartProperties: &message.PartProperties{
									Property: []message.Property{
										{Name: "MimeType", Value: "application/xml"},
									},
								},
							},
						},
					},
				},
			},
		},
		Body: &message.Body{},
	}

	// Create message with multiple payloads
	outMsg := &OutboundMessage{
		MessageID:   "multi-payload-001@test.example.com",
		FromPartyID: "sender",
		ToPartyID:   "receiver",
		Service:     "DocumentService",
		Action:      "SubmitDocuments",
		Envelope:    env,
		Payloads: []Payload{
			{
				ContentID:   "document.pdf",
				ContentType: "application/pdf",
				Data:        []byte("%PDF-1.4 fake pdf content"),
				Properties: map[string]string{
					"MimeType": "application/pdf",
				},
			},
			{
				ContentID:   "metadata.xml",
				ContentType: "application/xml",
				Data:        []byte("<metadata><title>Test Document</title></metadata>"),
				Properties: map[string]string{
					"MimeType": "application/xml",
				},
			},
		},
	}

	// Send message
	sendCtx, sendCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer sendCancel()

	err = msh.SendMessage(sendCtx, outMsg)
	if err != nil {
		t.Fatalf("Failed to send message with attachments: %v", err)
	}

	// Verify message was queued
	time.Sleep(100 * time.Millisecond)
	status, err := msh.GetMessageStatus("multi-payload-001@test.example.com")
	if err != nil {
		t.Fatalf("Failed to get message status: %v", err)
	}

	if len(outMsg.Payloads) != 2 {
		t.Errorf("Expected 2 payloads, got %d", len(outMsg.Payloads))
	}
	if status.Service != "DocumentService" {
		t.Errorf("Expected service DocumentService, got %s", status.Service)
	}
}

// TestIntegration_ErrorHandling tests error scenarios
func TestIntegration_ErrorHandling(t *testing.T) {
	// Create endpoint resolver
	resolver := NewStaticEndpointResolver()

	// Create MSH
	msh, err := NewMSH(MSHConfig{
		Resolver:      resolver,
		PModeRegistry: make(map[string]*pmode.ProcessingMode),
		WorkerCount:   2,
		MaxQueueSize:  10,
	})
	if err != nil {
		t.Fatalf("Failed to create MSH: %v", err)
	}

	// Start MSH
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := msh.Start(ctx); err != nil {
		t.Fatalf("Failed to start MSH: %v", err)
	}
	defer msh.Stop()

	sendCtx := context.Background()

	// Test 1: Message with empty MessageID
	emptyIDMsg := &OutboundMessage{
		MessageID:   "",
		FromPartyID: "sender",
		ToPartyID:   "receiver",
		Service:     "TestService",
		Action:      "TestAction",
	}
	err = msh.SendMessage(sendCtx, emptyIDMsg)
	if err == nil {
		t.Error("Expected error for empty MessageID, got nil")
	}

	// Test 2: Message with missing FromPartyID
	missingFromMsg := &OutboundMessage{
		MessageID:   "test-msg-001",
		FromPartyID: "",
		ToPartyID:   "receiver",
		Service:     "TestService",
		Action:      "TestAction",
	}
	err = msh.SendMessage(sendCtx, missingFromMsg)
	if err == nil {
		t.Error("Expected error for missing FromPartyID, got nil")
	}

	// Test 3: Message with missing ToPartyID
	missingToMsg := &OutboundMessage{
		MessageID:   "test-msg-002",
		FromPartyID: "sender",
		ToPartyID:   "",
		Service:     "TestService",
		Action:      "TestAction",
	}
	err = msh.SendMessage(sendCtx, missingToMsg)
	if err == nil {
		t.Error("Expected error for missing ToPartyID, got nil")
	}

	// Test 4: Message with missing Service
	missingServiceMsg := &OutboundMessage{
		MessageID:   "test-msg-003",
		FromPartyID: "sender",
		ToPartyID:   "receiver",
		Service:     "",
		Action:      "TestAction",
	}
	err = msh.SendMessage(sendCtx, missingServiceMsg)
	if err == nil {
		t.Error("Expected error for missing Service, got nil")
	}

	// Test 5: Message with missing Action
	missingActionMsg := &OutboundMessage{
		MessageID:   "test-msg-004",
		FromPartyID: "sender",
		ToPartyID:   "receiver",
		Service:     "TestService",
		Action:      "",
	}
	err = msh.SendMessage(sendCtx, missingActionMsg)
	if err == nil {
		t.Error("Expected error for missing Action, got nil")
	}
}

// TestIntegration_InboundMessageHandler tests receiving messages
func TestIntegration_InboundMessageHandler(t *testing.T) {
	// Channel to collect received messages
	receivedMessages := make(chan *InboundMessage, 10)

	// Create message handler
	handler := MessageHandler(func(msg *InboundMessage) {
		receivedMessages <- msg
	})

	// Create endpoint resolver
	resolver := NewStaticEndpointResolver()

	// Create MSH with message handler
	msh, err := NewMSH(MSHConfig{
		Resolver:       resolver,
		PModeRegistry:  make(map[string]*pmode.ProcessingMode),
		MessageHandler: handler,
		WorkerCount:    2,
		MaxQueueSize:   10,
	})
	if err != nil {
		t.Fatalf("Failed to create MSH: %v", err)
	}

	// Start MSH
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := msh.Start(ctx); err != nil {
		t.Fatalf("Failed to start MSH: %v", err)
	}
	defer msh.Stop()

	// Create test inbound message
	inboundEnv := &message.Envelope{
		Header: &message.Header{
			Messaging: &message.Messaging{
				UserMessage: &message.UserMessage{
					MessageInfo: &message.MessageInfo{
						Timestamp: time.Now(),
						MessageId: "inbound-001@test.example.com",
					},
					PartyInfo: &message.PartyInfo{
						From: &message.Party{
							PartyId: []message.PartyId{{Value: "external-sender"}},
							Role:    "Sender",
						},
						To: &message.Party{
							PartyId: []message.PartyId{{Value: "receiver"}},
							Role:    "Receiver",
						},
					},
					CollaborationInfo: &message.CollaborationInfo{
						Service:        message.Service{Value: "InboundService"},
						Action:         "InboundAction",
						ConversationId: "inbound-conv-001",
					},
				},
			},
		},
		Body: &message.Body{},
	}

	inMsg := &InboundMessage{
		MessageID:   "inbound-001@test.example.com",
		FromPartyID: "external-sender",
		ToPartyID:   "receiver",
		Service:     "InboundService",
		Action:      "InboundAction",
		Envelope:    inboundEnv,
		Payloads: []Payload{
			{
				ContentID:   "payload1",
				ContentType: "text/plain",
				Data:        []byte("Inbound test data"),
			},
		},
	}

	// Receive message
	receiveCtx, receiveCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer receiveCancel()

	err = msh.ReceiveMessage(receiveCtx, inMsg)
	if err != nil {
		t.Fatalf("Failed to receive message: %v", err)
	}

	// Wait for handler to process message
	select {
	case received := <-receivedMessages:
		if received.MessageID != "inbound-001@test.example.com" {
			t.Errorf("Expected MessageID inbound-001@test.example.com, got %s", received.MessageID)
		}
		if received.Service != "InboundService" {
			t.Errorf("Expected Service InboundService, got %s", received.Service)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for message handler")
	}
}

// BenchmarkMessageSending benchmarks message sending throughput
func BenchmarkMessageSending(b *testing.B) {
	// Create endpoint resolver
	resolver := NewStaticEndpointResolver()
	resolver.RegisterEndpoint("receiver", &EndpointInfo{
		URL:     "http://receiver.example.com/as4",
		PartyID: "receiver",
	})

	// Create MSH
	msh, err := NewMSH(MSHConfig{
		Resolver:      resolver,
		PModeRegistry: make(map[string]*pmode.ProcessingMode),
		WorkerCount:   4,
		MaxQueueSize:  1000,
	})
	if err != nil {
		b.Fatalf("Failed to create MSH: %v", err)
	}

	// Start MSH
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := msh.Start(ctx); err != nil {
		b.Fatalf("Failed to start MSH: %v", err)
	}
	defer msh.Stop()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		msgID := time.Now().Format("bench-msg-20060102-150405.000000")

		env := &message.Envelope{
			Header: &message.Header{
				Messaging: &message.Messaging{
					UserMessage: &message.UserMessage{
						MessageInfo: &message.MessageInfo{
							Timestamp: time.Now(),
							MessageId: msgID,
						},
						PartyInfo: &message.PartyInfo{
							From: &message.Party{
								PartyId: []message.PartyId{{Value: "sender"}},
								Role:    "Sender",
							},
							To: &message.Party{
								PartyId: []message.PartyId{{Value: "receiver"}},
								Role:    "Receiver",
							},
						},
						CollaborationInfo: &message.CollaborationInfo{
							Service:        message.Service{Value: "BenchService"},
							Action:         "BenchAction",
							ConversationId: "bench-conv",
						},
					},
				},
			},
			Body: &message.Body{},
		}

		outMsg := &OutboundMessage{
			MessageID:   msgID,
			FromPartyID: "sender",
			ToPartyID:   "receiver",
			Service:     "BenchService",
			Action:      "BenchAction",
			Envelope:    env,
		}

		sendCtx, sendCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := msh.SendMessage(sendCtx, outMsg); err != nil {
			b.Errorf("Failed to send message: %v", err)
		}
		sendCancel()
	}
}
