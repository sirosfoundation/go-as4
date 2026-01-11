package as4

import (
	"context"
	"encoding/xml"
	"testing"
	"time"

	"github.com/sirosfoundation/go-as4/pkg/message"
	"github.com/sirosfoundation/go-as4/pkg/pmode"
	"github.com/sirosfoundation/go-as4/pkg/security"
	"github.com/sirosfoundation/go-as4/pkg/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient_NilConfig(t *testing.T) {
	client, err := NewClient(nil)
	if err == nil {
		t.Error("expected error for nil config")
	}
	if client != nil {
		t.Error("expected nil client for nil config")
	}
}

func TestNewClient_ValidConfig(t *testing.T) {
	config := &ClientConfig{
		HTTPSConfig:    transport.DefaultHTTPSConfig(),
		SecurityConfig: &security.SecurityConfig{},
		PMode:          pmode.DefaultPMode(),
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.httpClient == nil {
		t.Error("expected httpClient to be initialized")
	}
	if client.pmodeManager == nil {
		t.Error("expected pmodeManager to be initialized")
	}
	if client.tracker == nil {
		t.Error("expected tracker to be initialized")
	}
	if client.compressor == nil {
		t.Error("expected compressor to be initialized")
	}
}

func TestNewClient_ConfigWithoutPMode(t *testing.T) {
	config := &ClientConfig{
		HTTPSConfig:    transport.DefaultHTTPSConfig(),
		SecurityConfig: &security.SecurityConfig{},
		// No PMode
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestNewClient_ConfigWithNilHTTPSConfig(t *testing.T) {
	config := &ClientConfig{
		HTTPSConfig: nil, // Will use default
		PMode:       pmode.DefaultPMode(),
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestNewServer_NilConfig(t *testing.T) {
	server, err := NewServer(nil)
	if err == nil {
		t.Error("expected error for nil config")
	}
	if server != nil {
		t.Error("expected nil server for nil config")
	}
}

func TestNewServer_ValidConfig(t *testing.T) {
	config := &ServerConfig{
		Address:        ":8443",
		HTTPSConfig:    transport.DefaultHTTPSConfig(),
		SecurityConfig: &security.SecurityConfig{},
		PModeManager:   pmode.NewPModeManager(),
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if server == nil {
		t.Fatal("expected non-nil server")
	}
	if server.tracker == nil {
		t.Error("expected tracker to be initialized")
	}
	if server.compressor == nil {
		t.Error("expected compressor to be initialized")
	}
	if server.httpServer == nil {
		t.Error("expected httpServer to be initialized")
	}
}

func TestNewServer_ConfigWithNilHTTPSConfig(t *testing.T) {
	config := &ServerConfig{
		Address:      ":8443",
		HTTPSConfig:  nil, // Will use default
		PModeManager: pmode.NewPModeManager(),
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if server == nil {
		t.Fatal("expected non-nil server")
	}
}

func TestClientConfig_Fields(t *testing.T) {
	httpsConfig := transport.DefaultHTTPSConfig()
	secConfig := &security.SecurityConfig{}
	pm := pmode.DefaultPMode()

	config := &ClientConfig{
		HTTPSConfig:    httpsConfig,
		SecurityConfig: secConfig,
		PMode:          pm,
	}

	if config.HTTPSConfig != httpsConfig {
		t.Error("HTTPSConfig mismatch")
	}
	if config.SecurityConfig != secConfig {
		t.Error("SecurityConfig mismatch")
	}
	if config.PMode != pm {
		t.Error("PMode mismatch")
	}
}

func TestServerConfig_Fields(t *testing.T) {
	httpsConfig := transport.DefaultHTTPSConfig()
	secConfig := &security.SecurityConfig{}
	pmManager := pmode.NewPModeManager()

	config := &ServerConfig{
		Address:        ":8443",
		HTTPSConfig:    httpsConfig,
		SecurityConfig: secConfig,
		PModeManager:   pmManager,
	}

	if config.Address != ":8443" {
		t.Error("Address mismatch")
	}
	if config.HTTPSConfig != httpsConfig {
		t.Error("HTTPSConfig mismatch")
	}
	if config.SecurityConfig != secConfig {
		t.Error("SecurityConfig mismatch")
	}
	if config.PModeManager != pmManager {
		t.Error("PModeManager mismatch")
	}
}

func TestServer_HandleMessage_ValidMessage(t *testing.T) {
	config := &ServerConfig{
		Address:      ":8443",
		HTTPSConfig:  transport.DefaultHTTPSConfig(),
		PModeManager: pmode.NewPModeManager(),
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	// Create a valid AS4 envelope
	envelope := &message.Envelope{
		Header: &message.Header{
			Messaging: &message.Messaging{
				UserMessage: &message.UserMessage{
					MessageInfo: &message.MessageInfo{
						MessageId: "test-msg-12345@example.com",
						Timestamp: time.Now(),
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
						Service:        message.Service{Value: "test-service"},
						Action:         "test-action",
						ConversationId: "conv-123",
					},
				},
			},
		},
		Body: &message.Body{},
	}

	messageData, err := xml.Marshal(envelope)
	require.NoError(t, err)

	ctx := context.Background()
	response, err := server.HandleMessage(ctx, messageData)
	require.NoError(t, err)
	assert.NotEmpty(t, response)

	// Parse response and verify it's a receipt
	var respEnvelope message.Envelope
	err = xml.Unmarshal(response, &respEnvelope)
	require.NoError(t, err)
	assert.NotNil(t, respEnvelope.Header)
	assert.NotNil(t, respEnvelope.Header.Messaging)
	assert.NotNil(t, respEnvelope.Header.Messaging.SignalMessage)
	assert.NotNil(t, respEnvelope.Header.Messaging.SignalMessage.Receipt)
}

func TestServer_HandleMessage_InvalidXML(t *testing.T) {
	config := &ServerConfig{
		Address:      ":8443",
		HTTPSConfig:  transport.DefaultHTTPSConfig(),
		PModeManager: pmode.NewPModeManager(),
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	ctx := context.Background()
	_, err = server.HandleMessage(ctx, []byte("not valid xml"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse message")
}

func TestServer_HandleMessage_MissingMessagingHeader(t *testing.T) {
	config := &ServerConfig{
		Address:      ":8443",
		HTTPSConfig:  transport.DefaultHTTPSConfig(),
		PModeManager: pmode.NewPModeManager(),
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	// Envelope with nil header
	envelope := &message.Envelope{
		Header: nil,
		Body:   &message.Body{},
	}

	messageData, err := xml.Marshal(envelope)
	require.NoError(t, err)

	ctx := context.Background()
	_, err = server.HandleMessage(ctx, messageData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing messaging header")

	// Envelope with header but nil messaging
	envelope2 := &message.Envelope{
		Header: &message.Header{Messaging: nil},
		Body:   &message.Body{},
	}

	messageData2, err := xml.Marshal(envelope2)
	require.NoError(t, err)

	_, err = server.HandleMessage(ctx, messageData2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing messaging header")
}

func TestServer_HandleMessage_MissingUserMessage(t *testing.T) {
	config := &ServerConfig{
		Address:      ":8443",
		HTTPSConfig:  transport.DefaultHTTPSConfig(),
		PModeManager: pmode.NewPModeManager(),
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	envelope := &message.Envelope{
		Header: &message.Header{
			Messaging: &message.Messaging{
				UserMessage: nil, // Missing user message
			},
		},
		Body: &message.Body{},
	}

	messageData, err := xml.Marshal(envelope)
	require.NoError(t, err)

	ctx := context.Background()
	_, err = server.HandleMessage(ctx, messageData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing user message")
}

func TestServer_HandleMessage_DuplicateMessage(t *testing.T) {
	config := &ServerConfig{
		Address:      ":8443",
		HTTPSConfig:  transport.DefaultHTTPSConfig(),
		PModeManager: pmode.NewPModeManager(),
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	envelope := &message.Envelope{
		Header: &message.Header{
			Messaging: &message.Messaging{
				UserMessage: &message.UserMessage{
					MessageInfo: &message.MessageInfo{
						MessageId: "duplicate-msg-67890@example.com",
						Timestamp: time.Now(),
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
						Service:        message.Service{Value: "test-service"},
						Action:         "test-action",
						ConversationId: "conv-123",
					},
				},
			},
		},
		Body: &message.Body{},
	}

	messageData, err := xml.Marshal(envelope)
	require.NoError(t, err)

	ctx := context.Background()

	// First call should succeed
	_, err = server.HandleMessage(ctx, messageData)
	require.NoError(t, err)

	// Second call with same message ID should fail as duplicate
	_, err = server.HandleMessage(ctx, messageData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate message")
}

func TestServer_serializeSignal(t *testing.T) {
	config := &ServerConfig{
		Address:      ":8443",
		HTTPSConfig:  transport.DefaultHTTPSConfig(),
		PModeManager: pmode.NewPModeManager(),
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	// Test serializing a receipt
	receipt := message.NewReceipt("test-msg-id@example.com", true)
	response, err := server.serializeSignal(receipt)
	require.NoError(t, err)
	assert.NotEmpty(t, response)

	// Verify the response can be parsed back
	var envelope message.Envelope
	err = xml.Unmarshal(response, &envelope)
	require.NoError(t, err)
	assert.NotNil(t, envelope.Header)
	assert.NotNil(t, envelope.Header.Messaging)
	assert.NotNil(t, envelope.Header.Messaging.SignalMessage)
	assert.NotNil(t, envelope.Header.Messaging.SignalMessage.Receipt)
}

func TestServer_serializeSignal_Error(t *testing.T) {
	config := &ServerConfig{
		Address:      ":8443",
		HTTPSConfig:  transport.DefaultHTTPSConfig(),
		PModeManager: pmode.NewPModeManager(),
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	// Test serializing an error signal
	errorSignal := message.NewError(
		"test-msg-id@example.com",
		"EBMS:0001",
		"Error",
		"Test Error",
		"This is a test error message",
	)

	response, err := server.serializeSignal(errorSignal)
	require.NoError(t, err)
	assert.NotEmpty(t, response)

	// Verify the response can be parsed back
	var envelope message.Envelope
	err = xml.Unmarshal(response, &envelope)
	require.NoError(t, err)
	assert.NotNil(t, envelope.Header.Messaging.SignalMessage)
	assert.NotNil(t, envelope.Header.Messaging.SignalMessage.Error)
}
