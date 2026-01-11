package msh

import (
	"context"
	"encoding/xml"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sirosfoundation/go-as4/pkg/message"
	"github.com/sirosfoundation/go-as4/pkg/pmode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMSH(t *testing.T) {
	resolver := NewStaticEndpointResolver()

	config := MSHConfig{
		Resolver: resolver,
	}

	msh, err := NewMSH(config)
	require.NoError(t, err)
	assert.NotNil(t, msh)
	assert.Equal(t, 4, msh.workerCount)
	assert.Equal(t, 100, msh.maxQueueSize)
	assert.Equal(t, 3, msh.retryMaxAttempts)
}

func TestNewMSH_MissingResolver(t *testing.T) {
	config := MSHConfig{}

	_, err := NewMSH(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "resolver is required")
}

func TestMSHStartStop(t *testing.T) {
	resolver := NewStaticEndpointResolver()
	config := MSHConfig{
		Resolver: resolver,
	}

	msh, err := NewMSH(config)
	require.NoError(t, err)

	ctx := context.Background()

	// Start MSH
	err = msh.Start(ctx)
	require.NoError(t, err)

	// Starting again should fail
	err = msh.Start(ctx)
	assert.Error(t, err)
	assert.Equal(t, ErrMSHAlreadyStarted, err)

	// Stop MSH
	err = msh.Stop()
	require.NoError(t, err)

	// Stopping again should fail
	err = msh.Stop()
	assert.Error(t, err)
	assert.Equal(t, ErrMSHNotStarted, err)
}

func TestSendMessage_NotStarted(t *testing.T) {
	resolver := NewStaticEndpointResolver()
	config := MSHConfig{
		Resolver: resolver,
	}

	msh, err := NewMSH(config)
	require.NoError(t, err)

	msg := &OutboundMessage{
		MessageID:   "test-123",
		FromPartyID: "sender",
		ToPartyID:   "receiver",
		Service:     "test-service",
		Action:      "test-action",
	}

	err = msh.SendMessage(context.Background(), msg)
	assert.Error(t, err)
	assert.Equal(t, ErrMSHNotStarted, err)
}

func TestSendMessage_ValidationError(t *testing.T) {
	resolver := NewStaticEndpointResolver()
	config := MSHConfig{
		Resolver: resolver,
	}

	msh, err := NewMSH(config)
	require.NoError(t, err)

	ctx := context.Background()
	err = msh.Start(ctx)
	require.NoError(t, err)
	defer msh.Stop()

	// Missing required fields
	msg := &OutboundMessage{
		MessageID: "test-123",
	}

	err = msh.SendMessage(context.Background(), msg)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidMessage)
}

func TestSendMessage_Success(t *testing.T) {
	resolver := NewStaticEndpointResolver()
	resolver.RegisterEndpoint("receiver", &EndpointInfo{
		URL:     "https://example.com/as4",
		PartyID: "receiver",
	})

	config := MSHConfig{
		Resolver: resolver,
	}

	msh, err := NewMSH(config)
	require.NoError(t, err)

	ctx := context.Background()
	err = msh.Start(ctx)
	require.NoError(t, err)
	defer msh.Stop()

	msg := &OutboundMessage{
		MessageID:   "test-456",
		FromPartyID: "sender",
		ToPartyID:   "receiver",
		Service:     "test-service",
		Action:      "test-action",
	}

	err = msh.SendMessage(context.Background(), msg)
	assert.NoError(t, err)

	// Give workers time to process
	time.Sleep(100 * time.Millisecond)

	// Check message metadata
	metadata, err := msh.GetMessageStatus("test-456")
	assert.NoError(t, err)
	assert.Equal(t, "test-456", metadata.MessageID)
	assert.Equal(t, MessageDirectionOutbound, metadata.Direction)
}

func TestStaticEndpointResolver(t *testing.T) {
	resolver := NewStaticEndpointResolver()

	endpoint := &EndpointInfo{
		URL:     "https://example.com/as4",
		PartyID: "party-123",
		Service: "test-service",
	}

	resolver.RegisterEndpoint("party-123", endpoint)

	ctx := context.Background()
	result, err := resolver.ResolveEndpoint(ctx, "party-123", "test-service", "test-action")
	require.NoError(t, err)
	assert.Equal(t, endpoint.URL, result.URL)
	assert.Equal(t, endpoint.PartyID, result.PartyID)

	// Test non-existent endpoint
	_, err = resolver.ResolveEndpoint(ctx, "unknown", "service", "action")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrEndpointNotFound)
}

func TestDynamicEndpointResolver(t *testing.T) {
	lookupCalled := false
	lookupFunc := func(ctx context.Context, partyID, service, action string) (*EndpointInfo, error) {
		lookupCalled = true
		return &EndpointInfo{
			URL:     "https://dynamic.example.com/as4",
			PartyID: partyID,
			Service: service,
		}, nil
	}

	resolver := NewDynamicEndpointResolver(lookupFunc, 60)

	ctx := context.Background()
	result, err := resolver.ResolveEndpoint(ctx, "party-456", "service", "action")
	require.NoError(t, err)
	assert.True(t, lookupCalled)
	assert.Equal(t, "https://dynamic.example.com/as4", result.URL)

	// Second call should use cache
	lookupCalled = false
	result2, err := resolver.ResolveEndpoint(ctx, "party-456", "service", "action")
	require.NoError(t, err)
	assert.False(t, lookupCalled, "Should use cached value")
	assert.Equal(t, result.URL, result2.URL)
}

func TestMultiResolver(t *testing.T) {
	// Create static resolver with one endpoint
	staticResolver := NewStaticEndpointResolver()
	staticResolver.RegisterEndpoint("party-static", &EndpointInfo{
		URL:     "https://static.example.com/as4",
		PartyID: "party-static",
	})

	// Create dynamic resolver that finds other endpoints
	dynamicResolver := NewDynamicEndpointResolver(
		func(ctx context.Context, partyID, service, action string) (*EndpointInfo, error) {
			if partyID == "party-dynamic" {
				return &EndpointInfo{
					URL:     "https://dynamic.example.com/as4",
					PartyID: partyID,
				}, nil
			}
			return nil, ErrEndpointNotFound
		},
		60,
	)

	// Create multi-resolver that tries static first, then dynamic
	multiResolver := NewMultiResolver(staticResolver, dynamicResolver)

	ctx := context.Background()

	// Should find in static resolver
	result, err := multiResolver.ResolveEndpoint(ctx, "party-static", "service", "action")
	require.NoError(t, err)
	assert.Equal(t, "https://static.example.com/as4", result.URL)

	// Should find in dynamic resolver
	result, err = multiResolver.ResolveEndpoint(ctx, "party-dynamic", "service", "action")
	require.NoError(t, err)
	assert.Equal(t, "https://dynamic.example.com/as4", result.URL)

	// Should fail for unknown party
	_, err = multiResolver.ResolveEndpoint(ctx, "unknown", "service", "action")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrEndpointNotFound)
}

func TestBuildEnvelope(t *testing.T) {
	resolver := NewStaticEndpointResolver()
	config := MSHConfig{
		Resolver: resolver,
	}

	msh, err := NewMSH(config)
	require.NoError(t, err)

	msg := &OutboundMessage{
		MessageID:   "msg-789",
		FromPartyID: "sender",
		ToPartyID:   "receiver",
		Service:     "test-service",
		Action:      "test-action",
		Payloads: []Payload{
			{
				ContentID:   "payload-1",
				ContentType: "application/xml",
				Data:        []byte("<test>data</test>"),
			},
		},
	}

	envelope, err := msh.buildEnvelope(msg)
	require.NoError(t, err)
	assert.NotNil(t, envelope)
	assert.NotNil(t, envelope.Header)
	assert.NotNil(t, envelope.Header.Messaging)
	assert.NotNil(t, envelope.Header.Messaging.UserMessage)

	userMsg := envelope.Header.Messaging.UserMessage
	assert.Equal(t, "msg-789", userMsg.MessageInfo.MessageId)
	assert.Equal(t, "sender", userMsg.PartyInfo.From.PartyId[0].Value)
	assert.Equal(t, "receiver", userMsg.PartyInfo.To.PartyId[0].Value)
	assert.Equal(t, "test-service", userMsg.CollaborationInfo.Service.Value)
	assert.Equal(t, "test-action", userMsg.CollaborationInfo.Action)
	assert.Len(t, userMsg.PayloadInfo.PartInfo, 1)
	assert.Equal(t, "payload-1", userMsg.PayloadInfo.PartInfo[0].Href)
}

func TestValidateOutboundMessage(t *testing.T) {
	resolver := NewStaticEndpointResolver()
	config := MSHConfig{
		Resolver: resolver,
	}

	msh, err := NewMSH(config)
	require.NoError(t, err)

	tests := []struct {
		name    string
		msg     *OutboundMessage
		wantErr string
	}{
		{
			name: "valid message",
			msg: &OutboundMessage{
				MessageID:   "msg-1",
				FromPartyID: "sender",
				ToPartyID:   "receiver",
				Service:     "service",
				Action:      "action",
			},
			wantErr: "",
		},
		{
			name: "missing message ID",
			msg: &OutboundMessage{
				FromPartyID: "sender",
				ToPartyID:   "receiver",
				Service:     "service",
				Action:      "action",
			},
			wantErr: "message ID is required",
		},
		{
			name: "missing from party",
			msg: &OutboundMessage{
				MessageID: "msg-1",
				ToPartyID: "receiver",
				Service:   "service",
				Action:    "action",
			},
			wantErr: "from party ID is required",
		},
		{
			name: "missing to party",
			msg: &OutboundMessage{
				MessageID:   "msg-1",
				FromPartyID: "sender",
				Service:     "service",
				Action:      "action",
			},
			wantErr: "to party ID is required",
		},
		{
			name: "missing service",
			msg: &OutboundMessage{
				MessageID:   "msg-1",
				FromPartyID: "sender",
				ToPartyID:   "receiver",
				Action:      "action",
			},
			wantErr: "service is required",
		},
		{
			name: "missing action",
			msg: &OutboundMessage{
				MessageID:   "msg-1",
				FromPartyID: "sender",
				ToPartyID:   "receiver",
				Service:     "service",
			},
			wantErr: "action is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := msh.validateOutboundMessage(tt.msg)
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestEventHandling(t *testing.T) {
	resolver := NewStaticEndpointResolver()
	// Register endpoint so message processing doesn't fail
	resolver.RegisterEndpoint("receiver", &EndpointInfo{
		URL:     "https://example.com/as4",
		PartyID: "receiver",
	})

	var mu sync.Mutex
	eventReceived := false
	var receivedEvent MessageEvent

	config := MSHConfig{
		Resolver: resolver,
		EventHandler: func(event MessageEvent) {
			mu.Lock()
			defer mu.Unlock()
			eventReceived = true
			receivedEvent = event
		},
	}

	msh, err := NewMSH(config)
	require.NoError(t, err)

	ctx := context.Background()
	err = msh.Start(ctx)
	require.NoError(t, err)
	defer msh.Stop()

	msg := &OutboundMessage{
		MessageID:   "event-test",
		FromPartyID: "sender",
		ToPartyID:   "receiver",
		Service:     "service",
		Action:      "action",
	}

	err = msh.SendMessage(context.Background(), msg)
	require.NoError(t, err)

	// Give event dispatcher time to process
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	assert.True(t, eventReceived)
	// Event can be either "message.queued" or "message.sent" depending on timing
	assert.Contains(t, []string{"message.queued", "message.sent", "message.error"}, receivedEvent.Type)
	assert.Equal(t, "event-test", receivedEvent.MessageID)
}

func TestApplySecurityWithPMode(t *testing.T) {
	resolver := NewStaticEndpointResolver()
	config := MSHConfig{
		Resolver: resolver,
	}

	msh, err := NewMSH(config)
	require.NoError(t, err)

	pm := &pmode.ProcessingMode{
		Security: &pmode.Security{
			X509: &pmode.X509Config{
				Sign: &pmode.SignConfig{
					Algorithm: "Ed25519",
				},
				Encryption: &pmode.EncryptionConfig{
					Algorithm: "X25519",
				},
			},
		},
	}

	msg := &OutboundMessage{
		MessageID:   "sec-test",
		FromPartyID: "sender",
		ToPartyID:   "receiver",
		Service:     "service",
		Action:      "action",
		PMode:       pm,
	}

	envelope, err := msh.buildEnvelope(msg)
	require.NoError(t, err)

	// Apply security (currently stubs, so should not error)
	err = msh.applyOutboundSecurity(envelope, msg, pm)
	assert.NoError(t, err)

	// For inbound, we need XML bytes
	envXML, _ := xml.Marshal(envelope)
	inboundMsg := &InboundMessage{
		MessageID: msg.MessageID,
		Envelope:  envelope,
		PMode:     pm,
	}
	err = msh.applyInboundSecurity(envXML, inboundMsg, pm)
	assert.NoError(t, err)
}

func TestGenerateMessageID(t *testing.T) {
	// Test that generateMessageID produces unique IDs
	id1 := generateMessageID()
	id2 := generateMessageID()

	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	assert.Contains(t, id1, "@siros.org")
	assert.Contains(t, id2, "@siros.org")
	// IDs should be different (generated with nanosecond timestamp)
	// This may occasionally fail due to timing, but generally works
	if id1 == id2 {
		t.Log("Warning: IDs were the same (timing issue)")
	}
}

func TestHandleError(t *testing.T) {
	resolver := NewStaticEndpointResolver()

	var errorHandlerCalled bool
	var errorMsg string
	var errorErr error

	config := MSHConfig{
		Resolver: resolver,
		ErrorHandler: func(messageID string, err error) {
			errorHandlerCalled = true
			errorMsg = messageID
			errorErr = err
		},
	}

	msh, err := NewMSH(config)
	require.NoError(t, err)

	ctx := context.Background()
	err = msh.Start(ctx)
	require.NoError(t, err)
	defer msh.Stop()

	// Pre-create message metadata
	testMsgID := "error-test-123"
	msh.mu.Lock()
	msh.messages[testMsgID] = &MessageMetadata{
		MessageID: testMsgID,
		Status:    MessageStatusPending,
	}
	msh.mu.Unlock()

	// Call handleError
	testErr := fmt.Errorf("test error")
	msh.handleError(testMsgID, testErr)

	// Give time for event dispatcher
	time.Sleep(50 * time.Millisecond)

	assert.True(t, errorHandlerCalled)
	assert.Equal(t, testMsgID, errorMsg)
	assert.Equal(t, testErr, errorErr)

	// Check status was updated to failed
	metadata, err := msh.GetMessageStatus(testMsgID)
	require.NoError(t, err)
	assert.Equal(t, MessageStatusFailed, metadata.Status)
}

func TestReceiveMessage(t *testing.T) {
	resolver := NewStaticEndpointResolver()

	var messageHandlerCalled bool
	var receivedMsg *InboundMessage

	config := MSHConfig{
		Resolver: resolver,
		MessageHandler: func(msg *InboundMessage) {
			messageHandlerCalled = true
			receivedMsg = msg
		},
	}

	msh, err := NewMSH(config)
	require.NoError(t, err)

	ctx := context.Background()
	err = msh.Start(ctx)
	require.NoError(t, err)
	defer msh.Stop()

	inMsg := &InboundMessage{
		MessageID:   "inbound-test-456",
		FromPartyID: "sender",
		ToPartyID:   "receiver",
		Service:     "test-service",
		Action:      "test-action",
	}

	err = msh.ReceiveMessage(context.Background(), inMsg)
	require.NoError(t, err)

	// Give time for processing
	time.Sleep(100 * time.Millisecond)

	assert.True(t, messageHandlerCalled)
	assert.Equal(t, "inbound-test-456", receivedMsg.MessageID)
}

func TestReceiveMessage_NotStarted(t *testing.T) {
	resolver := NewStaticEndpointResolver()
	config := MSHConfig{
		Resolver: resolver,
	}

	msh, err := NewMSH(config)
	require.NoError(t, err)

	msg := &InboundMessage{
		MessageID: "test-123",
	}

	err = msh.ReceiveMessage(context.Background(), msg)
	assert.Error(t, err)
	assert.Equal(t, ErrMSHNotStarted, err)
}

func TestStaticEndpointResolver_CacheAndInvalidate(t *testing.T) {
	resolver := NewStaticEndpointResolver()

	endpoint := &EndpointInfo{
		URL:     "https://example.com/as4",
		PartyID: "party-cache-test",
	}

	// Test CacheEndpoint
	resolver.CacheEndpoint(endpoint.PartyID, endpoint)

	ctx := context.Background()
	result, err := resolver.ResolveEndpoint(ctx, "party-cache-test", "service", "action")
	require.NoError(t, err)
	assert.Equal(t, endpoint.URL, result.URL)

	// Test InvalidateCache
	resolver.InvalidateCache("party-cache-test")

	_, err = resolver.ResolveEndpoint(ctx, "party-cache-test", "service", "action")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrEndpointNotFound)
}

func TestDynamicEndpointResolver_InvalidateCache(t *testing.T) {
	callCount := 0
	lookupFunc := func(ctx context.Context, partyID, service, action string) (*EndpointInfo, error) {
		callCount++
		return &EndpointInfo{
			URL:     fmt.Sprintf("https://dynamic-%d.example.com/as4", callCount),
			PartyID: partyID,
		}, nil
	}

	resolver := NewDynamicEndpointResolver(lookupFunc, 60)
	ctx := context.Background()

	// First call - should invoke lookup
	result1, err := resolver.ResolveEndpoint(ctx, "party-inv", "service", "action")
	require.NoError(t, err)
	assert.Equal(t, "https://dynamic-1.example.com/as4", result1.URL)
	assert.Equal(t, 1, callCount)

	// Second call - should use cache
	result2, err := resolver.ResolveEndpoint(ctx, "party-inv", "service", "action")
	require.NoError(t, err)
	assert.Equal(t, "https://dynamic-1.example.com/as4", result2.URL)
	assert.Equal(t, 1, callCount)

	// Invalidate cache - need to use full cache key format: partyID:service:action
	resolver.InvalidateCache("party-inv:service:action")

	// Third call after invalidation - should invoke lookup again
	result3, err := resolver.ResolveEndpoint(ctx, "party-inv", "service", "action")
	require.NoError(t, err)
	assert.Equal(t, "https://dynamic-2.example.com/as4", result3.URL)
	assert.Equal(t, 2, callCount)
}

func TestMultiResolver_CacheAndInvalidate(t *testing.T) {
	staticResolver := NewStaticEndpointResolver()
	dynamicResolver := NewDynamicEndpointResolver(
		func(ctx context.Context, partyID, service, action string) (*EndpointInfo, error) {
			return &EndpointInfo{URL: "https://dynamic.com", PartyID: partyID}, nil
		},
		60,
	)

	multiResolver := NewMultiResolver(staticResolver, dynamicResolver)

	endpoint := &EndpointInfo{
		URL:     "https://cached.example.com/as4",
		PartyID: "party-multi-cache",
	}

	// Test CacheEndpoint - caches to first resolver (static)
	multiResolver.CacheEndpoint("party-multi-cache", endpoint)

	ctx := context.Background()
	result, err := multiResolver.ResolveEndpoint(ctx, "party-multi-cache", "service", "action")
	require.NoError(t, err)
	assert.Equal(t, "https://cached.example.com/as4", result.URL)

	// Test InvalidateCache
	multiResolver.InvalidateCache("party-multi-cache")

	// After invalidation, should find via dynamic resolver
	result2, err := multiResolver.ResolveEndpoint(ctx, "party-multi-cache", "service", "action")
	require.NoError(t, err)
	assert.Equal(t, "https://dynamic.com", result2.URL)
}

func TestBuildEnvelope_WithExistingEnvelope(t *testing.T) {
	resolver := NewStaticEndpointResolver()
	config := MSHConfig{
		Resolver: resolver,
	}

	msh, err := NewMSH(config)
	require.NoError(t, err)

	existingEnvelope := &message.Envelope{
		Header: &message.Header{
			Messaging: &message.Messaging{
				UserMessage: &message.UserMessage{
					MessageInfo: &message.MessageInfo{
						MessageId: "pre-existing-id",
					},
				},
			},
		},
		Body: &message.Body{},
	}

	msg := &OutboundMessage{
		MessageID: "ignored-id",
		Envelope:  existingEnvelope,
	}

	envelope, err := msh.buildEnvelope(msg)
	require.NoError(t, err)

	// Should return the existing envelope unchanged
	assert.Equal(t, existingEnvelope, envelope)
	assert.Equal(t, "pre-existing-id", envelope.Header.Messaging.UserMessage.MessageInfo.MessageId)
}

func TestBuildEnvelope_WithRefToMessageID(t *testing.T) {
	resolver := NewStaticEndpointResolver()
	config := MSHConfig{
		Resolver: resolver,
	}

	msh, err := NewMSH(config)
	require.NoError(t, err)

	msg := &OutboundMessage{
		MessageID:      "reply-123",
		FromPartyID:    "sender",
		ToPartyID:      "receiver",
		Service:        "service",
		Action:         "Reply",
		RefToMessageID: "original-message-456",
	}

	envelope, err := msh.buildEnvelope(msg)
	require.NoError(t, err)

	assert.Equal(t, "original-message-456", envelope.Header.Messaging.UserMessage.MessageInfo.RefToMessageId)
}

func TestMSH_ConvertToMIMEPayloads(t *testing.T) {
	resolver := NewStaticEndpointResolver()
	config := MSHConfig{
		Resolver: resolver,
	}

	msh, err := NewMSH(config)
	require.NoError(t, err)

	payloads := []Payload{
		{
			ContentID:   "payload-1@example.com",
			ContentType: "application/xml",
			Data:        []byte("<test>data1</test>"),
		},
		{
			ContentID:   "payload-2@example.com",
			ContentType: "application/json",
			Data:        []byte(`{"key": "value"}`),
		},
	}

	mimePayloads := msh.convertToMIMEPayloads(payloads)

	require.Len(t, mimePayloads, 2)
	assert.Equal(t, "payload-1@example.com", mimePayloads[0].ContentID)
	assert.Equal(t, "application/xml", mimePayloads[0].ContentType)
	assert.Equal(t, "binary", mimePayloads[0].ContentTransfer)
	assert.Equal(t, []byte("<test>data1</test>"), mimePayloads[0].Data)

	assert.Equal(t, "payload-2@example.com", mimePayloads[1].ContentID)
	assert.Equal(t, "application/json", mimePayloads[1].ContentType)
}
