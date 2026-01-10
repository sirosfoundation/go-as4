package msh

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sirosfoundation/go-as4/pkg/compression"
	"github.com/sirosfoundation/go-as4/pkg/message"
	"github.com/sirosfoundation/go-as4/pkg/mime"
	"github.com/sirosfoundation/go-as4/pkg/pmode"
	"github.com/sirosfoundation/go-as4/pkg/security"
	"github.com/sirosfoundation/go-as4/pkg/transport"
)

var (
	// ErrMSHNotStarted is returned when operations are attempted on a stopped MSH
	ErrMSHNotStarted = errors.New("MSH not started")
	// ErrMSHAlreadyStarted is returned when Start is called on a running MSH
	ErrMSHAlreadyStarted = errors.New("MSH already started")
	// ErrInvalidMessage is returned for malformed messages
	ErrInvalidMessage = errors.New("invalid message")
)

// MSH (Message Service Handler) manages AS4 message sending and receiving
// with integrated security, reliability, and compression features.
// It supports asynchronous operations using Go channels and goroutines.
type MSH struct {
	// Configuration
	resolver          EndpointResolver
	pmodeRegistry     map[string]*pmode.ProcessingMode // pmodeID -> pmode
	encryptor         *security.Encryptor
	securityProcessor *SecurityProcessor // Integrated security handling
	compressor        compression.Compressor
	httpClient        *transport.HTTPSClient

	// Message handlers
	messageHandler MessageHandler
	eventHandler   EventHandler
	errorHandler   ErrorHandler

	// Async channels
	outboundQueue chan *OutboundMessage
	inboundQueue  chan *InboundMessage
	eventQueue    chan MessageEvent

	// State management
	mu       sync.RWMutex
	running  bool
	messages map[string]*MessageMetadata // messageID -> metadata

	// Worker control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Configuration options
	workerCount      int
	maxQueueSize     int
	retryMaxAttempts int
	retryDelay       time.Duration
}

// MSHConfig holds configuration for the MSH
type MSHConfig struct {
	Resolver      EndpointResolver
	PModeRegistry map[string]*pmode.ProcessingMode
	Encryptor     *security.Encryptor // Deprecated: Use Signer and AESEncryptor

	// Security configuration
	Signer       security.Signer // XML Signer (RSASigner or AS4Signer)
	AESEncryptor *security.AESEncryptor

	Compressor compression.Compressor
	HTTPClient *transport.HTTPSClient

	MessageHandler MessageHandler
	EventHandler   EventHandler
	ErrorHandler   ErrorHandler

	WorkerCount      int
	MaxQueueSize     int
	RetryMaxAttempts int
	RetryDelay       time.Duration
}

// NewMSH creates a new Message Service Handler with the provided configuration
func NewMSH(config MSHConfig) (*MSH, error) {
	if config.Resolver == nil {
		return nil, errors.New("resolver is required")
	}
	if config.PModeRegistry == nil {
		config.PModeRegistry = make(map[string]*pmode.ProcessingMode)
	}

	// Set defaults
	if config.WorkerCount == 0 {
		config.WorkerCount = 4
	}
	if config.MaxQueueSize == 0 {
		config.MaxQueueSize = 100
	}
	if config.RetryMaxAttempts == 0 {
		config.RetryMaxAttempts = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 5 * time.Second
	}

	// Initialize security processor if signer or encryptor provided
	var securityProcessor *SecurityProcessor
	if config.Signer != nil || config.AESEncryptor != nil {
		securityProcessor = NewSecurityProcessor(config.Signer, config.AESEncryptor)
	}

	return &MSH{
		resolver:          config.Resolver,
		pmodeRegistry:     config.PModeRegistry,
		encryptor:         config.Encryptor,
		securityProcessor: securityProcessor,
		compressor:        config.Compressor,
		httpClient:        config.HTTPClient,
		messageHandler:    config.MessageHandler,
		eventHandler:      config.EventHandler,
		errorHandler:      config.ErrorHandler,
		outboundQueue:     make(chan *OutboundMessage, config.MaxQueueSize),
		inboundQueue:      make(chan *InboundMessage, config.MaxQueueSize),
		eventQueue:        make(chan MessageEvent, config.MaxQueueSize),
		messages:          make(map[string]*MessageMetadata),
		workerCount:       config.WorkerCount,
		maxQueueSize:      config.MaxQueueSize,
		retryMaxAttempts:  config.RetryMaxAttempts,
		retryDelay:        config.RetryDelay,
	}, nil
}

// Start begins async message processing
func (m *MSH) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return ErrMSHAlreadyStarted
	}

	m.ctx, m.cancel = context.WithCancel(ctx)
	m.running = true

	// Start outbound workers
	for i := 0; i < m.workerCount; i++ {
		m.wg.Add(1)
		go m.outboundWorker(i)
	}

	// Start inbound workers
	for i := 0; i < m.workerCount; i++ {
		m.wg.Add(1)
		go m.inboundWorker(i)
	}

	// Start event dispatcher
	m.wg.Add(1)
	go m.eventDispatcher()

	return nil
}

// Stop gracefully shuts down the MSH
func (m *MSH) Stop() error {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return ErrMSHNotStarted
	}

	m.running = false
	m.cancel()
	m.mu.Unlock()

	// Wait for workers to finish
	m.wg.Wait()

	return nil
}

// SendMessage queues an outbound message for async processing
func (m *MSH) SendMessage(ctx context.Context, msg *OutboundMessage) error {
	m.mu.RLock()
	running := m.running
	m.mu.RUnlock()

	if !running {
		return ErrMSHNotStarted
	}

	// Validate message
	if err := m.validateOutboundMessage(msg); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidMessage, err)
	}

	// Initialize metadata
	metadata := &MessageMetadata{
		MessageID:   msg.MessageID,
		Status:      MessageStatusPending,
		Direction:   MessageDirectionOutbound,
		PMode:       msg.PMode,
		FromPartyID: msg.FromPartyID,
		ToPartyID:   msg.ToPartyID,
		Service:     msg.Service,
		Action:      msg.Action,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	m.mu.Lock()
	m.messages[msg.MessageID] = metadata
	m.mu.Unlock()

	// Queue for processing
	select {
	case m.outboundQueue <- msg:
		m.emitEvent(MessageEvent{
			Type:      "message.queued",
			MessageID: msg.MessageID,
			Timestamp: time.Now(),
		})
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ReceiveMessage handles an inbound message
func (m *MSH) ReceiveMessage(ctx context.Context, msg *InboundMessage) error {
	m.mu.RLock()
	running := m.running
	m.mu.RUnlock()

	if !running {
		return ErrMSHNotStarted
	}

	// Queue for processing
	select {
	case m.inboundQueue <- msg:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// GetMessageStatus retrieves the current status of a message
func (m *MSH) GetMessageStatus(messageID string) (*MessageMetadata, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	metadata, ok := m.messages[messageID]
	if !ok {
		return nil, fmt.Errorf("message not found: %s", messageID)
	}

	return metadata, nil
}

// outboundWorker processes outbound messages from the queue
func (m *MSH) outboundWorker(id int) {
	defer m.wg.Done()

	for {
		select {
		case <-m.ctx.Done():
			return
		case msg := <-m.outboundQueue:
			if err := m.processOutboundMessage(msg); err != nil {
				m.handleError(msg.MessageID, err)
			}
		}
	}
}

// inboundWorker processes inbound messages from the queue
func (m *MSH) inboundWorker(id int) {
	defer m.wg.Done()

	for {
		select {
		case <-m.ctx.Done():
			return
		case msg := <-m.inboundQueue:
			if err := m.processInboundMessage(msg); err != nil {
				m.handleError(msg.MessageID, err)
			}
		}
	}
}

// eventDispatcher sends events to the event handler
func (m *MSH) eventDispatcher() {
	defer m.wg.Done()

	for {
		select {
		case <-m.ctx.Done():
			return
		case event := <-m.eventQueue:
			if m.eventHandler != nil {
				m.eventHandler(event)
			}
		}
	}
}

// processOutboundMessage handles the complete outbound message flow
func (m *MSH) processOutboundMessage(msg *OutboundMessage) error {
	m.updateStatus(msg.MessageID, MessageStatusSending)

	// Resolve endpoint
	endpoint, err := m.resolver.ResolveEndpoint(m.ctx, msg.ToPartyID, msg.Service, msg.Action)
	if err != nil {
		return fmt.Errorf("endpoint resolution failed: %w", err)
	}

	// Build AS4 envelope
	envelope, err := m.buildEnvelope(msg)
	if err != nil {
		return fmt.Errorf("envelope building failed: %w", err)
	}

	// Apply compression if configured
	if msg.PMode != nil && msg.PMode.PayloadService != nil && msg.PMode.PayloadService.CompressionType != "" {
		// Compression will be handled at the payload level in future enhancement
	}

	// Apply security
	if err := m.applyOutboundSecurity(envelope, msg, msg.PMode); err != nil {
		return fmt.Errorf("security application failed: %w", err)
	}

	// Send via HTTP
	if m.httpClient != nil {
		// Serialize to MIME multipart/related format
		mimePayloads := m.convertToMIMEPayloads(msg.Payloads)
		mimeMsg := mime.NewMessage(envelope, mimePayloads)

		messageBytes, contentType, err := mimeMsg.Serialize()
		if err != nil {
			return fmt.Errorf("MIME serialization failed: %w", err)
		}

		_, err = m.httpClient.Send(m.ctx, endpoint.URL, messageBytes, contentType)
		if err != nil {
			return m.handleSendError(msg, err)
		}
	}

	m.updateStatus(msg.MessageID, MessageStatusSent)
	m.emitEvent(MessageEvent{
		Type:      "message.sent",
		MessageID: msg.MessageID,
		Timestamp: time.Now(),
	})

	return nil
}

// processInboundMessage handles the complete inbound message flow
func (m *MSH) processInboundMessage(msg *InboundMessage) error {
	m.updateStatus(msg.MessageID, MessageStatusReceived)

	// Serialize envelope to XML for security verification
	var envelopeXML []byte
	if msg.Envelope != nil {
		var err error
		envelopeXML, err = xml.Marshal(msg.Envelope)
		if err != nil {
			return fmt.Errorf("failed to marshal envelope: %w", err)
		}
	}

	// Apply security verification
	if err := m.applyInboundSecurity(envelopeXML, msg, msg.PMode); err != nil {
		return fmt.Errorf("security verification failed: %w", err)
	}

	// Handle message based on type
	if m.messageHandler != nil {
		m.messageHandler(msg)
	}

	// Generate receipt if required
	if msg.ReceiptRequest != nil {
		if err := m.generateReceipt(msg); err != nil {
			return fmt.Errorf("receipt generation failed: %w", err)
		}
	}

	m.emitEvent(MessageEvent{
		Type:      "message.received",
		MessageID: msg.MessageID,
		Timestamp: time.Now(),
	})

	return nil
}

// buildEnvelope constructs an AS4 SOAP envelope from the outbound message
func (m *MSH) buildEnvelope(msg *OutboundMessage) (*message.Envelope, error) {
	// Use existing envelope if provided
	if msg.Envelope != nil {
		return msg.Envelope, nil
	}

	// Create envelope with messaging header
	envelope := &message.Envelope{
		Header: &message.Header{
			Messaging: &message.Messaging{},
		},
		Body: &message.Body{},
	}

	// Add user message header
	userMsg := &message.UserMessage{
		MessageInfo: &message.MessageInfo{
			MessageId: msg.MessageID,
			Timestamp: time.Now(),
		},
		PartyInfo: &message.PartyInfo{
			From: &message.Party{
				PartyId: []message.PartyId{{Value: msg.FromPartyID}},
				Role:    "Sender",
			},
			To: &message.Party{
				PartyId: []message.PartyId{{Value: msg.ToPartyID}},
				Role:    "Receiver",
			},
		},
		CollaborationInfo: &message.CollaborationInfo{
			Service: message.Service{Value: msg.Service},
			Action:  msg.Action,
		},
	}

	if msg.RefToMessageID != "" {
		userMsg.MessageInfo.RefToMessageId = msg.RefToMessageID
	}

	// Add payloads
	if len(msg.Payloads) > 0 {
		userMsg.PayloadInfo = &message.PayloadInfo{}
		for _, payload := range msg.Payloads {
			userMsg.PayloadInfo.PartInfo = append(userMsg.PayloadInfo.PartInfo, message.PartInfo{
				Href: payload.ContentID,
			})
		}
	}

	envelope.Header.Messaging.UserMessage = userMsg

	return envelope, nil
}

// applyOutboundSecurity applies signing and encryption to outbound messages
func (m *MSH) applyOutboundSecurity(envelope *message.Envelope, msg *OutboundMessage, pm *pmode.ProcessingMode) error {
	if m.securityProcessor == nil {
		return nil // No security configured
	}

	if pm == nil || pm.Security == nil || pm.Security.X509 == nil {
		return nil // No security policy
	}

	// Encrypt payloads if configured
	if pm.Security.X509.Encryption != nil && m.securityProcessor.HasEncryptor() {
		if err := m.securityProcessor.EncryptPayloads(msg.Payloads); err != nil {
			return fmt.Errorf("payload encryption failed: %w", err)
		}
	}

	// Sign envelope if configured
	// Note: Signing modifies the envelope by adding Security headers.
	// The signed XML is produced but we don't unmarshal it back to avoid
	// struct/XML namespace conflicts. The Security header elements are
	// added directly to the envelope by the SecurityProcessor.
	if pm.Security.X509.Sign != nil && m.securityProcessor.HasSigner() {
		_, err := m.securityProcessor.SignEnvelope(envelope)
		if err != nil {
			return fmt.Errorf("envelope signing failed: %w", err)
		}
		// Signed XML is generated for wire format; envelope struct is modified in-place
	}

	return nil
}

// applyInboundSecurity verifies signatures and decrypts inbound messages
func (m *MSH) applyInboundSecurity(envelopeXML []byte, msg *InboundMessage, pm *pmode.ProcessingMode) error {
	if m.securityProcessor == nil {
		return nil // No security configured
	}

	if pm == nil || pm.Security == nil || pm.Security.X509 == nil {
		return nil // No security policy
	}

	// Verify signature if required
	if pm.Security.X509.Sign != nil && m.securityProcessor.HasSigner() {
		if err := m.securityProcessor.VerifyEnvelope(envelopeXML); err != nil {
			return fmt.Errorf("signature verification failed: %w", err)
		}
	}

	// Decrypt payloads if encrypted
	// Note: In production, we'd need the recipient's private key from secure storage
	// For now, this is a placeholder - actual key management would be configured separately
	if pm.Security.X509.Encryption != nil {
		// TODO: Implement payload decryption with proper key management
		// privateKey := getPrivateKeyFromKeyStore()
		// if err := m.securityProcessor.DecryptPayloads(msg.Payloads, privateKey); err != nil {
		//     return fmt.Errorf("payload decryption failed: %w", err)
		// }
	}

	return nil
}

// generateReceipt creates and sends a receipt for an inbound message
func (m *MSH) generateReceipt(msg *InboundMessage) error {
	// Build receipt message
	receipt := &OutboundMessage{
		MessageID:      generateMessageID(),
		RefToMessageID: msg.MessageID,
		FromPartyID:    msg.ToPartyID,
		ToPartyID:      msg.FromPartyID,
		Service:        msg.Service,
		Action:         "Receipt",
		PMode:          msg.PMode,
	}

	// Queue receipt for sending
	return m.SendMessage(m.ctx, receipt)
}

// handleSendError handles transmission errors with retry logic
func (m *MSH) handleSendError(msg *OutboundMessage, err error) error {
	metadata, _ := m.GetMessageStatus(msg.MessageID)
	if metadata == nil {
		return err
	}

	if metadata.RetryCount < m.retryMaxAttempts {
		m.updateStatus(msg.MessageID, MessageStatusRetrying)
		metadata.RetryCount++
		metadata.LastError = err.Error()

		// Schedule retry
		go func() {
			time.Sleep(m.retryDelay)
			m.outboundQueue <- msg
		}()

		return nil
	}

	m.updateStatus(msg.MessageID, MessageStatusFailed)
	return err
}

// validateOutboundMessage checks if an outbound message is valid
func (m *MSH) validateOutboundMessage(msg *OutboundMessage) error {
	if msg.MessageID == "" {
		return errors.New("message ID is required")
	}
	if msg.FromPartyID == "" {
		return errors.New("from party ID is required")
	}
	if msg.ToPartyID == "" {
		return errors.New("to party ID is required")
	}
	if msg.Service == "" {
		return errors.New("service is required")
	}
	if msg.Action == "" {
		return errors.New("action is required")
	}
	return nil
}

// updateStatus updates the status of a message
func (m *MSH) updateStatus(messageID string, status MessageStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if metadata, ok := m.messages[messageID]; ok {
		metadata.Status = status
		metadata.UpdatedAt = time.Now()
	}
}

// convertToMIMEPayloads converts MSH payloads to MIME payloads
func (m *MSH) convertToMIMEPayloads(payloads []Payload) []mime.Payload {
	mimePayloads := make([]mime.Payload, len(payloads))
	for i, payload := range payloads {
		mimePayloads[i] = mime.Payload{
			ContentID:       payload.ContentID,
			ContentType:     payload.ContentType,
			ContentTransfer: "binary",
			Data:            payload.Data,
		}
	}
	return mimePayloads
}

// emitEvent sends an event to the event queue
func (m *MSH) emitEvent(event MessageEvent) {
	select {
	case m.eventQueue <- event:
	default:
		// Event queue full, drop event
	}
}

// handleError invokes the error handler if configured
func (m *MSH) handleError(messageID string, err error) {
	m.updateStatus(messageID, MessageStatusFailed)

	if m.errorHandler != nil {
		m.errorHandler(messageID, err)
	}

	m.emitEvent(MessageEvent{
		Type:      "message.error",
		MessageID: messageID,
		Timestamp: time.Now(),
		Data:      map[string]interface{}{"error": err.Error()},
	})
}

// generateMessageID creates a unique message identifier
func generateMessageID() string {
	return fmt.Sprintf("%d@siros.org", time.Now().UnixNano())
}
