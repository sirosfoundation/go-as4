// Package as4 provides the main interface for AS4 messagingpackage as4

package as4

import (
	"context"
	"encoding/xml"
	"fmt"

	"github.com/sirosfoundation/go-as4/pkg/compression"
	"github.com/sirosfoundation/go-as4/pkg/mep"
	"github.com/sirosfoundation/go-as4/pkg/message"
	"github.com/sirosfoundation/go-as4/pkg/pmode"
	"github.com/sirosfoundation/go-as4/pkg/reliability"
	"github.com/sirosfoundation/go-as4/pkg/security"
	"github.com/sirosfoundation/go-as4/pkg/transport"
)

// Client is the main AS4 client for sending messages
type Client struct {
	httpClient   *transport.HTTPSClient
	pmodeManager *pmode.PModeManager
	tracker      *reliability.MessageTracker
	compressor   *compression.Compressor
	secConfig    *security.SecurityConfig
}

// ClientConfig holds client configuration
type ClientConfig struct {
	HTTPSConfig    *transport.HTTPSConfig
	SecurityConfig *security.SecurityConfig
	PMode          *pmode.ProcessingMode
}

// NewClient creates a new AS4 client
func NewClient(config *ClientConfig) (*Client, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	httpClient := transport.NewHTTPSClient(config.HTTPSConfig)

	pmodeManager := pmode.NewPModeManager()
	if config.PMode != nil {
		pmodeManager.AddPMode(config.PMode)
	}

	var duplicateWindow = pmode.DefaultPMode().ReceptionAwareness.DuplicateDetection.Window
	if config.PMode != nil && config.PMode.ReceptionAwareness != nil {
		duplicateWindow = config.PMode.ReceptionAwareness.DuplicateDetection.Window
	}

	return &Client{
		httpClient:   httpClient,
		pmodeManager: pmodeManager,
		tracker:      reliability.NewMessageTracker(duplicateWindow),
		compressor:   compression.NewCompressor(),
		secConfig:    config.SecurityConfig,
	}, nil
}

// SendMessage sends an AS4 message
func (c *Client) SendMessage(ctx context.Context, msg *message.UserMessage, payloads []message.PayloadPart, endpoint string) (*message.SignalMessage, error) {
	// 1. Find or use P-Mode
	pmode := c.pmodeManager.FindPMode(
		msg.CollaborationInfo.Service.Value,
		msg.CollaborationInfo.Action,
		msg.PartyInfo.From.PartyId[0].Value,
		msg.PartyInfo.To.PartyId[0].Value,
	)
	if pmode == nil {
		return nil, fmt.Errorf("no matching P-Mode found")
	}

	// 2. Compress payloads if configured
	if pmode.PayloadService != nil && pmode.PayloadService.CompressionType == compression.CompressionTypeGzip {
		for i := range payloads {
			if compression.ShouldCompress(payloads[i].ContentType) {
				compressed, err := c.compressor.Compress(payloads[i].Data)
				if err != nil {
					return nil, fmt.Errorf("failed to compress payload: %w", err)
				}
				payloads[i].Data = compressed
				payloads[i].Compressed = true
			}
		}
	}

	// 3. Build envelope
	envelope := &message.Envelope{
		Header: &message.Header{
			Messaging: &message.Messaging{
				UserMessage: msg,
			},
		},
		Body: &message.Body{},
	}

	// 4. Sign message (if configured)
	// TODO: Implement signing with Ed25519

	// 5. Encrypt message (if configured)
	// TODO: Implement encryption with X25519/HKDF/AES-GCM

	// 6. Serialize to SOAP
	soapData, err := xml.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize message: %w", err)
	}

	// 7. Track message
	messageID := msg.MessageInfo.MessageId
	if pmode.ReceptionAwareness != nil && pmode.ReceptionAwareness.Enabled {
		c.tracker.Track(
			messageID,
			pmode.ReceptionAwareness.Retry.MaxRetries,
			pmode.ReceptionAwareness.Retry.RetryInterval,
			pmode.ReceptionAwareness.Retry.RetryMultiplier,
		)
	}

	// 8. Send via HTTPS
	c.tracker.MarkSending(messageID)

	response, err := c.httpClient.Send(ctx, endpoint, soapData, "application/soap+xml; charset=utf-8")
	if err != nil {
		c.tracker.RecordError(messageID, err)
		return nil, fmt.Errorf("failed to send message: %w", err)
	}

	c.tracker.MarkAwaitingReceipt(messageID)

	// 9. Parse response (receipt or error)
	var responseEnvelope message.Envelope
	if err := xml.Unmarshal(response, &responseEnvelope); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if responseEnvelope.Header == nil || responseEnvelope.Header.Messaging == nil {
		return nil, fmt.Errorf("invalid response: missing messaging header")
	}

	signalMsg := responseEnvelope.Header.Messaging.SignalMessage
	if signalMsg == nil {
		return nil, fmt.Errorf("invalid response: missing signal message")
	}

	// 10. Process receipt/error
	if signalMsg.Receipt != nil {
		c.tracker.RecordReceipt(messageID, signalMsg.Receipt.Any)
	} else if signalMsg.Error != nil {
		err := fmt.Errorf("received error: %s - %s",
			signalMsg.Error.ErrorCode, signalMsg.Error.ShortDescription)
		c.tracker.RecordError(messageID, err)
		return nil, err
	}

	return signalMsg, nil
}

// Server handles incoming AS4 messages
type Server struct {
	httpServer   *transport.HTTPSServer
	tracker      *reliability.MessageTracker
	compressor   *compression.Compressor
	secConfig    *security.SecurityConfig
	pmodeManager *pmode.PModeManager
	mepHandler   mep.Handler
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Address        string
	HTTPSConfig    *transport.HTTPSConfig
	SecurityConfig *security.SecurityConfig
	PModeManager   *pmode.PModeManager
	MEPHandler     mep.Handler
}

// NewServer creates a new AS4 server
func NewServer(config *ServerConfig) (*Server, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	server := &Server{
		tracker:      reliability.NewMessageTracker(pmode.DefaultPMode().ReceptionAwareness.DuplicateDetection.Window),
		compressor:   compression.NewCompressor(),
		secConfig:    config.SecurityConfig,
		pmodeManager: config.PModeManager,
		mepHandler:   config.MEPHandler,
	}

	server.httpServer = transport.NewHTTPSServer(config.Address, config.HTTPSConfig, server)

	return server, nil
}

// HandleMessage implements transport.AS4Handler
func (s *Server) HandleMessage(ctx context.Context, messageData []byte) ([]byte, error) {
	// 1. Parse message
	var envelope message.Envelope
	if err := xml.Unmarshal(messageData, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse message: %w", err)
	}

	if envelope.Header == nil || envelope.Header.Messaging == nil {
		return nil, fmt.Errorf("invalid message: missing messaging header")
	}

	userMsg := envelope.Header.Messaging.UserMessage
	if userMsg == nil {
		return nil, fmt.Errorf("invalid message: missing user message")
	}

	messageID := userMsg.MessageInfo.MessageId

	// 2. Check for duplicates
	if s.tracker.IsDuplicate(messageID) {
		// Return cached receipt if available
		// For now, just indicate it's a duplicate
		return nil, fmt.Errorf("duplicate message: %s", messageID)
	}

	s.tracker.MarkReceived(messageID)

	// 3. Verify signature
	// TODO: Implement signature verification

	// 4. Decrypt if encrypted
	// TODO: Implement decryption

	// 5. Decompress payloads
	// TODO: Process payloads from MIME parts

	// 6. Validate against P-Mode
	// TODO: Implement P-Mode matching and validation

	// 7. Process business message via MEP handler
	if s.mepHandler != nil {
		// This would delegate to business logic
		_, err := s.mepHandler.HandleRequest(ctx, messageData)
		if err != nil {
			// Generate error signal
			errorMsg := message.NewError(
				messageID,
				reliability.ErrorDeliveryFailure.Code,
				reliability.ErrorDeliveryFailure.Severity,
				reliability.ErrorDeliveryFailure.ShortDescription,
				err.Error(),
			)

			return s.serializeSignal(errorMsg)
		}
	}

	// 8. Generate receipt
	receipt := message.NewReceipt(messageID, true)

	return s.serializeSignal(receipt)
}

// serializeSignal serializes a signal message to SOAP
func (s *Server) serializeSignal(signal *message.SignalMessage) ([]byte, error) {
	envelope := &message.Envelope{
		Header: &message.Header{
			Messaging: &message.Messaging{
				SignalMessage: signal,
			},
		},
		Body: &message.Body{},
	}

	return xml.MarshalIndent(envelope, "", "  ")
}

// Start starts the AS4 server
func (s *Server) Start() error {
	return s.httpServer.Start()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}
