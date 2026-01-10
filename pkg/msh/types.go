// Package msh implements the Message Service Handler (MSH) as defined in AS4 2.0package msh

// The MSH is responsible for sending and receiving AS4 messages, including
// security processing, reliability, and message exchange patterns.
package msh

import (
	"time"

	"github.com/sirosfoundation/go-as4/pkg/message"
	"github.com/sirosfoundation/go-as4/pkg/pmode"
)

// MessageStatus represents the current state of a message
type MessageStatus string

const (
	// MessageStatusPending indicates the message is queued for sending
	MessageStatusPending MessageStatus = "PENDING"
	// MessageStatusSending indicates the message is being transmitted
	MessageStatusSending MessageStatus = "SENDING"
	// MessageStatusSent indicates the message was successfully sent
	MessageStatusSent MessageStatus = "SENT"
	// MessageStatusReceived indicates the message was received
	MessageStatusReceived MessageStatus = "RECEIVED"
	// MessageStatusAcknowledged indicates receipt was acknowledged
	MessageStatusAcknowledged MessageStatus = "ACKNOWLEDGED"
	// MessageStatusFailed indicates the message failed to send/receive
	MessageStatusFailed MessageStatus = "FAILED"
	// MessageStatusRetrying indicates the message is being retried
	MessageStatusRetrying MessageStatus = "RETRYING"
)

// MessageDirection indicates whether this is an outbound or inbound message
type MessageDirection string

const (
	// MessageDirectionOutbound for messages being sent
	MessageDirectionOutbound MessageDirection = "OUTBOUND"
	// MessageDirectionInbound for messages being received
	MessageDirectionInbound MessageDirection = "INBOUND"
)

// MessageMetadata contains metadata about a message being processed
type MessageMetadata struct {
	MessageID      string
	ConversationID string
	RefToMessageID string
	Timestamp      time.Time
	Direction      MessageDirection
	Status         MessageStatus
	RetryCount     int
	PMode          *pmode.ProcessingMode
	Endpoint       string
	Error          error
	LastError      string
	FromPartyID    string
	ToPartyID      string
	Service        string
	Action         string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// OutboundMessage represents a message to be sent
type OutboundMessage struct {
	MessageID      string
	RefToMessageID string
	FromPartyID    string
	ToPartyID      string
	Service        string
	Action         string
	ConversationID string
	Envelope       *message.Envelope
	Payloads       []Payload
	PMode          *pmode.ProcessingMode
	Metadata       *MessageMetadata
}

// Payload represents a message payload/attachment
type Payload struct {
	ContentID   string
	ContentType string
	Data        []byte
	Properties  map[string]string
}

// InboundMessage represents a received message
type InboundMessage struct {
	MessageID      string
	RefToMessageID string
	FromPartyID    string
	ToPartyID      string
	Service        string
	Action         string
	Envelope       *message.Envelope
	Payloads       []Payload
	RawData        []byte
	PMode          *pmode.ProcessingMode
	ReceiptRequest *ReceiptRequest
	Metadata       *MessageMetadata
}

// MessageEvent represents an event in the message lifecycle
type MessageEvent struct {
	Type      string
	MessageID string
	Timestamp time.Time
	Status    MessageStatus
	Direction MessageDirection
	Error     error
	Data      map[string]interface{}
}

// ReceiptRequest represents a request for a receipt/acknowledgment
type ReceiptRequest struct {
	OriginalMessageID string
	ReceiptType       string
	Timestamp         time.Time
}

// PullRequest represents an AS4 pull request
type PullRequest struct {
	MPC       string // Message Partition Channel
	PMode     *pmode.ProcessingMode
	Timestamp time.Time
}

// EndpointInfo contains information about a message endpoint
type EndpointInfo struct {
	URL         string
	Certificate []byte
	PartyID     string
	Service     string
	Action      string
	Properties  map[string]string
}

// MessageHandler is the callback function for processing received messages
type MessageHandler func(*InboundMessage)

// EventHandler is the callback function for message lifecycle events
type EventHandler func(MessageEvent)

// ErrorHandler is the callback function for handling errors
type ErrorHandler func(messageID string, err error)
