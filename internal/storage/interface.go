// Package storage provides data storage interfaces and implementations
// for the multi-tenant AS4 server.
//
// # Interface Design
//
// The storage layer is organized into focused interfaces:
//
//   - [TenantStore]: Multi-tenant configuration and metadata
//   - [ParticipantStore]: Trading partner (participant) management
//   - [MailboxStore]: Per-participant mailboxes for message organization
//   - [MessageStore]: AS4 message metadata and status tracking
//   - [PayloadStore]: Binary payload storage with streaming support
//   - [EncryptedKeyStore]: Encrypted signing key storage for PRF mode
//   - [StateStore]: JMAP state tracking for efficient synchronization
//
// The [Store] interface combines all sub-stores for convenience.
//
// # Implementations
//
// The mongodb sub-package provides a production-ready MongoDB implementation.
// Additional backends (PostgreSQL, in-memory) may be added.
//
// # Concurrency
//
// All store implementations must be safe for concurrent use from multiple
// goroutines. The MongoDB implementation uses connection pooling and
// supports optimistic locking via version fields.
package storage

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/sirosfoundation/go-as4/internal/keystore"
)

// Store is the main storage interface combining all sub-stores
type Store interface {
	TenantStore
	ParticipantStore
	MailboxStore
	MessageStore
	PayloadStore
	EncryptedKeyStore
	StateStore

	// Close releases storage resources
	Close(ctx context.Context) error

	// Ping checks database connectivity
	Ping(ctx context.Context) error
}

// TenantStore manages tenant data
type TenantStore interface {
	// CreateTenant creates a new tenant
	CreateTenant(ctx context.Context, tenant *Tenant) error

	// GetTenant retrieves a tenant by ID
	GetTenant(ctx context.Context, id string) (*Tenant, error)

	// GetTenantByDomain retrieves a tenant by domain
	GetTenantByDomain(ctx context.Context, domain string) (*Tenant, error)

	// UpdateTenant updates a tenant
	UpdateTenant(ctx context.Context, tenant *Tenant) error

	// DeleteTenant deletes a tenant (soft delete)
	DeleteTenant(ctx context.Context, id string) error

	// ListTenants returns all tenants
	ListTenants(ctx context.Context, filter *TenantFilter) ([]*Tenant, error)
}

// ParticipantStore manages participant data
type ParticipantStore interface {
	// CreateParticipant creates a new participant
	CreateParticipant(ctx context.Context, participant *Participant) error

	// GetParticipant retrieves a participant by ID
	GetParticipant(ctx context.Context, tenantID, id string) (*Participant, error)

	// GetParticipantByPartyID retrieves a participant by AS4 party ID
	GetParticipantByPartyID(ctx context.Context, tenantID string, partyID PartyID) (*Participant, error)

	// UpdateParticipant updates a participant
	UpdateParticipant(ctx context.Context, participant *Participant) error

	// DeleteParticipant deletes a participant
	DeleteParticipant(ctx context.Context, tenantID, id string) error

	// ListParticipants returns participants for a tenant
	ListParticipants(ctx context.Context, tenantID string, filter *ParticipantFilter) ([]*Participant, error)
}

// MailboxStore manages mailbox data
type MailboxStore interface {
	// GetMailbox retrieves a mailbox by ID
	GetMailbox(ctx context.Context, tenantID, id string) (*Mailbox, error)

	// GetMailboxByParticipant retrieves the mailbox for a participant
	GetMailboxByParticipant(ctx context.Context, tenantID, participantID string) (*Mailbox, error)

	// CreateMailbox creates a new mailbox
	CreateMailbox(ctx context.Context, mailbox *Mailbox) error

	// UpdateMailbox updates a mailbox
	UpdateMailbox(ctx context.Context, mailbox *Mailbox) error

	// ListMailboxes returns mailboxes for a tenant
	ListMailboxes(ctx context.Context, tenantID string) ([]*Mailbox, error)
}

// MessageStore manages message data
type MessageStore interface {
	// CreateMessage stores a new message
	CreateMessage(ctx context.Context, msg *Message) error

	// GetMessage retrieves a message by ID
	GetMessage(ctx context.Context, tenantID, id string) (*Message, error)

	// GetMessageByAS4ID retrieves a message by AS4 message ID
	GetMessageByAS4ID(ctx context.Context, tenantID, as4MessageID string) (*Message, error)

	// UpdateMessage updates a message
	UpdateMessage(ctx context.Context, msg *Message) error

	// UpdateMessageStatus updates just the status of a message
	UpdateMessageStatus(ctx context.Context, tenantID, id string, status MessageStatus) error

	// ListMessages returns messages with filtering
	ListMessages(ctx context.Context, tenantID string, filter *MessageFilter) ([]*Message, error)

	// CountMessages returns message count with filtering
	CountMessages(ctx context.Context, tenantID string, filter *MessageFilter) (int64, error)

	// GetPendingOutbound returns messages pending delivery
	GetPendingOutbound(ctx context.Context, tenantID string, limit int) ([]*Message, error)
}

// PayloadStore manages message payloads (large binary data)
type PayloadStore interface {
	// StorePayload stores a payload and returns its ID
	StorePayload(ctx context.Context, tenantID string, payload *PayloadData) (string, error)

	// GetPayload retrieves a payload by ID
	GetPayload(ctx context.Context, tenantID, id string) (*PayloadData, error)

	// DeletePayload deletes a payload
	DeletePayload(ctx context.Context, tenantID, id string) error
}

// EncryptedKeyStore stores encrypted signing keys (for PRF mode)
// This implements the keystore.EncryptedKeyStore interface
type EncryptedKeyStore interface {
	keystore.EncryptedKeyStore

	// StoreEncryptedKey stores an encrypted key blob
	StoreEncryptedKey(ctx context.Context, tenantID string, blob *keystore.EncryptedKeyBlob) error

	// StoreCertificate stores a certificate
	StoreCertificate(ctx context.Context, tenantID, keyID string, cert *x509.Certificate) error

	// DeleteKey deletes an encrypted key and its certificate
	DeleteKey(ctx context.Context, tenantID, keyID string) error
}

// StateStore provides state tracking for JMAP synchronization
type StateStore interface {
	// GetState returns the current state string for a data type within a tenant
	// dataType is one of: "AS4Message", "AS4Mailbox", "AS4Participant"
	GetState(ctx context.Context, tenantID, dataType string) (string, error)

	// GetChanges returns changes since a given state
	// Returns created, updated, destroyed IDs and the new state
	// If sinceState is invalid/expired, returns ErrStateNotFound
	GetChanges(ctx context.Context, tenantID, dataType, sinceState string, maxChanges int) (*Changes, error)

	// Subscribe returns a channel that receives state change events for a tenant
	// The channel is closed when the context is cancelled
	// Multiple data types can be subscribed to at once
	Subscribe(ctx context.Context, tenantID string, dataTypes []string) (<-chan StateChange, error)
}

// Changes represents the delta between two states
type Changes struct {
	OldState       string   `json:"oldState"`
	NewState       string   `json:"newState"`
	HasMoreChanges bool     `json:"hasMoreChanges"`
	Created        []string `json:"created"`
	Updated        []string `json:"updated"`
	Destroyed      []string `json:"destroyed"`
}

// StateChange represents a single change event for pub/sub
type StateChange struct {
	TenantID  string            `json:"tenantId"`
	DataTypes map[string]string `json:"changed"` // dataType -> newState
}

// ErrStateNotFound indicates the requested state is invalid or expired
var ErrStateNotFound = fmt.Errorf("state not found or expired")

// Domain models

// Tenant represents an organization operating an AS4 access point
type Tenant struct {
	ID        string       `bson:"_id" json:"id"`
	Name      string       `bson:"name" json:"name"`
	Domain    string       `bson:"domain" json:"domain"`
	Status    TenantStatus `bson:"status" json:"status"`
	CreatedAt time.Time    `bson:"created_at" json:"createdAt"`
	UpdatedAt time.Time    `bson:"updated_at" json:"updatedAt"`

	// Contact information
	AdminEmail string `bson:"admin_email" json:"adminEmail"`

	// SMP configuration
	SMPEndpoint string `bson:"smp_endpoint,omitempty" json:"smpEndpoint,omitempty"`

	// Default P-Mode settings
	DefaultSigningKeyID string `bson:"default_signing_key_id,omitempty" json:"defaultSigningKeyId,omitempty"`
}

type TenantStatus string

const (
	TenantStatusActive    TenantStatus = "active"
	TenantStatusSuspended TenantStatus = "suspended"
	TenantStatusPending   TenantStatus = "pending"
)

type TenantFilter struct {
	Status TenantStatus
	Limit  int
	Offset int
}

// Participant represents an entity that can send/receive AS4 messages
type Participant struct {
	ID        string    `bson:"_id" json:"id"`
	TenantID  string    `bson:"tenant_id" json:"tenantId"`
	Name      string    `bson:"name" json:"name"`
	Status    string    `bson:"status" json:"status"`
	CreatedAt time.Time `bson:"created_at" json:"createdAt"`
	UpdatedAt time.Time `bson:"updated_at" json:"updatedAt"`

	// AS4 Party identification
	PartyID PartyID `bson:"party_id" json:"partyId"`

	// Associated mailbox ID
	MailboxID string `bson:"mailbox_id" json:"mailboxId"`

	// Signing key ID for this participant (if different from tenant default)
	SigningKeyID string `bson:"signing_key_id,omitempty" json:"signingKeyId,omitempty"`

	// Endpoint is the AS4 endpoint URL for this participant (optional)
	// If set, this overrides SMP discovery when sending to this participant
	Endpoint string `bson:"endpoint,omitempty" json:"endpoint,omitempty"`
}

type PartyID struct {
	Type  string `bson:"type" json:"type"`   // e.g., "urn:oasis:names:tc:ebcore:partyid-type:unregistered"
	Value string `bson:"value" json:"value"` // e.g., "acme-corp"
}

type ParticipantFilter struct {
	Status string
	Limit  int
	Offset int
}

// Mailbox is a message inbox/outbox for a participant
type Mailbox struct {
	ID            string    `bson:"_id" json:"id"`
	TenantID      string    `bson:"tenant_id" json:"tenantId"`
	ParticipantID string    `bson:"participant_id" json:"participantId"`
	Name          string    `bson:"name" json:"name"`
	CreatedAt     time.Time `bson:"created_at" json:"createdAt"`

	// Counters for JMAP state tracking
	TotalMessages int64  `bson:"total_messages" json:"totalMessages"`
	UnreadCount   int64  `bson:"unread_count" json:"unreadCount"`
	StateID       string `bson:"state_id" json:"stateId"` // Changes on any mailbox modification
}

// Message represents an AS4 message
type Message struct {
	ID        string           `bson:"_id" json:"id"`
	TenantID  string           `bson:"tenant_id" json:"tenantId"`
	MailboxID string           `bson:"mailbox_id" json:"mailboxId"`
	Direction MessageDirection `bson:"direction" json:"direction"`
	Status    MessageStatus    `bson:"status" json:"status"`

	// AS4 identifiers
	AS4MessageID   string `bson:"as4_message_id" json:"as4MessageId"`
	ConversationID string `bson:"conversation_id" json:"conversationId"`
	RefToMessageID string `bson:"ref_to_message_id,omitempty" json:"refToMessageId,omitempty"`

	// Routing
	FromParty PartyID `bson:"from_party" json:"fromParty"`
	ToParty   PartyID `bson:"to_party" json:"toParty"`

	// Business context
	Service string `bson:"service" json:"service"`
	Action  string `bson:"action" json:"action"`

	// Payloads
	Payloads []PayloadRef `bson:"payloads" json:"payloads"`

	// Timestamps
	ReceivedAt  time.Time  `bson:"received_at" json:"receivedAt"`
	ProcessedAt *time.Time `bson:"processed_at,omitempty" json:"processedAt,omitempty"`
	DeliveredAt *time.Time `bson:"delivered_at,omitempty" json:"deliveredAt,omitempty"`
	ReadAt      *time.Time `bson:"read_at,omitempty" json:"readAt,omitempty"`

	// Security
	SignatureValid bool   `bson:"signature_valid" json:"signatureValid"`
	ReceiptID      string `bson:"receipt_id,omitempty" json:"receiptId,omitempty"`

	// Retry tracking (outbound)
	RetryCount  int        `bson:"retry_count" json:"retryCount"`
	NextRetryAt *time.Time `bson:"next_retry_at,omitempty" json:"nextRetryAt,omitempty"`
	LastError   string     `bson:"last_error,omitempty" json:"lastError,omitempty"`
}

type MessageDirection string

const (
	DirectionInbound  MessageDirection = "inbound"
	DirectionOutbound MessageDirection = "outbound"
)

type MessageStatus string

const (
	StatusPending   MessageStatus = "pending"   // Queued for sending
	StatusSending   MessageStatus = "sending"   // Currently being sent
	StatusSent      MessageStatus = "sent"      // Successfully sent
	StatusReceived  MessageStatus = "received"  // Received from partner
	StatusDelivered MessageStatus = "delivered" // Delivered to application
	StatusRead      MessageStatus = "read"      // Marked as read
	StatusFailed    MessageStatus = "failed"    // Delivery failed
	StatusRejected  MessageStatus = "rejected"  // Rejected by receiver
)

type MessageFilter struct {
	MailboxID string
	Direction MessageDirection
	Status    MessageStatus
	Service   string
	Action    string
	Since     *time.Time
	Limit     int
	Offset    int
}

// PayloadRef references a payload stored in GridFS
type PayloadRef struct {
	ID         string `bson:"id" json:"id"`
	ContentID  string `bson:"content_id" json:"contentId"`
	MimeType   string `bson:"mime_type" json:"mimeType"`
	Size       int64  `bson:"size" json:"size"`
	Compressed bool   `bson:"compressed" json:"compressed"`
	GridFSID   string `bson:"gridfs_id" json:"-"`
	Checksum   string `bson:"checksum" json:"checksum"`
}

// PayloadData holds payload content and metadata
type PayloadData struct {
	ID        string `json:"id"`
	ContentID string `json:"contentId"`
	MimeType  string `json:"mimeType"`
	Data      []byte `json:"-"`
	Checksum  string `json:"checksum"`
}
