package jmap

import (
	"time"
)

// Capability URN for JMAP-AS4
const CapabilityAS4 = "urn:ietf:params:jmap:as4"

// Request represents a JMAP request
type Request struct {
	Using       []string          `json:"using"`
	MethodCalls []MethodCall      `json:"methodCalls"`
	CreatedIDs  map[string]string `json:"createdIds,omitempty"`
}

// MethodCall represents a single method invocation [name, args, callId]
type MethodCall struct {
	Name   string
	Args   map[string]any
	CallID string
}

// Response represents a JMAP response
type Response struct {
	MethodResponses []MethodResponse  `json:"methodResponses"`
	CreatedIDs      map[string]string `json:"createdIds,omitempty"`
	SessionState    string            `json:"sessionState"`
}

// MethodResponse represents a single method response [name, args, callId]
type MethodResponse struct {
	Name   string
	Args   map[string]any
	CallID string
}

// Session represents JMAP session information
type Session struct {
	Capabilities    map[string]any     `json:"capabilities"`
	Accounts        map[string]Account `json:"accounts"`
	PrimaryAccounts map[string]string  `json:"primaryAccounts"`
	Username        string             `json:"username"`
	APIUrl          string             `json:"apiUrl"`
	DownloadUrl     string             `json:"downloadUrl"`
	UploadUrl       string             `json:"uploadUrl"`
	EventSourceUrl  string             `json:"eventSourceUrl"`
	State           string             `json:"state"`
}

// Account represents a JMAP account (tenant)
type Account struct {
	Name                string         `json:"name"`
	IsPersonal          bool           `json:"isPersonal"`
	IsReadOnly          bool           `json:"isReadOnly"`
	AccountCapabilities map[string]any `json:"accountCapabilities"`
}

// AS4Capability represents account-level AS4 capability
type AS4Capability struct {
	MaxPayloadSize    int64    `json:"maxPayloadSize"`
	SupportedServices []string `json:"supportedServices"`
	SupportedActions  []string `json:"supportedActions"`
}

// Party represents an AS4 party identifier
type Party struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// AS4Payload represents a message payload reference
type AS4Payload struct {
	ID         string `json:"id"`
	ContentID  string `json:"contentId"`
	MimeType   string `json:"mimeType"`
	Size       int64  `json:"size"`
	Compressed bool   `json:"compressed"`
	Checksum   string `json:"checksum"`
}

// AS4Message represents an AS4 message
type AS4Message struct {
	ID             string       `json:"id"`
	MailboxID      string       `json:"mailboxId"`
	Direction      string       `json:"direction"`
	Status         string       `json:"status"`
	AS4MessageID   string       `json:"as4MessageId"`
	ConversationID string       `json:"conversationId"`
	RefToMessageID *string      `json:"refToMessageId"`
	FromParty      Party        `json:"fromParty"`
	ToParty        Party        `json:"toParty"`
	Service        string       `json:"service"`
	Action         string       `json:"action"`
	Payloads       []AS4Payload `json:"payloads"`
	ReceivedAt     time.Time    `json:"receivedAt"`
	ProcessedAt    *time.Time   `json:"processedAt"`
	DeliveredAt    *time.Time   `json:"deliveredAt"`
	ReadAt         *time.Time   `json:"readAt"`
	SignatureValid bool         `json:"signatureValid"`
	ReceiptID      *string      `json:"receiptId"`
	RetryCount     int          `json:"retryCount"`
	LastError      *string      `json:"lastError"`
}

// AS4Mailbox represents a message container
type AS4Mailbox struct {
	ID            string `json:"id"`
	ParticipantID string `json:"participantId"`
	Name          string `json:"name"`
	TotalMessages int64  `json:"totalMessages"`
	UnreadCount   int64  `json:"unreadCount"`
	Role          string `json:"role"`
}

// AS4Participant represents a trading partner
type AS4Participant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	PartyID   Party     `json:"partyId"`
	MailboxID string    `json:"mailboxId"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
}

// GetRequest is the standard JMAP /get request arguments
type GetRequest struct {
	AccountID  string   `json:"accountId"`
	IDs        []string `json:"ids"`
	Properties []string `json:"properties,omitempty"`
}

// GetResponse is the standard JMAP /get response
type GetResponse struct {
	AccountID string   `json:"accountId"`
	State     string   `json:"state"`
	List      []any    `json:"list"`
	NotFound  []string `json:"notFound"`
}

// ChangesRequest is the standard JMAP /changes request
type ChangesRequest struct {
	AccountID  string `json:"accountId"`
	SinceState string `json:"sinceState"`
	MaxChanges int    `json:"maxChanges,omitempty"`
}

// ChangesResponse is the standard JMAP /changes response
type ChangesResponse struct {
	AccountID      string   `json:"accountId"`
	OldState       string   `json:"oldState"`
	NewState       string   `json:"newState"`
	HasMoreChanges bool     `json:"hasMoreChanges"`
	Created        []string `json:"created"`
	Updated        []string `json:"updated"`
	Destroyed      []string `json:"destroyed"`
}

// QueryRequest is the standard JMAP /query request
type QueryRequest struct {
	AccountID      string            `json:"accountId"`
	Filter         *AS4MessageFilter `json:"filter,omitempty"`
	Sort           []SortComparator  `json:"sort,omitempty"`
	Position       int               `json:"position,omitempty"`
	Anchor         string            `json:"anchor,omitempty"`
	AnchorOffset   int               `json:"anchorOffset,omitempty"`
	Limit          int               `json:"limit,omitempty"`
	CalculateTotal bool              `json:"calculateTotal,omitempty"`
}

// AS4MessageFilter defines filter conditions for message queries
type AS4MessageFilter struct {
	MailboxID      string     `json:"mailboxId,omitempty"`
	Direction      string     `json:"direction,omitempty"`
	Status         string     `json:"status,omitempty"`
	Service        string     `json:"service,omitempty"`
	Action         string     `json:"action,omitempty"`
	FromPartyValue string     `json:"fromPartyValue,omitempty"`
	ToPartyValue   string     `json:"toPartyValue,omitempty"`
	ConversationID string     `json:"conversationId,omitempty"`
	ReceivedAfter  *time.Time `json:"receivedAfter,omitempty"`
	ReceivedBefore *time.Time `json:"receivedBefore,omitempty"`
	HasUnread      *bool      `json:"hasUnread,omitempty"`
}

// SortComparator defines sort order
type SortComparator struct {
	Property    string `json:"property"`
	IsAscending bool   `json:"isAscending"`
}

// QueryResponse is the standard JMAP /query response
type QueryResponse struct {
	AccountID           string   `json:"accountId"`
	QueryState          string   `json:"queryState"`
	CanCalculateChanges bool     `json:"canCalculateChanges"`
	Position            int      `json:"position"`
	IDs                 []string `json:"ids"`
	Total               *int64   `json:"total,omitempty"`
}

// QueryChangesRequest is the JMAP /queryChanges request
type QueryChangesRequest struct {
	AccountID       string            `json:"accountId"`
	Filter          *AS4MessageFilter `json:"filter,omitempty"`
	Sort            []SortComparator  `json:"sort,omitempty"`
	SinceQueryState string            `json:"sinceQueryState"`
	MaxChanges      int               `json:"maxChanges,omitempty"`
	UpToID          string            `json:"upToId,omitempty"`
	CalculateTotal  bool              `json:"calculateTotal,omitempty"`
}

// QueryChangesResponse is the JMAP /queryChanges response
type QueryChangesResponse struct {
	AccountID     string      `json:"accountId"`
	OldQueryState string      `json:"oldQueryState"`
	NewQueryState string      `json:"newQueryState"`
	Total         *int64      `json:"total,omitempty"`
	Removed       []string    `json:"removed"`
	Added         []AddedItem `json:"added"`
}

// AddedItem represents a newly added item in queryChanges
type AddedItem struct {
	ID    string `json:"id"`
	Index int    `json:"index"`
}

// SetRequest is the standard JMAP /set request
type SetRequest struct {
	AccountID string                      `json:"accountId"`
	IfInState string                      `json:"ifInState,omitempty"`
	Create    map[string]AS4MessageCreate `json:"create,omitempty"`
	Update    map[string]AS4MessageUpdate `json:"update,omitempty"`
	Destroy   []string                    `json:"destroy,omitempty"`
}

// AS4MessageCreate defines properties for creating a message
type AS4MessageCreate struct {
	MailboxID      string             `json:"mailboxId"`
	ToParty        Party              `json:"toParty"`
	Service        string             `json:"service"`
	Action         string             `json:"action"`
	ConversationID string             `json:"conversationId,omitempty"`
	RefToMessageID string             `json:"refToMessageId,omitempty"`
	Payloads       []PayloadUploadRef `json:"payloads"`
}

// PayloadUploadRef references an uploaded blob
type PayloadUploadRef struct {
	BlobID    string `json:"blobId"`
	ContentID string `json:"contentId"`
	MimeType  string `json:"mimeType"`
}

// AS4MessageUpdate defines updatable properties
type AS4MessageUpdate struct {
	Status string `json:"status,omitempty"`
}

// ParticipantSetRequest is the AS4Participant/set request
type ParticipantSetRequest struct {
	AccountID string                          `json:"accountId"`
	IfInState string                          `json:"ifInState,omitempty"`
	Create    map[string]AS4ParticipantCreate `json:"create,omitempty"`
	Update    map[string]AS4ParticipantUpdate `json:"update,omitempty"`
	Destroy   []string                        `json:"destroy,omitempty"`
}

// AS4ParticipantCreate defines properties for creating a participant
type AS4ParticipantCreate struct {
	Name    string `json:"name"`
	PartyID Party  `json:"partyId"`
	Status  string `json:"status,omitempty"` // defaults to "active"
}

// AS4ParticipantUpdate defines updatable participant properties
type AS4ParticipantUpdate struct {
	Name   *string `json:"name,omitempty"`
	Status *string `json:"status,omitempty"`
}

// SetResponse is the standard JMAP /set response
type SetResponse struct {
	AccountID    string                `json:"accountId"`
	OldState     string                `json:"oldState"`
	NewState     string                `json:"newState"`
	Created      map[string]AS4Message `json:"created,omitempty"`
	Updated      map[string]any        `json:"updated,omitempty"`
	Destroyed    []string              `json:"destroyed,omitempty"`
	NotCreated   map[string]SetError   `json:"notCreated,omitempty"`
	NotUpdated   map[string]SetError   `json:"notUpdated,omitempty"`
	NotDestroyed map[string]SetError   `json:"notDestroyed,omitempty"`
}

// SetError describes why a create/update/destroy failed
type SetError struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

// Error types
const (
	ErrorNotFound               = "notFound"
	ErrorInvalidArguments       = "invalidArguments"
	ErrorStateMismatch          = "stateMismatch"
	ErrorForbidden              = "forbidden"
	ErrorCannotCalculateChanges = "cannotCalculateChanges"
	ErrorServerFail             = "serverFail"
)
