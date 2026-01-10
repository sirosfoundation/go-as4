package message

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// UserMessageBuilder helps construct AS4 UserMessages
type UserMessageBuilder struct {
	msg      *UserMessage
	payloads []PayloadPart
	errors   []error
}

// Option represents a functional option for UserMessageBuilder
type Option func(*UserMessageBuilder)

// NewUserMessage creates a new UserMessage with the given options
func NewUserMessage(opts ...Option) *UserMessageBuilder {
	builder := &UserMessageBuilder{
		msg: &UserMessage{
			MessageInfo: &MessageInfo{
				Timestamp: time.Now().UTC(),
				MessageId: generateMessageId(),
			},
			PartyInfo: &PartyInfo{
				From: &Party{},
				To:   &Party{},
			},
			CollaborationInfo: &CollaborationInfo{
				ConversationId: uuid.New().String(),
			},
		},
		payloads: make([]PayloadPart, 0),
	}

	for _, opt := range opts {
		opt(builder)
	}

	return builder
}

// WithFrom sets the sender party information
func WithFrom(partyId, partyType string) Option {
	return func(b *UserMessageBuilder) {
		b.msg.PartyInfo.From.PartyId = []PartyId{{Type: partyType, Value: partyId}}
		b.msg.PartyInfo.From.Role = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/defaultRole"
	}
}

// WithTo sets the receiver party information
func WithTo(partyId, partyType string) Option {
	return func(b *UserMessageBuilder) {
		b.msg.PartyInfo.To.PartyId = []PartyId{{Type: partyType, Value: partyId}}
		b.msg.PartyInfo.To.Role = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/defaultRole"
	}
}

// WithFromRole sets the sender role
func WithFromRole(role string) Option {
	return func(b *UserMessageBuilder) {
		b.msg.PartyInfo.From.Role = role
	}
}

// WithToRole sets the receiver role
func WithToRole(role string) Option {
	return func(b *UserMessageBuilder) {
		b.msg.PartyInfo.To.Role = role
	}
}

// WithService sets the service information
func WithService(service string) Option {
	return func(b *UserMessageBuilder) {
		b.msg.CollaborationInfo.Service = Service{Value: service}
	}
}

// WithAction sets the action
func WithAction(action string) Option {
	return func(b *UserMessageBuilder) {
		b.msg.CollaborationInfo.Action = action
	}
}

// WithConversationId sets a custom conversation ID
func WithConversationId(convId string) Option {
	return func(b *UserMessageBuilder) {
		b.msg.CollaborationInfo.ConversationId = convId
	}
}

// WithRefToMessageId sets the RefToMessageId for responses
func WithRefToMessageId(refId string) Option {
	return func(b *UserMessageBuilder) {
		b.msg.MessageInfo.RefToMessageId = refId
	}
}

// WithAgreementRef sets the agreement reference
func WithAgreementRef(agreementRef string) Option {
	return func(b *UserMessageBuilder) {
		b.msg.CollaborationInfo.AgreementRef = &AgreementRef{Value: agreementRef}
	}
}

// WithMessageProperty adds a message property
func WithMessageProperty(name, value string) Option {
	return func(b *UserMessageBuilder) {
		if b.msg.MessageProperties == nil {
			b.msg.MessageProperties = &MessageProperties{
				Property: make([]Property, 0),
			}
		}
		b.msg.MessageProperties.Property = append(b.msg.MessageProperties.Property, Property{
			Name:  name,
			Value: value,
		})
	}
}

// AddPayload adds a payload to the message
func (b *UserMessageBuilder) AddPayload(data []byte, contentType string) *UserMessageBuilder {
	contentId := fmt.Sprintf("%s@as4.example.com", uuid.New().String())

	payload := PayloadPart{
		ContentID:   contentId,
		ContentType: contentType,
		Data:        data,
	}

	b.payloads = append(b.payloads, payload)

	// Add PartInfo to UserMessage
	if b.msg.PayloadInfo == nil {
		b.msg.PayloadInfo = &PayloadInfo{
			PartInfo: make([]PartInfo, 0),
		}
	}

	partInfo := PartInfo{
		Href: "cid:" + contentId,
	}

	b.msg.PayloadInfo.PartInfo = append(b.msg.PayloadInfo.PartInfo, partInfo)

	return b
}

// AddPartProperty adds a property to the last added payload part
func (b *UserMessageBuilder) AddPartProperty(name, value string) *UserMessageBuilder {
	if len(b.msg.PayloadInfo.PartInfo) == 0 {
		b.errors = append(b.errors, fmt.Errorf("no payload parts to add property to"))
		return b
	}

	lastPart := &b.msg.PayloadInfo.PartInfo[len(b.msg.PayloadInfo.PartInfo)-1]
	if lastPart.PartProperties == nil {
		lastPart.PartProperties = &PartProperties{
			Property: make([]Property, 0),
		}
	}

	lastPart.PartProperties.Property = append(lastPart.PartProperties.Property, Property{
		Name:  name,
		Value: value,
	})

	return b
}

// Build returns the constructed UserMessage and payloads
func (b *UserMessageBuilder) Build() (*UserMessage, []PayloadPart, error) {
	if len(b.errors) > 0 {
		return nil, nil, b.errors[0]
	}

	// Validate required fields
	if len(b.msg.PartyInfo.From.PartyId) == 0 {
		return nil, nil, fmt.Errorf("sender party ID is required")
	}
	if len(b.msg.PartyInfo.To.PartyId) == 0 {
		return nil, nil, fmt.Errorf("receiver party ID is required")
	}
	if b.msg.CollaborationInfo.Service.Value == "" {
		return nil, nil, fmt.Errorf("service is required")
	}
	if b.msg.CollaborationInfo.Action == "" {
		return nil, nil, fmt.Errorf("action is required")
	}

	return b.msg, b.payloads, nil
}

// BuildEnvelope creates a complete SOAP envelope with the UserMessage
func (b *UserMessageBuilder) BuildEnvelope() (*Envelope, []PayloadPart, error) {
	msg, payloads, err := b.Build()
	if err != nil {
		return nil, nil, err
	}

	envelope := &Envelope{
		Header: &Header{
			Messaging: &Messaging{
				UserMessage: msg,
			},
		},
		Body: &Body{},
	}

	return envelope, payloads, nil
}

// generateMessageId generates a unique message ID following RFC2822 format
func generateMessageId() string {
	return fmt.Sprintf("%s@as4.example.com", uuid.New().String())
}

// NewReceipt creates a receipt signal message for a given UserMessage
func NewReceipt(refMessageId string, nonRepudiation bool) *SignalMessage {
	receipt := &SignalMessage{
		MessageInfo: &MessageInfo{
			Timestamp:      time.Now().UTC(),
			MessageId:      generateMessageId(),
			RefToMessageId: refMessageId,
		},
		Receipt: &Receipt{},
	}

	return receipt
}

// NewError creates an error signal message
func NewError(refMessageId, errorCode, severity, shortDesc, description string) *SignalMessage {
	return &SignalMessage{
		MessageInfo: &MessageInfo{
			Timestamp:      time.Now().UTC(),
			MessageId:      generateMessageId(),
			RefToMessageId: refMessageId,
		},
		Error: &Error{
			ErrorCode:           errorCode,
			Severity:            severity,
			ShortDescription:    shortDesc,
			Description:         description,
			RefToMessageInError: refMessageId,
		},
	}
}
