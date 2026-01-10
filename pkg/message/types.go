// Package message provides AS4 message structure and ebMS3 headers implementation.
package message

import (
	"encoding/xml"
	"time"
)

// Namespace constants for AS4/ebMS3
const (
	NsSOAPEnv = "http://www.w3.org/2003/05/soap-envelope"
	NsEbMS    = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
	NsWSSE    = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	NsWSU     = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	NsDS      = "http://www.w3.org/2000/09/xmldsig#"
	NsXENC    = "http://www.w3.org/2001/04/xmlenc#"
	NsXENC11  = "http://www.w3.org/2009/xmlenc11#"
	NsDSMore  = "http://www.w3.org/2021/04/xmldsig-more#"
	NsDS11    = "http://www.w3.org/2009/xmldsig11#"
)

// MEP constants for Message Exchange Patterns
const (
	MEPOneWay          = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/oneWay"
	MEPTwoWay          = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/twoWay"
	MEPBindingPush     = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/push"
	MEPBindingPushPush = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/pushAndPush"
	MEPBindingPull     = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/pull"
)

// Test Service constants
const (
	TestService = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/service"
	TestAction  = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/test"
)

// Envelope represents a SOAP 1.2 envelope
type Envelope struct {
	XMLName xml.Name `xml:"http://www.w3.org/2003/05/soap-envelope Envelope"`
	Header  *Header  `xml:"Header"`
	Body    *Body    `xml:"Body"`
}

// Header represents the SOAP header containing ebMS3 Messaging header
type Header struct {
	Messaging *Messaging `xml:"http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/ Messaging"`
	Security  *Security  `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd Security,omitempty"`
}

// Body represents the SOAP body (empty for AS4 as payloads are in MIME attachments)
type Body struct {
	XMLName xml.Name `xml:"http://www.w3.org/2003/05/soap-envelope Body"`
}

// Messaging represents the ebMS3 Messaging header
type Messaging struct {
	XMLName       xml.Name       `xml:"http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/ Messaging"`
	UserMessage   *UserMessage   `xml:"UserMessage,omitempty"`
	SignalMessage *SignalMessage `xml:"SignalMessage,omitempty"`
	// Note: mustUnderstand attribute is added dynamically during signing to ensure correct namespace prefix
}

// UserMessage represents an ebMS3 UserMessage
type UserMessage struct {
	XMLName           xml.Name           `xml:"http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/ UserMessage"`
	MessageInfo       *MessageInfo       `xml:"MessageInfo"`
	PartyInfo         *PartyInfo         `xml:"PartyInfo"`
	CollaborationInfo *CollaborationInfo `xml:"CollaborationInfo"`
	MessageProperties *MessageProperties `xml:"MessageProperties,omitempty"`
	PayloadInfo       *PayloadInfo       `xml:"PayloadInfo,omitempty"`
}

// MessageInfo contains message identification and timestamps
type MessageInfo struct {
	Timestamp      time.Time `xml:"Timestamp"`
	MessageId      string    `xml:"MessageId"`
	RefToMessageId string    `xml:"RefToMessageId,omitempty"`
}

// PartyInfo contains sender and receiver party information
type PartyInfo struct {
	From *Party `xml:"From"`
	To   *Party `xml:"To"`
}

// Party represents a messaging party
type Party struct {
	PartyId []PartyId `xml:"PartyId"`
	Role    string    `xml:"Role"`
}

// PartyId represents a party identifier with type
type PartyId struct {
	Type  string `xml:"type,attr,omitempty"`
	Value string `xml:",chardata"`
}

// CollaborationInfo contains service and action information
type CollaborationInfo struct {
	AgreementRef   *AgreementRef `xml:"AgreementRef,omitempty"`
	Service        Service       `xml:"Service"`
	Action         string        `xml:"Action"`
	ConversationId string        `xml:"ConversationId"`
}

// AgreementRef references a business agreement
type AgreementRef struct {
	Type  string `xml:"type,attr,omitempty"`
	Pmode string `xml:"pmode,attr,omitempty"`
	Value string `xml:",chardata"`
}

// Service identifies the service
type Service struct {
	Type  string `xml:"type,attr,omitempty"`
	Value string `xml:",chardata"`
}

// MessageProperties contains custom message properties
type MessageProperties struct {
	Property []Property `xml:"Property"`
}

// Property represents a message property
type Property struct {
	Name  string `xml:"name,attr"`
	Type  string `xml:"type,attr,omitempty"`
	Value string `xml:",chardata"`
}

// PayloadInfo contains references to payload parts
type PayloadInfo struct {
	PartInfo []PartInfo `xml:"PartInfo"`
}

// PartInfo describes a payload part
type PartInfo struct {
	Href           string          `xml:"href,attr,omitempty"`
	PartProperties *PartProperties `xml:"PartProperties,omitempty"`
}

// PartProperties contains properties for a payload part
type PartProperties struct {
	Property []Property `xml:"Property"`
}

// SignalMessage represents an ebMS3 SignalMessage (Receipt or Error)
type SignalMessage struct {
	XMLName     xml.Name     `xml:"http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/ SignalMessage"`
	MessageInfo *MessageInfo `xml:"MessageInfo"`
	Receipt     *Receipt     `xml:"Receipt,omitempty"`
	Error       *Error       `xml:"Error,omitempty"`
}

// Receipt represents a receipt acknowledgment
type Receipt struct {
	XMLName xml.Name `xml:"http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/ Receipt"`
	// Can contain NonRepudiationInformation or simple ack
	Any []byte `xml:",innerxml"`
}

// Error represents an ebMS3 error
type Error struct {
	XMLName             xml.Name `xml:"http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/ Error"`
	ErrorCode           string   `xml:"errorCode,attr"`
	Severity            string   `xml:"severity,attr"`
	ShortDescription    string   `xml:"shortDescription,attr"`
	Description         string   `xml:"Description,omitempty"`
	ErrorDetail         string   `xml:"ErrorDetail,omitempty"`
	RefToMessageInError string   `xml:"refToMessageInError,attr,omitempty"`
}

// Security represents WS-Security header
type Security struct {
	XMLName        xml.Name `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd Security"`
	MustUnderstand string   `xml:"http://www.w3.org/2003/05/soap-envelope mustUnderstand,attr"`
	// Will contain BinarySecurityToken, Signature, EncryptedKey, etc.
	// Implemented in security package
}

// PayloadPart represents a MIME payload part
type PayloadPart struct {
	ContentID   string
	ContentType string
	Data        []byte
	Compressed  bool
}
