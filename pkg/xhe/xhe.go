// Package xhe implements XML Header Envelope (XHE) support for Swedish SDK federation.
// XHE is the standard envelope format for business documents in SDK.
//
// XHE provides:
//   - Standardized routing metadata (FromParty, ToParty)
//   - Support for multiple payloads in a single envelope
//   - Cross-profile interoperability with other eDelivery federations
//
// Reference: https://docs.oasis-open.org/bdxr/ns/XHE/unqualified/1.0
package xhe

import (
	"encoding/xml"
	"fmt"
	"time"
)

// Namespace constants for XHE
const (
	// NsXHE is the XHE namespace
	NsXHE = "oasis:names:specification:ubl:schema:xsd:eDeliveryXHE-1"
	// NsCAC is the Common Aggregate Components namespace
	NsCAC = "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
	// NsCBC is the Common Basic Components namespace
	NsCBC = "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"

	// SDK Customization ID
	SDKCustomizationID = "urn:fdc:digg.se:edelivery:xhe:1.0"
)

// XHE represents an XML Header Envelope document
type XHE struct {
	XMLName         xml.Name `xml:"XHE"`
	XHEVersionID    string   `xml:"XHEVersionID"`
	CustomizationID string   `xml:"CustomizationID,omitempty"`
	ProfileID       string   `xml:"ProfileID,omitempty"`
	Header          Header   `xml:"Header"`
	Payloads        Payloads `xml:"Payloads"`
}

// Header contains routing and metadata information
type Header struct {
	ID                     string    `xml:"ID"`
	UUID                   string    `xml:"UUID,omitempty"`
	CreationDateTimeString string    `xml:"CreationDateTime"`
	FromParty              Party     `xml:"FromParty"`
	ToParty                []Party   `xml:"ToParty"`
	BusinessScope          []Scope   `xml:"BusinessScope>Scope,omitempty"`
	DocumentReference      []DocRef  `xml:"DocumentReference,omitempty"`
	creationDateTime       time.Time // Internal parsed time
}

// CreationDateTime returns the parsed creation date/time
func (h *Header) CreationDateTime() time.Time {
	if h.creationDateTime.IsZero() && h.CreationDateTimeString != "" {
		t, _ := time.Parse(time.RFC3339, h.CreationDateTimeString)
		h.creationDateTime = t
	}
	return h.creationDateTime
}

// SetCreationDateTime sets the creation date/time
func (h *Header) SetCreationDateTime(t time.Time) {
	h.creationDateTime = t
	h.CreationDateTimeString = t.Format(time.RFC3339)
}

// Party represents a sender or receiver party
type Party struct {
	PartyID PartyID `xml:"PartyIdentification>ID"`
}

// PartyID represents a party identifier with scheme
type PartyID struct {
	SchemeID string `xml:"schemeID,attr,omitempty"`
	Value    string `xml:",chardata"`
}

// Scope represents a business scope element
type Scope struct {
	Type       string `xml:"Type"`
	InstanceID string `xml:"InstanceIdentifier"`
	Identifier string `xml:"Identifier,omitempty"`
}

// DocRef represents a document reference
type DocRef struct {
	ID           string `xml:"ID"`
	DocumentType string `xml:"DocumentType,omitempty"`
}

// Payloads contains the payload collection
type Payloads struct {
	Payload []Payload `xml:"Payload"`
}

// Payload represents a single payload within the XHE
type Payload struct {
	ID                          string         `xml:"ID,omitempty"`
	Description                 string         `xml:"Description,omitempty"`
	ContentTypeCode             string         `xml:"ContentTypeCode,omitempty"`
	CustomizationID             string         `xml:"CustomizationID,omitempty"`
	ProfileID                   string         `xml:"ProfileID,omitempty"`
	InstanceEncryptionIndicator bool           `xml:"InstanceEncryptionIndicator,omitempty"`
	PayloadContent              PayloadContent `xml:"PayloadContent"`
}

// PayloadContent contains the actual payload data
type PayloadContent struct {
	Content []byte `xml:",innerxml"`
}

// Builder provides a fluent interface for creating XHE envelopes
type Builder struct {
	xhe *XHE
	err error
}

// NewBuilder creates a new XHE builder
func NewBuilder() *Builder {
	return &Builder{
		xhe: &XHE{
			XHEVersionID:    "1.0",
			CustomizationID: SDKCustomizationID,
			Header: Header{
				ToParty: make([]Party, 0),
			},
			Payloads: Payloads{
				Payload: make([]Payload, 0),
			},
		},
	}
}

// WithID sets the header ID
func (b *Builder) WithID(id string) *Builder {
	if b.err != nil {
		return b
	}
	b.xhe.Header.ID = id
	return b
}

// WithUUID sets the header UUID
func (b *Builder) WithUUID(uuid string) *Builder {
	if b.err != nil {
		return b
	}
	b.xhe.Header.UUID = uuid
	return b
}

// WithCreationTime sets the creation timestamp
func (b *Builder) WithCreationTime(t time.Time) *Builder {
	if b.err != nil {
		return b
	}
	b.xhe.Header.SetCreationDateTime(t)
	return b
}

// WithFromParty sets the sender party
func (b *Builder) WithFromParty(schemeID, partyID string) *Builder {
	if b.err != nil {
		return b
	}
	b.xhe.Header.FromParty = Party{
		PartyID: PartyID{
			SchemeID: schemeID,
			Value:    partyID,
		},
	}
	return b
}

// WithToParty adds a recipient party
func (b *Builder) WithToParty(schemeID, partyID string) *Builder {
	if b.err != nil {
		return b
	}
	b.xhe.Header.ToParty = append(b.xhe.Header.ToParty, Party{
		PartyID: PartyID{
			SchemeID: schemeID,
			Value:    partyID,
		},
	})
	return b
}

// WithCustomizationID sets a custom customization ID
func (b *Builder) WithCustomizationID(id string) *Builder {
	if b.err != nil {
		return b
	}
	b.xhe.CustomizationID = id
	return b
}

// WithProfileID sets the profile ID
func (b *Builder) WithProfileID(id string) *Builder {
	if b.err != nil {
		return b
	}
	b.xhe.ProfileID = id
	return b
}

// WithBusinessScope adds a business scope
func (b *Builder) WithBusinessScope(scopeType, instanceID, identifier string) *Builder {
	if b.err != nil {
		return b
	}
	b.xhe.Header.BusinessScope = append(b.xhe.Header.BusinessScope, Scope{
		Type:       scopeType,
		InstanceID: instanceID,
		Identifier: identifier,
	})
	return b
}

// AddPayload adds a payload to the envelope
func (b *Builder) AddPayload(payload Payload) *Builder {
	if b.err != nil {
		return b
	}
	b.xhe.Payloads.Payload = append(b.xhe.Payloads.Payload, payload)
	return b
}

// AddXMLPayload adds an XML document payload
func (b *Builder) AddXMLPayload(id string, content []byte) *Builder {
	return b.AddPayload(Payload{
		ID:              id,
		ContentTypeCode: "application/xml",
		PayloadContent: PayloadContent{
			Content: content,
		},
	})
}

// AddBinaryPayload adds a binary payload with specified content type
func (b *Builder) AddBinaryPayload(id, contentType string, content []byte) *Builder {
	return b.AddPayload(Payload{
		ID:              id,
		ContentTypeCode: contentType,
		PayloadContent: PayloadContent{
			Content: content,
		},
	})
}

// Build creates the XHE envelope
func (b *Builder) Build() (*XHE, error) {
	if b.err != nil {
		return nil, b.err
	}

	// Validate required fields
	if b.xhe.Header.ID == "" {
		return nil, fmt.Errorf("header ID is required")
	}
	if b.xhe.Header.FromParty.PartyID.Value == "" {
		return nil, fmt.Errorf("FromParty is required")
	}
	if len(b.xhe.Header.ToParty) == 0 {
		return nil, fmt.Errorf("at least one ToParty is required")
	}
	if len(b.xhe.Payloads.Payload) == 0 {
		return nil, fmt.Errorf("at least one payload is required")
	}

	// Set creation time if not set
	if b.xhe.Header.CreationDateTimeString == "" {
		b.xhe.Header.SetCreationDateTime(time.Now().UTC())
	}

	return b.xhe, nil
}

// Marshal serializes the XHE to XML bytes
func (x *XHE) Marshal() ([]byte, error) {
	return xml.MarshalIndent(x, "", "  ")
}

// Parse parses XML bytes into an XHE structure
func Parse(data []byte) (*XHE, error) {
	var xhe XHE
	if err := xml.Unmarshal(data, &xhe); err != nil {
		return nil, fmt.Errorf("failed to parse XHE: %w", err)
	}
	return &xhe, nil
}

// GetFirstToParty returns the first ToParty or empty Party
func (x *XHE) GetFirstToParty() Party {
	if len(x.Header.ToParty) > 0 {
		return x.Header.ToParty[0]
	}
	return Party{}
}

// GetPayloadByID returns a payload by ID
func (x *XHE) GetPayloadByID(id string) *Payload {
	for i := range x.Payloads.Payload {
		if x.Payloads.Payload[i].ID == id {
			return &x.Payloads.Payload[i]
		}
	}
	return nil
}

// GetFirstPayload returns the first payload or nil
func (x *XHE) GetFirstPayload() *Payload {
	if len(x.Payloads.Payload) > 0 {
		return &x.Payloads.Payload[0]
	}
	return nil
}
