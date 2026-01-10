// Package mime implements MIME multipart/related message handling for AS4
package mime

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"

	"github.com/google/uuid"
	"github.com/sirosfoundation/go-as4/pkg/message"
)

const (
	// ContentTypeMultipartRelated is the MIME type for multipart/related
	ContentTypeMultipartRelated = "multipart/related"
	// ContentTypeApplicationXML is the MIME type for XML
	ContentTypeApplicationXML = "application/xml"
	// ContentTypeTextXML is the MIME type for text XML
	ContentTypeTextXML = "text/xml"
	// ContentTypeSOAPXML is the MIME type for SOAP
	ContentTypeSOAPXML = "application/soap+xml"
)

// Message represents a complete AS4 MIME message
type Message struct {
	Boundary    string
	ContentType string
	StartID     string
	Type        string
	Envelope    *message.Envelope
	Payloads    []Payload
}

// Payload represents a MIME payload part
type Payload struct {
	ContentID       string
	ContentType     string
	ContentTransfer string
	CompressionType string
	MimeType        string
	CharacterSet    string
	Data            []byte
	Headers         textproto.MIMEHeader
}

// NewMessage creates a new MIME message with the given envelope and payloads
func NewMessage(envelope *message.Envelope, payloads []Payload) *Message {
	boundary := generateBoundary()
	startID := fmt.Sprintf("<%s@as4.siros.org>", uuid.New().String())

	return &Message{
		Boundary:    boundary,
		ContentType: ContentTypeMultipartRelated,
		StartID:     startID,
		Type:        ContentTypeSOAPXML,
		Envelope:    envelope,
		Payloads:    payloads,
	}
}

// Serialize creates the complete MIME multipart message
func (m *Message) Serialize() ([]byte, string, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Use custom boundary
	if err := writer.SetBoundary(m.Boundary); err != nil {
		return nil, "", fmt.Errorf("failed to set boundary: %w", err)
	}

	// Create SOAP envelope part (first part)
	envelopeData, err := xml.MarshalIndent(m.Envelope, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal envelope: %w", err)
	}

	soapHeader := textproto.MIMEHeader{}
	soapHeader.Set("Content-Type", fmt.Sprintf("%s; charset=UTF-8", ContentTypeSOAPXML))
	soapHeader.Set("Content-Transfer-Encoding", "8bit")
	soapHeader.Set("Content-ID", m.StartID)

	soapPart, err := writer.CreatePart(soapHeader)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create SOAP part: %w", err)
	}

	if _, err := soapPart.Write(envelopeData); err != nil {
		return nil, "", fmt.Errorf("failed to write SOAP part: %w", err)
	}

	// Create payload parts
	for _, payload := range m.Payloads {
		payloadHeader := textproto.MIMEHeader{}

		// Set Content-Type
		contentType := payload.ContentType
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		if payload.CharacterSet != "" {
			contentType = fmt.Sprintf("%s; charset=%s", contentType, payload.CharacterSet)
		}
		payloadHeader.Set("Content-Type", contentType)

		// Set Content-Transfer-Encoding
		transferEncoding := payload.ContentTransfer
		if transferEncoding == "" {
			transferEncoding = "binary"
		}
		payloadHeader.Set("Content-Transfer-Encoding", transferEncoding)

		// Set Content-ID
		contentID := payload.ContentID
		if contentID == "" {
			contentID = fmt.Sprintf("<%s@as4.siros.org>", uuid.New().String())
		}
		if !strings.HasPrefix(contentID, "<") {
			contentID = "<" + contentID + ">"
		}
		payloadHeader.Set("Content-ID", contentID)

		// Add custom headers
		for key, values := range payload.Headers {
			for _, value := range values {
				payloadHeader.Add(key, value)
			}
		}

		payloadPart, err := writer.CreatePart(payloadHeader)
		if err != nil {
			return nil, "", fmt.Errorf("failed to create payload part: %w", err)
		}

		if _, err := payloadPart.Write(payload.Data); err != nil {
			return nil, "", fmt.Errorf("failed to write payload part: %w", err)
		}
	}

	if err := writer.Close(); err != nil {
		return nil, "", fmt.Errorf("failed to close multipart writer: %w", err)
	}

	// Build complete Content-Type header using mime.FormatMediaType for proper escaping
	// Note: The start parameter should reference the Content-ID without angle brackets
	// The Content-ID header itself has the angle brackets
	startRef := GetContentIDWithoutBrackets(m.StartID)
	params := map[string]string{
		"boundary": m.Boundary,
		"type":     m.Type,
		"start":    startRef,
	}
	contentType := mime.FormatMediaType(m.ContentType, params)

	return buf.Bytes(), contentType, nil
}

// Parse parses a MIME multipart message
func Parse(r io.Reader, contentType string) (*Message, error) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, fmt.Errorf("failed to parse content type: %w", err)
	}

	if !strings.HasPrefix(mediaType, "multipart/") {
		return nil, fmt.Errorf("not a multipart message: %s", mediaType)
	}

	boundary := params["boundary"]
	if boundary == "" {
		return nil, fmt.Errorf("boundary not found in content type")
	}

	startID := params["start"]
	msgType := params["type"]

	msg := &Message{
		Boundary:    boundary,
		ContentType: mediaType,
		StartID:     startID,
		Type:        msgType,
		Payloads:    []Payload{},
	}

	reader := multipart.NewReader(r, boundary)
	isFirstPart := true

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read part: %w", err)
		}

		data, err := io.ReadAll(part)
		if err != nil {
			return nil, fmt.Errorf("failed to read part data: %w", err)
		}

		contentID := part.Header.Get("Content-ID")
		partContentType := part.Header.Get("Content-Type")

		// Determine if this is the SOAP envelope
		// It's the first part OR matches the start ID (with flexible matching)
		isEnvelope := false
		if isFirstPart {
			isEnvelope = true
		} else if startID != "" && contentID != "" {
			// Normalize both for comparison
			normalizedStart := normalizeContentID(startID)
			normalizedCurrent := normalizeContentID(contentID)
			isEnvelope = normalizedStart == normalizedCurrent
		}

		if isEnvelope {
			var envelope message.Envelope
			if err := xml.Unmarshal(data, &envelope); err != nil {
				return nil, fmt.Errorf("failed to unmarshal SOAP envelope: %w", err)
			}
			msg.Envelope = &envelope
			isFirstPart = false
		} else {
			// Payload part
			payload := Payload{
				ContentID:       contentID,
				ContentType:     partContentType,
				ContentTransfer: part.Header.Get("Content-Transfer-Encoding"),
				Data:            data,
				Headers:         part.Header,
			}
			msg.Payloads = append(msg.Payloads, payload)
		}
	}

	if msg.Envelope == nil {
		return nil, fmt.Errorf("SOAP envelope not found in message")
	}

	return msg, nil
}

// normalizeContentID normalizes a Content-ID for comparison
func normalizeContentID(contentID string) string {
	// Remove cid: prefix
	contentID = strings.TrimPrefix(contentID, "cid:")
	// Remove angle brackets
	contentID = strings.TrimPrefix(contentID, "<")
	contentID = strings.TrimSuffix(contentID, ">")
	return contentID
}

// CreatePayload creates a new payload with the given data and content type
func CreatePayload(data []byte, contentType string) Payload {
	contentID := fmt.Sprintf("<%s@as4.siros.org>", uuid.New().String())

	return Payload{
		ContentID:       contentID,
		ContentType:     contentType,
		ContentTransfer: "binary",
		Data:            data,
		Headers:         make(textproto.MIMEHeader),
	}
}

// CreatePayloadWithID creates a new payload with a specific Content-ID
func CreatePayloadWithID(data []byte, contentType, contentID string) Payload {
	if !strings.HasPrefix(contentID, "<") {
		contentID = "<" + contentID + ">"
	}

	return Payload{
		ContentID:       contentID,
		ContentType:     contentType,
		ContentTransfer: "binary",
		Data:            data,
		Headers:         make(textproto.MIMEHeader),
	}
}

// CorrelatePayloadsWithPartInfo matches MIME payloads with PartInfo elements from UserMessage
// Returns a map of Content-ID to enriched Payload with metadata from PartInfo
func (m *Message) CorrelatePayloadsWithPartInfo() (map[string]*Payload, error) {
	result := make(map[string]*Payload)

	// Get PayloadInfo from the UserMessage
	if m.Envelope == nil || m.Envelope.Header == nil ||
		m.Envelope.Header.Messaging == nil {
		return result, nil
	}

	messaging := m.Envelope.Header.Messaging
	if messaging.UserMessage == nil {
		return result, nil
	}

	userMessage := messaging.UserMessage
	if userMessage.PayloadInfo == nil {
		return result, nil
	}

	// Build map of PartInfo by href (Content-ID reference)
	partInfoByHref := make(map[string]*message.PartInfo)
	for i := range userMessage.PayloadInfo.PartInfo {
		pi := &userMessage.PayloadInfo.PartInfo[i]
		if pi.Href != "" {
			normalizedHref := normalizeContentID(pi.Href)
			partInfoByHref[normalizedHref] = pi
		}
	}

	// Match payloads with PartInfo
	for i := range m.Payloads {
		payload := &m.Payloads[i]
		normalizedCID := normalizeContentID(payload.ContentID)

		// Find matching PartInfo
		if pi, ok := partInfoByHref[normalizedCID]; ok {
			// Enrich payload with PartInfo metadata
			enrichPayloadFromPartInfo(payload, pi)
		}

		result[normalizedCID] = payload
	}

	return result, nil
}

// enrichPayloadFromPartInfo enriches a Payload with metadata from PartInfo
func enrichPayloadFromPartInfo(payload *Payload, partInfo *message.PartInfo) {
	if partInfo.PartProperties == nil {
		return
	}

	for _, prop := range partInfo.PartProperties.Property {
		switch prop.Name {
		case "MimeType":
			payload.MimeType = prop.Value
		case "CompressionType":
			payload.CompressionType = prop.Value
		case "CharacterSet":
			payload.CharacterSet = prop.Value
		}
	}
}

// GetPayloadByContentID finds a payload by its Content-ID
// Handles various Content-ID formats (with/without cid:, angle brackets)
func (m *Message) GetPayloadByContentID(contentID string) *Payload {
	normalizedSearch := normalizeContentID(contentID)

	for i := range m.Payloads {
		if normalizeContentID(m.Payloads[i].ContentID) == normalizedSearch {
			return &m.Payloads[i]
		}
	}
	return nil
}

// GetPayloadsForDecryption returns payloads in a format suitable for WS-Security decryption
// Each payload includes its Content-ID and data
func (m *Message) GetPayloadsForDecryption() []PayloadForDecryption {
	var result []PayloadForDecryption
	for _, p := range m.Payloads {
		result = append(result, PayloadForDecryption{
			ContentID: normalizeContentID(p.ContentID),
			Data:      p.Data,
		})
	}
	return result
}

// PayloadForDecryption represents a payload ready for decryption
type PayloadForDecryption struct {
	ContentID string
	Data      []byte
}

// UpdatePayloadData updates the data for a specific payload (e.g., after decryption)
func (m *Message) UpdatePayloadData(contentID string, newData []byte) bool {
	normalizedSearch := normalizeContentID(contentID)

	for i := range m.Payloads {
		if normalizeContentID(m.Payloads[i].ContentID) == normalizedSearch {
			m.Payloads[i].Data = newData
			return true
		}
	}
	return false
}

// generateBoundary generates a MIME boundary string
func generateBoundary() string {
	return fmt.Sprintf("----=_Part_%s", strings.ReplaceAll(uuid.New().String(), "-", ""))
}

// GetContentIDWithoutBrackets removes < and > from Content-ID
func GetContentIDWithoutBrackets(contentID string) string {
	contentID = strings.TrimPrefix(contentID, "<")
	contentID = strings.TrimSuffix(contentID, ">")
	return contentID
}

// AddContentIDBrackets adds < and > to Content-ID if not present
func AddContentIDBrackets(contentID string) string {
	if !strings.HasPrefix(contentID, "<") {
		contentID = "<" + contentID
	}
	if !strings.HasSuffix(contentID, ">") {
		contentID = contentID + ">"
	}
	return contentID
}
