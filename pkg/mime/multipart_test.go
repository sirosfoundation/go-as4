package mime

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/sirosfoundation/go-as4/pkg/message"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreatePayload(t *testing.T) {
	data := []byte("test payload data")
	contentType := "text/plain"

	payload := CreatePayload(data, contentType)

	assert.NotEmpty(t, payload.ContentID)
	assert.True(t, strings.HasPrefix(payload.ContentID, "<"))
	assert.True(t, strings.HasSuffix(payload.ContentID, ">"))
	assert.Equal(t, contentType, payload.ContentType)
	assert.Equal(t, "binary", payload.ContentTransfer)
	assert.Equal(t, data, payload.Data)
	assert.NotNil(t, payload.Headers)
}

func TestCreatePayloadWithID(t *testing.T) {
	data := []byte("test data")
	contentType := "application/json"
	contentID := "custom-id-123"

	payload := CreatePayloadWithID(data, contentType, contentID)

	assert.Equal(t, "<custom-id-123>", payload.ContentID)
	assert.Equal(t, contentType, payload.ContentType)
	assert.Equal(t, data, payload.Data)
}

func TestCreatePayloadWithID_AddBrackets(t *testing.T) {
	data := []byte("test")
	contentID := "id-without-brackets"

	payload := CreatePayloadWithID(data, "text/plain", contentID)

	assert.Equal(t, "<id-without-brackets>", payload.ContentID)
}

func TestNewMessage(t *testing.T) {
	envelope := &message.Envelope{
		Header: &message.Header{
			Messaging: &message.Messaging{
				UserMessage: &message.UserMessage{},
			},
		},
		Body: &message.Body{},
	}

	payloads := []Payload{
		CreatePayload([]byte("payload1"), "text/plain"),
		CreatePayload([]byte("payload2"), "application/json"),
	}

	msg := NewMessage(envelope, payloads)

	assert.NotNil(t, msg)
	assert.NotEmpty(t, msg.Boundary)
	assert.NotEmpty(t, msg.StartID)
	assert.Equal(t, ContentTypeMultipartRelated, msg.ContentType)
	assert.Equal(t, ContentTypeSOAPXML, msg.Type)
	assert.Equal(t, envelope, msg.Envelope)
	assert.Len(t, msg.Payloads, 2)
}

func TestMessage_Serialize(t *testing.T) {
	// Create a simple SOAP envelope
	envelope := &message.Envelope{
		XMLName: xml.Name{Space: "http://www.w3.org/2003/05/soap-envelope", Local: "Envelope"},
		Header: &message.Header{
			Messaging: &message.Messaging{
				UserMessage: &message.UserMessage{
					MessageInfo: &message.MessageInfo{
						MessageId: "test-msg-123",
					},
				},
			},
		},
		Body: &message.Body{},
	}

	payloads := []Payload{
		CreatePayload([]byte("test payload"), "text/plain"),
	}

	msg := NewMessage(envelope, payloads)

	// Serialize
	mimeData, contentType, err := msg.Serialize()
	require.NoError(t, err)
	assert.NotEmpty(t, mimeData)
	assert.NotEmpty(t, contentType)

	// Verify content type
	assert.Contains(t, contentType, "multipart/related")
	assert.Contains(t, contentType, "boundary=")
	assert.Contains(t, contentType, "type=")
	assert.Contains(t, contentType, "start=")

	// Verify MIME data contains expected parts
	mimeStr := string(mimeData)
	assert.Contains(t, mimeStr, "Content-Type: application/soap+xml")
	assert.Contains(t, mimeStr, "Content-Type: text/plain")
	assert.Contains(t, mimeStr, "test-msg-123")
	assert.Contains(t, mimeStr, "test payload")
}

func TestMessage_SerializeAndParse(t *testing.T) {
	// Create envelope
	envelope := &message.Envelope{
		XMLName: xml.Name{Space: "http://www.w3.org/2003/05/soap-envelope", Local: "Envelope"},
		Header: &message.Header{
			Messaging: &message.Messaging{
				UserMessage: &message.UserMessage{
					MessageInfo: &message.MessageInfo{
						MessageId: "test-123",
					},
				},
			},
		},
		Body: &message.Body{},
	}

	// Create payloads
	payloads := []Payload{
		CreatePayloadWithID([]byte("payload data 1"), "text/plain", "payload-1"),
		CreatePayloadWithID([]byte("payload data 2"), "application/json", "payload-2"),
	}

	// Create and serialize message
	msg := NewMessage(envelope, payloads)
	mimeData, contentType, err := msg.Serialize()
	require.NoError(t, err)

	// Parse back
	parsed, err := Parse(bytes.NewReader(mimeData), contentType)
	require.NoError(t, err)
	require.NotNil(t, parsed)

	// Verify envelope was parsed
	assert.NotNil(t, parsed.Envelope)
	assert.NotNil(t, parsed.Envelope.Header)
	assert.NotNil(t, parsed.Envelope.Header.Messaging)

	// Verify payloads were parsed
	assert.Len(t, parsed.Payloads, 2)
}

func TestParse_InvalidContentType(t *testing.T) {
	data := []byte("some data")

	_, err := Parse(bytes.NewReader(data), "text/plain")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a multipart message")
}

func TestParse_MissingBoundary(t *testing.T) {
	data := []byte("some data")

	_, err := Parse(bytes.NewReader(data), "multipart/related")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "boundary not found")
}

func TestGetContentIDWithoutBrackets(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"<id-123>", "id-123"},
		{"id-456", "id-456"},
		{"<some@example.com>", "some@example.com"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := GetContentIDWithoutBrackets(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAddContentIDBrackets(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"id-123", "<id-123>"},
		{"<id-456>", "<id-456>"},
		{"<id-789", "<id-789>"},
		{"id-abc>", "<id-abc>"},
		{"", "<>"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := AddContentIDBrackets(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMessage_SerializeMultiplePayloads(t *testing.T) {
	envelope := &message.Envelope{
		XMLName: xml.Name{Space: "http://www.w3.org/2003/05/soap-envelope", Local: "Envelope"},
		Header:  &message.Header{Messaging: &message.Messaging{}},
		Body:    &message.Body{},
	}

	payloads := []Payload{
		CreatePayload([]byte("payload1"), "text/plain"),
		CreatePayload([]byte("payload2"), "application/xml"),
		CreatePayload([]byte("payload3"), "application/json"),
	}

	msg := NewMessage(envelope, payloads)
	mimeData, contentType, err := msg.Serialize()
	require.NoError(t, err)

	// Parse back
	parsed, err := Parse(bytes.NewReader(mimeData), contentType)
	require.NoError(t, err)
	assert.Len(t, parsed.Payloads, 3)
}

func TestPayload_Headers(t *testing.T) {
	payload := CreatePayload([]byte("data"), "text/plain")
	payload.Headers.Set("X-Custom-Header", "custom-value")
	payload.Headers.Set("X-Another-Header", "another-value")

	assert.Equal(t, "custom-value", payload.Headers.Get("X-Custom-Header"))
	assert.Equal(t, "another-value", payload.Headers.Get("X-Another-Header"))
}
