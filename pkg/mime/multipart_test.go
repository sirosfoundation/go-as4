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

func TestMessage_CorrelatePayloadsWithPartInfo(t *testing.T) {
	tests := []struct {
		name        string
		envelope    *message.Envelope
		payloads    []Payload
		expectKeys  []string
		expectEmpty bool
	}{
		{
			name:        "nil envelope",
			envelope:    nil,
			payloads:    []Payload{CreatePayload([]byte("data"), "text/plain")},
			expectEmpty: true,
		},
		{
			name: "nil header",
			envelope: &message.Envelope{
				Header: nil,
				Body:   &message.Body{},
			},
			payloads:    []Payload{CreatePayload([]byte("data"), "text/plain")},
			expectEmpty: true,
		},
		{
			name: "nil messaging",
			envelope: &message.Envelope{
				Header: &message.Header{Messaging: nil},
				Body:   &message.Body{},
			},
			payloads:    []Payload{CreatePayload([]byte("data"), "text/plain")},
			expectEmpty: true,
		},
		{
			name: "nil user message",
			envelope: &message.Envelope{
				Header: &message.Header{
					Messaging: &message.Messaging{UserMessage: nil},
				},
				Body: &message.Body{},
			},
			payloads:    []Payload{CreatePayload([]byte("data"), "text/plain")},
			expectEmpty: true,
		},
		{
			name: "nil payload info",
			envelope: &message.Envelope{
				Header: &message.Header{
					Messaging: &message.Messaging{
						UserMessage: &message.UserMessage{PayloadInfo: nil},
					},
				},
				Body: &message.Body{},
			},
			payloads:    []Payload{CreatePayload([]byte("data"), "text/plain")},
			expectEmpty: true,
		},
		{
			name: "with matching part info",
			envelope: &message.Envelope{
				Header: &message.Header{
					Messaging: &message.Messaging{
						UserMessage: &message.UserMessage{
							PayloadInfo: &message.PayloadInfo{
								PartInfo: []message.PartInfo{
									{
										Href: "cid:attachment@example.com",
										PartProperties: &message.PartProperties{
											Property: []message.Property{
												{Name: "MimeType", Value: "application/xml"},
												{Name: "CompressionType", Value: "gzip"},
												{Name: "CharacterSet", Value: "UTF-8"},
											},
										},
									},
								},
							},
						},
					},
				},
				Body: &message.Body{},
			},
			payloads: []Payload{
				CreatePayloadWithID([]byte("data"), "application/xml", "attachment@example.com"),
			},
			expectKeys:  []string{"attachment@example.com"},
			expectEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &Message{
				Envelope: tt.envelope,
				Payloads: tt.payloads,
			}

			result, err := msg.CorrelatePayloadsWithPartInfo()
			require.NoError(t, err)

			if tt.expectEmpty {
				assert.Empty(t, result)
			} else {
				for _, key := range tt.expectKeys {
					_, exists := result[key]
					assert.True(t, exists, "expected key %s to exist", key)
				}
			}
		})
	}
}

func TestMessage_CorrelatePayloadsWithPartInfo_EnrichPayload(t *testing.T) {
	envelope := &message.Envelope{
		Header: &message.Header{
			Messaging: &message.Messaging{
				UserMessage: &message.UserMessage{
					PayloadInfo: &message.PayloadInfo{
						PartInfo: []message.PartInfo{
							{
								Href: "cid:test@example.com",
								PartProperties: &message.PartProperties{
									Property: []message.Property{
										{Name: "MimeType", Value: "text/xml"},
										{Name: "CompressionType", Value: "application/gzip"},
										{Name: "CharacterSet", Value: "ISO-8859-1"},
									},
								},
							},
						},
					},
				},
			},
		},
		Body: &message.Body{},
	}

	msg := &Message{
		Envelope: envelope,
		Payloads: []Payload{
			CreatePayloadWithID([]byte("xml data"), "application/octet-stream", "test@example.com"),
		},
	}

	result, err := msg.CorrelatePayloadsWithPartInfo()
	require.NoError(t, err)

	payload := result["test@example.com"]
	require.NotNil(t, payload)
	assert.Equal(t, "text/xml", payload.MimeType)
	assert.Equal(t, "application/gzip", payload.CompressionType)
	assert.Equal(t, "ISO-8859-1", payload.CharacterSet)
}

func TestMessage_GetPayloadByContentID(t *testing.T) {
	msg := &Message{
		Payloads: []Payload{
			CreatePayloadWithID([]byte("data1"), "text/plain", "id1@example.com"),
			CreatePayloadWithID([]byte("data2"), "text/plain", "id2@example.com"),
			CreatePayloadWithID([]byte("data3"), "text/plain", "id3@example.com"),
		},
	}

	tests := []struct {
		name      string
		contentID string
		wantData  []byte
		wantNil   bool
	}{
		{"find by exact id", "id2@example.com", []byte("data2"), false},
		{"find with cid prefix", "cid:id1@example.com", []byte("data1"), false},
		{"find with brackets", "<id3@example.com>", []byte("data3"), false},
		{"not found", "nonexistent@example.com", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := msg.GetPayloadByContentID(tt.contentID)
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.Equal(t, tt.wantData, result.Data)
			}
		})
	}
}

func TestMessage_GetPayloadsForDecryption(t *testing.T) {
	msg := &Message{
		Payloads: []Payload{
			CreatePayloadWithID([]byte("encrypted1"), "application/octet-stream", "payload1@example.com"),
			CreatePayloadWithID([]byte("encrypted2"), "application/octet-stream", "payload2@example.com"),
		},
	}

	result := msg.GetPayloadsForDecryption()
	require.Len(t, result, 2)

	assert.Equal(t, "payload1@example.com", result[0].ContentID)
	assert.Equal(t, []byte("encrypted1"), result[0].Data)
	assert.Equal(t, "payload2@example.com", result[1].ContentID)
	assert.Equal(t, []byte("encrypted2"), result[1].Data)
}

func TestMessage_UpdatePayloadData(t *testing.T) {
	msg := &Message{
		Payloads: []Payload{
			CreatePayloadWithID([]byte("original1"), "text/plain", "id1@example.com"),
			CreatePayloadWithID([]byte("original2"), "text/plain", "id2@example.com"),
		},
	}

	// Update existing payload
	success := msg.UpdatePayloadData("id1@example.com", []byte("updated1"))
	assert.True(t, success)
	assert.Equal(t, []byte("updated1"), msg.Payloads[0].Data)

	// Update with cid prefix
	success = msg.UpdatePayloadData("cid:id2@example.com", []byte("updated2"))
	assert.True(t, success)
	assert.Equal(t, []byte("updated2"), msg.Payloads[1].Data)

	// Update non-existent payload
	success = msg.UpdatePayloadData("nonexistent@example.com", []byte("data"))
	assert.False(t, success)
}

func TestMessage_EmptyPayloads(t *testing.T) {
	msg := &Message{
		Payloads: []Payload{},
	}

	// GetPayloadByContentID on empty
	result := msg.GetPayloadByContentID("any@example.com")
	assert.Nil(t, result)

	// GetPayloadsForDecryption on empty
	decryptPayloads := msg.GetPayloadsForDecryption()
	assert.Empty(t, decryptPayloads)

	// UpdatePayloadData on empty
	success := msg.UpdatePayloadData("any@example.com", []byte("data"))
	assert.False(t, success)
}
