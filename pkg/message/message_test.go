package message

import (
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserMessageBuilder_BasicCreation(t *testing.T) {
	builder := NewUserMessage(
		WithFrom("sender-123", "urn:oasis:names:tc:ebcore:partyid-type:unregistered"),
		WithTo("receiver-456", "urn:oasis:names:tc:ebcore:partyid-type:unregistered"),
		WithService("http://example.com/service"),
		WithAction("processOrder"),
	)

	msg, payloads, err := builder.Build()
	require.NoError(t, err)
	assert.NotNil(t, msg)
	assert.NotEmpty(t, msg.MessageInfo.MessageId)
	assert.Empty(t, payloads)

	// Verify PartyInfo
	require.NotNil(t, msg.PartyInfo)
	require.Len(t, msg.PartyInfo.From.PartyId, 1)
	assert.Equal(t, "sender-123", msg.PartyInfo.From.PartyId[0].Value)

	// Verify CollaborationInfo
	require.NotNil(t, msg.CollaborationInfo)
	assert.Equal(t, "http://example.com/service", msg.CollaborationInfo.Service.Value)
	assert.Equal(t, "processOrder", msg.CollaborationInfo.Action)
}

func TestUserMessageBuilder_WithPayload(t *testing.T) {
	builder := NewUserMessage(
		WithFrom("s", "t"),
		WithTo("r", "t"),
		WithService("svc"),
		WithAction("act"),
	)
	payloadData := []byte("<order><item>Widget</item></order>")
	builder.AddPayload(payloadData, "application/xml")

	msg, payloads, err := builder.Build()
	require.NoError(t, err)
	require.Len(t, msg.PayloadInfo.PartInfo, 1)
	assert.True(t, strings.HasPrefix(msg.PayloadInfo.PartInfo[0].Href, "cid:"))
	require.Len(t, payloads, 1)
	assert.Equal(t, payloadData, payloads[0].Data)
	assert.Equal(t, "application/xml", payloads[0].ContentType)
}

func TestUserMessageBuilder_WithProperties(t *testing.T) {
	builder := NewUserMessage(
		WithFrom("s", "t"),
		WithTo("r", "t"),
		WithService("svc"),
		WithAction("act"),
		WithMessageProperty("priority", "high"),
		WithMessageProperty("department", "sales"),
	)

	msg, _, err := builder.Build()
	require.NoError(t, err)
	require.NotNil(t, msg.MessageProperties)
	require.Len(t, msg.MessageProperties.Property, 2)
	assert.Equal(t, "priority", msg.MessageProperties.Property[0].Name)
	assert.Equal(t, "high", msg.MessageProperties.Property[0].Value)
}

func TestUserMessageBuilder_BuildEnvelope(t *testing.T) {
	builder := NewUserMessage(
		WithFrom("sender", "type1"),
		WithTo("receiver", "type2"),
		WithService("test-service"),
		WithAction("test-action"),
	)

	envelope, payloads, err := builder.BuildEnvelope()
	require.NoError(t, err)
	require.NotNil(t, envelope)
	assert.Empty(t, payloads)

	// Verify Header
	require.NotNil(t, envelope.Header)
	require.NotNil(t, envelope.Header.Messaging)
	require.NotNil(t, envelope.Header.Messaging.UserMessage)

	// Verify message content
	userMsg := envelope.Header.Messaging.UserMessage
	assert.NotEmpty(t, userMsg.MessageInfo.MessageId)
	assert.Equal(t, "test-service", userMsg.CollaborationInfo.Service.Value)
	assert.Equal(t, "test-action", userMsg.CollaborationInfo.Action)
}

func TestEnvelope_XMLMarshaling(t *testing.T) {
	builder := NewUserMessage(
		WithFrom("sender", "type1"),
		WithTo("receiver", "type2"),
		WithService("service1"),
		WithAction("action1"),
	)

	envelope, _, err := builder.BuildEnvelope()
	require.NoError(t, err)

	// Marshal to XML
	xmlData, err := xml.MarshalIndent(envelope, "", "  ")
	require.NoError(t, err)
	assert.NotEmpty(t, xmlData)

	// Verify XML contains expected elements
	xmlStr := string(xmlData)
	assert.Contains(t, xmlStr, "Envelope")
	assert.Contains(t, xmlStr, "Header")
	assert.Contains(t, xmlStr, "Body")
	assert.Contains(t, xmlStr, "Messaging")
	assert.Contains(t, xmlStr, "UserMessage")
}

func TestEnvelope_RoundTrip(t *testing.T) {
	builder := NewUserMessage(
		WithFrom("test-sender", "urn:test"),
		WithTo("test-receiver", "urn:test"),
		WithService("http://test.com/service"),
		WithAction("testAction"),
	)

	envelope, _, err := builder.BuildEnvelope()
	require.NoError(t, err)

	// Marshal to XML
	xmlData, err := xml.Marshal(envelope)
	require.NoError(t, err)

	// Unmarshal back
	var unmarshaled Envelope
	err = xml.Unmarshal(xmlData, &unmarshaled)
	require.NoError(t, err)

	// Verify content
	assert.NotNil(t, unmarshaled.Header)
	assert.NotNil(t, unmarshaled.Header.Messaging)
	userMsg := unmarshaled.Header.Messaging.UserMessage
	require.NotNil(t, userMsg)
	assert.Equal(t, "http://test.com/service", userMsg.CollaborationInfo.Service.Value)
	assert.Equal(t, "testAction", userMsg.CollaborationInfo.Action)
}

func TestMessageInfo_Timestamp(t *testing.T) {
	builder := NewUserMessage(
		WithFrom("s", "t"),
		WithTo("r", "t"),
		WithService("svc"),
		WithAction("act"),
	)

	msg, _, err := builder.Build()
	require.NoError(t, err)

	// Verify timestamp is not zero
	assert.False(t, msg.MessageInfo.Timestamp.IsZero())

	// Verify timestamp is recent (within last minute)
	assert.True(t, time.Since(msg.MessageInfo.Timestamp) < time.Minute)
}

func TestSignalMessage_Receipt(t *testing.T) {
	refToMessageID := "msg-123"
	receipt := NewReceipt(refToMessageID, false)

	assert.NotNil(t, receipt)
	assert.NotEmpty(t, receipt.MessageInfo.MessageId)
	assert.Equal(t, refToMessageID, receipt.MessageInfo.RefToMessageId)
	assert.NotNil(t, receipt.Receipt)
}

func TestSignalMessage_Error(t *testing.T) {
	refToMessageID := "msg-456"
	errorCode := "EBMS:0004"
	shortDesc := "Error in processing"
	errorDescription := "Error processing message"
	severity := "failure"

	errMsg := NewError(refToMessageID, errorCode, severity, shortDesc, errorDescription)

	assert.NotNil(t, errMsg)
	assert.Equal(t, refToMessageID, errMsg.MessageInfo.RefToMessageId)
	assert.NotNil(t, errMsg.Error)
	assert.Equal(t, errorCode, errMsg.Error.ErrorCode)
	assert.Equal(t, errorDescription, errMsg.Error.Description)
	assert.Equal(t, severity, errMsg.Error.Severity)
}

func TestUserMessageBuilder_Validation(t *testing.T) {
	t.Run("missing sender", func(t *testing.T) {
		builder := NewUserMessage(
			WithTo("r", "t"),
			WithService("svc"),
			WithAction("act"),
		)

		_, _, err := builder.Build()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "sender")
	})

	t.Run("missing receiver", func(t *testing.T) {
		builder := NewUserMessage(
			WithFrom("s", "t"),
			WithService("svc"),
			WithAction("act"),
		)

		_, _, err := builder.Build()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "receiver")
	})

	t.Run("missing service", func(t *testing.T) {
		builder := NewUserMessage(
			WithFrom("s", "t"),
			WithTo("r", "t"),
			WithAction("act"),
		)

		_, _, err := builder.Build()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "service")
	})

	t.Run("missing action", func(t *testing.T) {
		builder := NewUserMessage(
			WithFrom("s", "t"),
			WithTo("r", "t"),
			WithService("svc"),
		)

		_, _, err := builder.Build()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "action")
	})
}

func TestUserMessageBuilder_MultiplePayloads(t *testing.T) {
	builder := NewUserMessage(
		WithFrom("s", "t"),
		WithTo("r", "t"),
		WithService("svc"),
		WithAction("act"),
	)

	builder.AddPayload([]byte("payload1"), "text/plain")
	builder.AddPayload([]byte("payload2"), "application/json")
	builder.AddPayload([]byte("payload3"), "application/pdf")

	msg, payloads, err := builder.Build()
	require.NoError(t, err)
	assert.Len(t, msg.PayloadInfo.PartInfo, 3)
	assert.Len(t, payloads, 3)

	// Verify each payload
	assert.Equal(t, "text/plain", payloads[0].ContentType)
	assert.Equal(t, "application/json", payloads[1].ContentType)
	assert.Equal(t, "application/pdf", payloads[2].ContentType)
}

func TestUserMessageBuilder_PartProperties(t *testing.T) {
	builder := NewUserMessage(
		WithFrom("s", "t"),
		WithTo("r", "t"),
		WithService("svc"),
		WithAction("act"),
	)

	builder.AddPayload([]byte("data"), "text/plain")
	builder.AddPartProperty("CompressionType", "application/gzip")
	builder.AddPartProperty("MimeType", "text/plain")

	msg, _, err := builder.Build()
	require.NoError(t, err)
	require.Len(t, msg.PayloadInfo.PartInfo, 1)

	partInfo := msg.PayloadInfo.PartInfo[0]
	require.NotNil(t, partInfo.PartProperties)
	assert.Len(t, partInfo.PartProperties.Property, 2)
}

func TestUserMessageBuilder_ConversationID(t *testing.T) {
	customConvID := "custom-conversation-123"
	builder := NewUserMessage(
		WithFrom("s", "t"),
		WithTo("r", "t"),
		WithService("svc"),
		WithAction("act"),
		WithConversationId(customConvID),
	)

	msg, _, err := builder.Build()
	require.NoError(t, err)
	assert.Equal(t, customConvID, msg.CollaborationInfo.ConversationId)
}

func TestUserMessageBuilder_RefToMessageId(t *testing.T) {
	refID := "original-message-123"
	builder := NewUserMessage(
		WithFrom("s", "t"),
		WithTo("r", "t"),
		WithService("svc"),
		WithAction("act"),
		WithRefToMessageId(refID),
	)

	msg, _, err := builder.Build()
	require.NoError(t, err)
	assert.Equal(t, refID, msg.MessageInfo.RefToMessageId)
}

func TestUserMessageBuilder_AgreementRef(t *testing.T) {
	agreementRef := "agreement-v1.0"
	builder := NewUserMessage(
		WithFrom("s", "t"),
		WithTo("r", "t"),
		WithService("svc"),
		WithAction("act"),
		WithAgreementRef(agreementRef),
	)

	msg, _, err := builder.Build()
	require.NoError(t, err)
	require.NotNil(t, msg.CollaborationInfo.AgreementRef)
	assert.Equal(t, agreementRef, msg.CollaborationInfo.AgreementRef.Value)
}
