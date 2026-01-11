package message

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEBMS3NamespaceCompliance verifies that our implementation uses the correct
// ebMS 3.0 namespace (200704) for all message elements and constants, matching
// what Domibus 5.1.9 expects.
func TestEBMS3NamespaceCompliance(t *testing.T) {
	// Test namespace constants match ebMS 3.0 spec
	assert.Equal(t, "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/", NsEbMS,
		"ebMS namespace should use 200704 version")

	// Test MEP constants use correct namespace
	assert.Contains(t, MEPOneWay, "200704", "MEPOneWay should use 200704 namespace")
	assert.Contains(t, MEPTwoWay, "200704", "MEPTwoWay should use 200704 namespace")
	assert.Contains(t, MEPBindingPush, "200704", "MEPBindingPush should use 200704 namespace")
	assert.Contains(t, MEPBindingPushPush, "200704", "MEPBindingPushPush should use 200704 namespace")
	assert.Contains(t, MEPBindingPull, "200704", "MEPBindingPull should use 200704 namespace")

	// Test service constants
	assert.Contains(t, TestService, "200704", "TestService should use 200704 namespace")
	assert.Contains(t, TestAction, "200704", "TestAction should use 200704 namespace")

	// Test actual XML marshaling uses correct namespace
	builder := NewUserMessage(
		WithFrom("sender", "urn:oasis:names:tc:ebcore:partyid-type:unregistered"),
		WithTo("receiver", "urn:oasis:names:tc:ebcore:partyid-type:unregistered"),
		WithService(TestService),
		WithAction(TestAction),
	)

	msg, _, err := builder.Build()
	require.NoError(t, err)

	// Marshal to XML
	env := &Envelope{
		Header: &Header{
			Messaging: &Messaging{
				UserMessage: msg,
			},
		},
		Body: &Body{},
	}

	xmlData, err := xml.MarshalIndent(env, "", "  ")
	require.NoError(t, err)

	xmlStr := string(xmlData)

	// Verify 200704 namespace appears in XML
	assert.Contains(t, xmlStr, "200704", "Marshaled XML should contain 200704 namespace")

	// Verify no AS4 v2.0 namespace (202X) appears
	assert.NotContains(t, xmlStr, "202X", "Marshaled XML should NOT contain AS4 v2.0 namespace")
	assert.NotContains(t, xmlStr, "as4/v2.0", "Marshaled XML should NOT contain AS4 v2.0 namespace")

	// Verify ebXML messaging namespace is correct
	assert.Contains(t, xmlStr, "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/",
		"Marshaled XML should use ebMS 3.0 namespace")
}

// TestDomibusCompatibleConstants verifies our constants match Domibus exactly
func TestDomibusCompatibleConstants(t *testing.T) {
	// These values are from Domibus Ebms3Constants.java
	domibusMEPOneWay := "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/oneWay"
	domibusMEPTwoWay := "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/twoWay"
	domibusMEPPush := "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/push"
	domibusMEPPull := "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/pull"
	domibusTestService := "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/service"
	domibusTestAction := "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/test"

	// Verify our constants match Domibus
	assert.Equal(t, domibusMEPOneWay, MEPOneWay, "MEPOneWay should match Domibus")
	assert.Equal(t, domibusMEPTwoWay, MEPTwoWay, "MEPTwoWay should match Domibus")
	assert.Equal(t, domibusMEPPush, MEPBindingPush, "MEPBindingPush should match Domibus")
	assert.Equal(t, domibusMEPPull, MEPBindingPull, "MEPBindingPull should match Domibus")
	assert.Equal(t, domibusTestService, TestService, "TestService should match Domibus")
	assert.Equal(t, domibusTestAction, TestAction, "TestAction should match Domibus")
}

// TestMessageRoleDefaultValue tests that party roles use the correct default value
func TestMessageRoleDefaultValue(t *testing.T) {
	builder := NewUserMessage(
		WithFrom("sender", "urn:test"),
		WithTo("receiver", "urn:test"),
		WithService("test-service"),
		WithAction("test-action"),
	)

	msg, _, err := builder.Build()
	require.NoError(t, err)

	// Domibus default role from Ebms3Constants.java
	expectedDefaultRole := "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/defaultRole"

	assert.Equal(t, expectedDefaultRole, msg.PartyInfo.From.Role, "From role should use ebMS 3.0 default")
	assert.Equal(t, expectedDefaultRole, msg.PartyInfo.To.Role, "To role should use ebMS 3.0 default")
}

// TestXMLStructNamespaceDeclarations verifies XML struct tags use correct namespaces
func TestXMLStructNamespaceDeclarations(t *testing.T) {
	// Create a minimal message
	builder := NewUserMessage(
		WithFrom("test-sender", "urn:test"),
		WithTo("test-receiver", "urn:test"),
		WithService("test-service"),
		WithAction("test-action"),
	)

	msg, _, err := builder.Build()
	require.NoError(t, err)

	// Create envelope
	env := &Envelope{
		Header: &Header{
			Messaging: &Messaging{
				UserMessage: msg,
			},
		},
		Body: &Body{},
	}

	// Marshal to XML
	xmlData, err := xml.MarshalIndent(env, "", "  ")
	require.NoError(t, err)

	xmlStr := string(xmlData)

	// Verify proper namespace declarations
	tests := []struct {
		name     string
		contains string
		shouldBe bool
	}{
		{"SOAP 1.2 namespace", "http://www.w3.org/2003/05/soap-envelope", true},
		{"ebMS 3.0 namespace with 200704", "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/", true},
		{"No AS4 v2.0 namespace", "as4/v2.0", false},
		{"No 202X version", "202X", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldBe {
				assert.Contains(t, xmlStr, tt.contains, "XML should contain %s", tt.contains)
			} else {
				assert.NotContains(t, xmlStr, tt.contains, "XML should NOT contain %s", tt.contains)
			}
		})
	}
}

// TestNamespaceConsistency verifies all message elements use consistent namespace
func TestNamespaceConsistency(t *testing.T) {
	builder := NewUserMessage(
		WithFrom("sender", "urn:test"),
		WithTo("receiver", "urn:test"),
		WithService("http://example.com/service"),
		WithAction("ProcessOrder"),
		WithConversationId("conv-123"),
	)

	builder.AddPayload([]byte("<order>test</order>"), "application/xml")

	msg, _, err := builder.Build()
	require.NoError(t, err)

	env := &Envelope{
		Header: &Header{
			Messaging: &Messaging{
				UserMessage: msg,
			},
		},
		Body: &Body{},
	}

	xmlData, err := xml.Marshal(env)
	require.NoError(t, err)

	// Count occurrences of different namespace versions
	xmlStr := string(xmlData)
	count200704 := strings.Count(xmlStr, "200704")
	count202X := strings.Count(xmlStr, "202X")

	// Should have multiple references to 200704 (namespace declaration + element tags)
	assert.Greater(t, count200704, 0, "Should have at least one reference to 200704 namespace")

	// Should have NO references to 202X (AS4 v2.0)
	assert.Equal(t, 0, count202X, "Should have no references to AS4 v2.0 namespace")
}

// TestAddEbMSPrefix tests the AddEbMSPrefix function
func TestAddEbMSPrefix(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		contains    []string
		notContains []string
	}{
		{
			name: "basic messaging element",
			input: `<Messaging xmlns="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
  <UserMessage>
    <MessageInfo>
      <Timestamp>2024-01-01T00:00:00Z</Timestamp>
      <MessageId>msg-123</MessageId>
    </MessageInfo>
  </UserMessage>
</Messaging>`,
			contains: []string{
				`<eb:Messaging xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">`,
				"<eb:UserMessage>",
				"<eb:MessageInfo>",
				"<eb:Timestamp>",
				"<eb:MessageId>",
				"</eb:MessageInfo>",
				"</eb:UserMessage>",
				"</eb:Messaging>",
			},
			notContains: []string{
				"<UserMessage>",
				"<MessageInfo>",
			},
		},
		{
			name: "party info elements",
			input: `<Messaging xmlns="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
  <UserMessage>
    <PartyInfo>
      <From>
        <PartyId>sender</PartyId>
        <Role>initiator</Role>
      </From>
      <To>
        <PartyId>receiver</PartyId>
        <Role>responder</Role>
      </To>
    </PartyInfo>
  </UserMessage>
</Messaging>`,
			contains: []string{
				"<eb:PartyInfo>",
				"<eb:From>",
				"<eb:To>",
				"<eb:PartyId>",
				"<eb:Role>",
			},
		},
		{
			name: "collaboration info elements",
			input: `<Messaging xmlns="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
  <UserMessage>
    <CollaborationInfo>
      <AgreementRef>agreement</AgreementRef>
      <Service>service</Service>
      <Action>action</Action>
      <ConversationId>conv-123</ConversationId>
    </CollaborationInfo>
  </UserMessage>
</Messaging>`,
			contains: []string{
				"<eb:CollaborationInfo>",
				"<eb:AgreementRef>",
				"<eb:Service>",
				"<eb:Action>",
				"<eb:ConversationId>",
			},
		},
		{
			name: "payload info elements",
			input: `<Messaging xmlns="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
  <UserMessage>
    <PayloadInfo>
      <PartInfo href="cid:attachment">
        <PartProperties>
          <Property name="MimeType">application/xml</Property>
        </PartProperties>
      </PartInfo>
    </PayloadInfo>
  </UserMessage>
</Messaging>`,
			contains: []string{
				"<eb:PayloadInfo>",
				"<eb:PartInfo",
				"<eb:PartProperties>",
				"<eb:Property",
			},
		},
		{
			name: "signal message elements",
			input: `<Messaging xmlns="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
  <SignalMessage>
    <MessageInfo>
      <MessageId>signal-123</MessageId>
      <RefToMessageId>msg-123</RefToMessageId>
    </MessageInfo>
    <Receipt>receipt data</Receipt>
  </SignalMessage>
</Messaging>`,
			contains: []string{
				"<eb:SignalMessage>",
				"<eb:RefToMessageId>",
				"<eb:Receipt>",
			},
		},
		{
			name: "error elements",
			input: `<Messaging xmlns="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
  <SignalMessage>
    <Error>
      <Description>error description</Description>
      <ErrorDetail>detail</ErrorDetail>
    </Error>
  </SignalMessage>
</Messaging>`,
			contains: []string{
				"<eb:Error>",
				"<eb:Description>",
				"<eb:ErrorDetail>",
			},
		},
		{
			name: "message properties",
			input: `<Messaging xmlns="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
  <UserMessage>
    <MessageProperties>
      <Property name="key">value</Property>
    </MessageProperties>
  </UserMessage>
</Messaging>`,
			contains: []string{
				"<eb:MessageProperties>",
				"<eb:Property",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := AddEbMSPrefix([]byte(tt.input))
			require.NoError(t, err)
			resultStr := string(result)

			for _, expected := range tt.contains {
				assert.Contains(t, resultStr, expected, "result should contain %s", expected)
			}

			for _, notExpected := range tt.notContains {
				assert.NotContains(t, resultStr, notExpected, "result should NOT contain %s", notExpected)
			}
		})
	}
}

// TestRemoveDefaultNamespace tests the RemoveDefaultNamespace function
func TestRemoveDefaultNamespace(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		namespace string
		prefix    string
		expected  string
	}{
		{
			name:      "ebms namespace",
			input:     `<Messaging xmlns="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">`,
			namespace: "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/",
			prefix:    "eb",
			expected:  `<Messaging xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">`,
		},
		{
			name:      "soap namespace",
			input:     `<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">`,
			namespace: "http://www.w3.org/2003/05/soap-envelope",
			prefix:    "S",
			expected:  `<Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope">`,
		},
		{
			name:      "no matching namespace",
			input:     `<Element xmlns="http://other.namespace/">`,
			namespace: "http://different.namespace/",
			prefix:    "ns",
			expected:  `<Element xmlns="http://other.namespace/">`,
		},
		{
			name:      "multiple occurrences",
			input:     `<Root xmlns="http://test.ns/"><Child xmlns="http://test.ns/"/></Root>`,
			namespace: "http://test.ns/",
			prefix:    "t",
			expected:  `<Root xmlns:t="http://test.ns/"><Child xmlns:t="http://test.ns/"/></Root>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := RemoveDefaultNamespace([]byte(tt.input), tt.namespace, tt.prefix)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(result))
		})
	}
}
