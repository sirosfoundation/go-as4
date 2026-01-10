// Copyright (c) 2024 SIROS Foundation
// SPDX-License-Identifier: BSD-2-Clause

/*
Package message provides AS4 message structures and builders.

This package implements the message structures defined in the OASIS ebXML
Messaging Services Version 3.0 specification, with extensions for the
AS4 profile.

# Message Types

The package defines two main message types:

UserMessage - Business messages containing:
  - MessageInfo: Message ID, timestamp, RefToMessageId
  - PartyInfo: Sender and receiver party identification
  - CollaborationInfo: Service, action, conversation ID
  - MessageProperties: Custom properties
  - PayloadInfo: References to attached payloads

SignalMessage - Protocol signals:
  - Receipt: Acknowledgment of received messages
  - Error: Error notifications

# Building Messages

Use the fluent builder API to construct messages:

	builder := message.NewUserMessage(
	    message.WithFrom("sender", "urn:oasis:names:tc:ebcore:partyid-type:unregistered"),
	    message.WithTo("receiver", "urn:oasis:names:tc:ebcore:partyid-type:unregistered"),
	    message.WithService("http://example.com/service"),
	    message.WithAction("processDocument"),
	    message.WithConversationId("conv-123"),
	)
	msg := builder.Build()

# Adding Payloads

Attach payloads to messages:

	builder.AddPayload(data, "application/xml")
	builder.AddPayloadWithId("cid:payload-1", data, "application/xml")

# Namespaces

The package defines standard ebMS3 and AS4 namespaces:

	NS_SOAP12   = "http://www.w3.org/2003/05/soap-envelope"
	NS_EBMS     = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
	NS_WSSE     = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	NS_WSU      = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"

# References

  - OASIS ebMS 3.0 Core: https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/core/os/
  - ebCore Party ID Types: https://docs.oasis-open.org/ebcore/PartyIdType/v1.0/
*/
package message
