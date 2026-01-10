// Copyright (c) 2024 SIROS Foundation
// SPDX-License-Identifier: BSD-2-Clause

/*
Package as4 provides the main client interface for AS4 messaging.

This package implements the core AS4 client functionality for sending
AS4 UserMessages according to the eDelivery AS4 2.0 specification and
the OASIS AS4 Profile of ebMS 3.0.

# Client Creation

Create a new AS4 client with configuration:

	client, err := as4.NewClient(&as4.ClientConfig{
	    HTTPSConfig:    transport.DefaultHTTPSConfig(),
	    SecurityConfig: securityConfig,
	    PMode:          processingMode,
	})

# Sending Messages

Use the client to send AS4 messages:

	receipt, err := client.SendMessage(ctx, userMessage, payloads, endpoint)

The client automatically handles:
  - P-Mode resolution
  - Payload compression (if configured)
  - Message signing
  - Message encryption
  - HTTPS transport
  - Receipt processing

# Message Exchange Patterns

The client supports the One-Way/Push MEP as defined in the OASIS AS4 Profile:

  - Sender initiates HTTP request with UserMessage
  - Receiver responds with Receipt signal message

# Reliability

The client supports reception awareness features:
  - Retry with configurable attempts and delays
  - Duplicate detection using message IDs

# References

  - OASIS AS4 Profile: https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/
  - eDelivery AS4 2.0: https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/845480153/
*/
package as4
