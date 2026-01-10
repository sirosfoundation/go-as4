// Copyright (c) 2024 SIROS Foundation
// SPDX-License-Identifier: BSD-2-Clause

/*
Package msh implements the Message Service Handler for AS4.

The MSH is the core processing component that handles incoming and
outgoing AS4 messages according to P-Mode configuration.

# MSH Components

The MSH coordinates:
  - Message validation
  - Security processing (signing, encryption)
  - Payload handling
  - Receipt generation
  - Error handling

# Incoming Messages

Process received messages:

	handler := msh.NewMessageHandler(pmodeManager, securityConfig)
	receipt, err := handler.ProcessIncoming(ctx, envelope, attachments)

# Outgoing Messages

Prepare messages for sending:

	prepared, err := handler.PrepareOutgoing(ctx, userMessage, payloads, pmode)

# Security Processing

The MSH applies security based on P-Mode:
  - Verify incoming signatures
  - Decrypt incoming encrypted content
  - Sign outgoing messages
  - Encrypt outgoing payloads

# References

  - OASIS ebMS 3.0 Processing: https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/core/os/
*/
package msh
