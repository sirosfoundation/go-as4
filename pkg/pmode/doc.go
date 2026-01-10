// Copyright (c) 2024 SIROS Foundation
// SPDX-License-Identifier: BSD-2-Clause

/*
Package pmode provides Processing Mode (P-Mode) configuration for AS4.

P-Mode is the central configuration mechanism in AS4 that defines how
messages are processed. Each P-Mode specifies settings for a particular
message exchange agreement between parties.

# P-Mode Structure

A P-Mode contains the following configuration sections:

	type ProcessingMode struct {
	    ID                    string
	    Agreement             Agreement           // Business agreement reference
	    MEP                   MEP                 // Message Exchange Pattern
	    MEPBinding            MEPBinding          // Protocol binding
	    Initiator             PartyInfo           // Sending party configuration
	    Responder             PartyInfo           // Receiving party configuration
	    Protocol              Protocol            // Transport protocol settings
	    BusinessInfo          BusinessInfo        // Service and action
	    PayloadService        PayloadService      // Compression settings
	    ReceptionAwareness    ReceptionAwareness  // Retry and duplicate detection
	    Security              Security            // Signing and encryption settings
	}

# Creating P-Modes

Use the default P-Mode as a starting point:

	pmode := pmode.DefaultPMode()
	pmode.ID = "my-pmode"
	pmode.BusinessInfo.Service = "OrderService"
	pmode.BusinessInfo.Action = "submitOrder"

# P-Mode Manager

The P-Mode manager handles P-Mode resolution:

	manager := pmode.NewPModeManager()
	manager.AddPMode(pmode)

	// Find matching P-Mode
	found := manager.FindPMode(service, action, fromParty, toParty)

# Message Exchange Patterns

Supported MEPs:
  - One-Way/Push: Sender initiates, receiver responds with receipt
  - One-Way/Pull: Receiver initiates request for waiting messages (planned)

# References

  - OASIS AS4 P-Mode: https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/
  - eDelivery P-Mode: https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/
*/
package pmode
