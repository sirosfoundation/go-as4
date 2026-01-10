// Copyright (c) 2024 SIROS Foundation
// SPDX-License-Identifier: BSD-2-Clause

/*
Package mep defines Message Exchange Patterns for AS4.

This package implements the Message Exchange Patterns (MEPs) specified in
the OASIS AS4 Profile.

# Supported MEPs

One-Way/Push:

  - Sender initiates HTTP POST with UserMessage

  - Receiver responds with Receipt signal

  - Most common pattern for document exchange

    mep := mep.OneWayPush

One-Way/Pull (planned):

  - Receiver initiates request for waiting messages

  - Sender responds with queued messages

  - Used when receiver cannot accept incoming connections

    mep := mep.OneWayPull

# MEP Bindings

MEP bindings define how MEPs map to protocols:

	Push: HTTP POST initiates message transfer
	Pull: HTTP POST with PullRequest signal

# References

  - OASIS AS4 MEP: https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/
  - OASIS ebMS 3.0 MEP: https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/core/os/
*/
package mep
