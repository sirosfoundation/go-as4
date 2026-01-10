// Copyright (c) 2024 SIROS Foundation
// SPDX-License-Identifier: BSD-2-Clause

/*
Package reliability provides reception awareness for AS4 messaging.

This package implements the reception awareness features specified in the
OASIS AS4 Profile, ensuring reliable message delivery.

# Reception Awareness

Reception awareness provides:
  - Retry mechanism for failed deliveries
  - Duplicate detection to prevent reprocessing
  - Message tracking and status monitoring

# Message Tracker

Track message status and detect duplicates:

	tracker := reliability.NewMessageTracker(24 * time.Hour)

	// Track sent message
	tracker.TrackSent(messageID, timestamp)

	// Check for duplicates
	if tracker.IsDuplicate(messageID) {
	    // Handle duplicate
	}

	// Update status on receipt
	tracker.MarkReceived(messageID)

# Retry Configuration

Configure retry behavior in P-Mode:

	receptionAwareness := &pmode.ReceptionAwareness{
	    Retry: &pmode.RetryConfig{
	        MaxRetries: 3,
	        RetryInterval: 5 * time.Minute,
	    },
	    DuplicateDetection: &pmode.DuplicateDetection{
	        Window: 24 * time.Hour,
	    },
	}

# References

  - OASIS AS4 Reception Awareness: https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/
*/
package reliability
