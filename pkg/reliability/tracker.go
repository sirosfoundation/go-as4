// Package reliability implements AS4 Reception Awareness, Retry, and Duplicate Detectionpackage reliability

package reliability

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// MessageState represents the state of a message in the reliability layer
type MessageState int

const (
	StateSubmitted       MessageState = iota // Message submitted for sending
	StateSending                             // Message is being sent
	StateAwaitingReceipt                     // Awaiting receipt
	StateReceived                            // Receipt received
	StateFailed                              // Failed after retries
)

// MessageTracker tracks messages for reception awareness
type MessageTracker struct {
	mu       sync.RWMutex
	messages map[string]*TrackedMessage

	// Duplicate detection
	receivedMessages map[string]time.Time
	duplicateWindow  time.Duration
}

// TrackedMessage represents a tracked message
type TrackedMessage struct {
	MessageID       string
	State           MessageState
	SubmittedAt     time.Time
	LastAttemptAt   time.Time
	AttemptCount    int
	MaxRetries      int
	RetryInterval   time.Duration
	RetryMultiplier float64
	Receipt         []byte
	Errors          []string
}

// NewMessageTracker creates a new message tracker
func NewMessageTracker(duplicateWindow time.Duration) *MessageTracker {
	tracker := &MessageTracker{
		messages:         make(map[string]*TrackedMessage),
		receivedMessages: make(map[string]time.Time),
		duplicateWindow:  duplicateWindow,
	}

	// Start cleanup goroutine
	go tracker.cleanupExpiredMessages()

	return tracker
}

// Track starts tracking a message
func (t *MessageTracker) Track(messageID string, maxRetries int, retryInterval time.Duration, retryMultiplier float64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.messages[messageID] = &TrackedMessage{
		MessageID:       messageID,
		State:           StateSubmitted,
		SubmittedAt:     time.Now(),
		MaxRetries:      maxRetries,
		RetryInterval:   retryInterval,
		RetryMultiplier: retryMultiplier,
		Errors:          make([]string, 0),
	}
}

// MarkSending marks a message as being sent
func (t *MessageTracker) MarkSending(messageID string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	msg, exists := t.messages[messageID]
	if !exists {
		return fmt.Errorf("message %s not tracked", messageID)
	}

	msg.State = StateSending
	msg.LastAttemptAt = time.Now()
	msg.AttemptCount++

	return nil
}

// MarkAwaitingReceipt marks a message as awaiting receipt
func (t *MessageTracker) MarkAwaitingReceipt(messageID string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	msg, exists := t.messages[messageID]
	if !exists {
		return fmt.Errorf("message %s not tracked", messageID)
	}

	msg.State = StateAwaitingReceipt

	return nil
}

// RecordReceipt records a receipt for a message
func (t *MessageTracker) RecordReceipt(messageID string, receipt []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	msg, exists := t.messages[messageID]
	if !exists {
		return fmt.Errorf("message %s not tracked", messageID)
	}

	msg.State = StateReceived
	msg.Receipt = receipt

	return nil
}

// RecordError records an error for a message
func (t *MessageTracker) RecordError(messageID string, err error) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	msg, exists := t.messages[messageID]
	if !exists {
		return fmt.Errorf("message %s not tracked", messageID)
	}

	msg.Errors = append(msg.Errors, err.Error())

	// Check if we should retry or mark as failed
	if msg.AttemptCount >= msg.MaxRetries {
		msg.State = StateFailed
	} else {
		msg.State = StateSubmitted // Ready for retry
	}

	return nil
}

// ShouldRetry checks if a message should be retried
func (t *MessageTracker) ShouldRetry(messageID string) (bool, time.Duration) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	msg, exists := t.messages[messageID]
	if !exists {
		return false, 0
	}

	if msg.State != StateSubmitted {
		return false, 0
	}

	if msg.AttemptCount >= msg.MaxRetries {
		return false, 0
	}

	// Calculate retry delay with exponential backoff
	delay := time.Duration(float64(msg.RetryInterval) *
		(msg.RetryMultiplier * float64(msg.AttemptCount)))

	timeSinceLastAttempt := time.Since(msg.LastAttemptAt)
	if timeSinceLastAttempt < delay {
		return false, delay - timeSinceLastAttempt
	}

	return true, 0
}

// GetMessage retrieves a tracked message
func (t *MessageTracker) GetMessage(messageID string) (*TrackedMessage, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	msg, exists := t.messages[messageID]
	return msg, exists
}

// RemoveMessage removes a message from tracking
func (t *MessageTracker) RemoveMessage(messageID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.messages, messageID)
}

// IsDuplicate checks if a message is a duplicate
func (t *MessageTracker) IsDuplicate(messageID string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	receivedAt, exists := t.receivedMessages[messageID]
	if !exists {
		return false
	}

	// Check if still within duplicate detection window
	return time.Since(receivedAt) < t.duplicateWindow
}

// MarkReceived marks a message as received (for duplicate detection)
func (t *MessageTracker) MarkReceived(messageID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.receivedMessages[messageID] = time.Now()
}

// cleanupExpiredMessages removes old received messages from duplicate detection
func (t *MessageTracker) cleanupExpiredMessages() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		t.mu.Lock()
		now := time.Now()

		for msgID, receivedAt := range t.receivedMessages {
			if now.Sub(receivedAt) > t.duplicateWindow {
				delete(t.receivedMessages, msgID)
			}
		}

		t.mu.Unlock()
	}
}

// ComputeMessageHash computes a hash of message content for duplicate detection
func ComputeMessageHash(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}

// ReceiptValidator validates AS4 receipts
type ReceiptValidator struct {
	// Configuration for receipt validation
}

// NewReceiptValidator creates a new receipt validator
func NewReceiptValidator() *ReceiptValidator {
	return &ReceiptValidator{}
}

// ValidateReceipt validates a receipt against the original message
func (v *ReceiptValidator) ValidateReceipt(receipt []byte, originalMessage []byte) error {
	// TODO: Implement receipt validation
	// - Verify signature on receipt
	// - Verify digest values match
	// - Verify reference to original message

	return nil
}

// ErrorCode represents AS4 error codes
type ErrorCode struct {
	Code             string
	Severity         string
	ShortDescription string
	Category         string
}

// Predefined AS4 error codes
var (
	ErrorDeliveryFailure = ErrorCode{
		Code:             "EBMS:0202",
		Severity:         "Failure",
		ShortDescription: "DeliveryFailure",
		Category:         "Communication",
	}

	ErrorMissingReceipt = ErrorCode{
		Code:             "EBMS:0301",
		Severity:         "Failure",
		ShortDescription: "MissingReceipt",
		Category:         "Communication",
	}

	ErrorDecompressionFailure = ErrorCode{
		Code:             "EBMS:0303",
		Severity:         "Failure",
		ShortDescription: "DecompressionFailure",
		Category:         "Communication",
	}

	ErrorEmptyMessagePartition = ErrorCode{
		Code:             "EBMS:0006",
		Severity:         "Warning",
		ShortDescription: "EmptyMessagePartitionChannel",
		Category:         "Communication",
	}
)
