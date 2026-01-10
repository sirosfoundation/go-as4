package reliability

import (
	"errors"
	"testing"
	"time"
)

func TestNewMessageTracker(t *testing.T) {
	tracker := NewMessageTracker(24 * time.Hour)
	if tracker == nil {
		t.Fatal("expected non-nil tracker")
	}
	if tracker.messages == nil {
		t.Error("expected messages map to be initialized")
	}
	if tracker.receivedMessages == nil {
		t.Error("expected receivedMessages map to be initialized")
	}
	if tracker.duplicateWindow != 24*time.Hour {
		t.Errorf("expected duplicateWindow 24h, got %v", tracker.duplicateWindow)
	}
}

func TestMessageTracker_Track(t *testing.T) {
	tracker := NewMessageTracker(time.Hour)

	tracker.Track("msg-1", 3, time.Minute, 2.0)

	msg, exists := tracker.GetMessage("msg-1")
	if !exists {
		t.Fatal("expected message to exist")
	}
	if msg.MessageID != "msg-1" {
		t.Errorf("expected MessageID 'msg-1', got '%s'", msg.MessageID)
	}
	if msg.State != StateSubmitted {
		t.Errorf("expected StateSubmitted, got %d", msg.State)
	}
	if msg.MaxRetries != 3 {
		t.Errorf("expected MaxRetries 3, got %d", msg.MaxRetries)
	}
	if msg.RetryInterval != time.Minute {
		t.Errorf("expected RetryInterval 1m, got %v", msg.RetryInterval)
	}
	if msg.RetryMultiplier != 2.0 {
		t.Errorf("expected RetryMultiplier 2.0, got %f", msg.RetryMultiplier)
	}
	if msg.AttemptCount != 0 {
		t.Errorf("expected AttemptCount 0, got %d", msg.AttemptCount)
	}
}

func TestMessageTracker_GetMessage_NotFound(t *testing.T) {
	tracker := NewMessageTracker(time.Hour)

	msg, exists := tracker.GetMessage("nonexistent")
	if exists {
		t.Error("expected message to not exist")
	}
	if msg != nil {
		t.Error("expected nil message")
	}
}

func TestMessageTracker_MarkSending(t *testing.T) {
	tracker := NewMessageTracker(time.Hour)

	// Track a message first
	tracker.Track("msg-1", 3, time.Minute, 2.0)

	// Mark as sending
	err := tracker.MarkSending("msg-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg, _ := tracker.GetMessage("msg-1")
	if msg.State != StateSending {
		t.Errorf("expected StateSending, got %d", msg.State)
	}
	if msg.AttemptCount != 1 {
		t.Errorf("expected AttemptCount 1, got %d", msg.AttemptCount)
	}
	if msg.LastAttemptAt.IsZero() {
		t.Error("expected LastAttemptAt to be set")
	}
}

func TestMessageTracker_MarkSending_NotTracked(t *testing.T) {
	tracker := NewMessageTracker(time.Hour)

	err := tracker.MarkSending("nonexistent")
	if err == nil {
		t.Error("expected error for untracked message")
	}
}

func TestMessageTracker_MarkAwaitingReceipt(t *testing.T) {
	tracker := NewMessageTracker(time.Hour)

	tracker.Track("msg-1", 3, time.Minute, 2.0)
	tracker.MarkSending("msg-1")

	err := tracker.MarkAwaitingReceipt("msg-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg, _ := tracker.GetMessage("msg-1")
	if msg.State != StateAwaitingReceipt {
		t.Errorf("expected StateAwaitingReceipt, got %d", msg.State)
	}
}

func TestMessageTracker_MarkAwaitingReceipt_NotTracked(t *testing.T) {
	tracker := NewMessageTracker(time.Hour)

	err := tracker.MarkAwaitingReceipt("nonexistent")
	if err == nil {
		t.Error("expected error for untracked message")
	}
}

func TestMessageTracker_RecordReceipt(t *testing.T) {
	tracker := NewMessageTracker(time.Hour)

	tracker.Track("msg-1", 3, time.Minute, 2.0)
	tracker.MarkSending("msg-1")
	tracker.MarkAwaitingReceipt("msg-1")

	receiptData := []byte("<Receipt>...</Receipt>")
	err := tracker.RecordReceipt("msg-1", receiptData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg, _ := tracker.GetMessage("msg-1")
	if msg.State != StateReceived {
		t.Errorf("expected StateReceived, got %d", msg.State)
	}
	if string(msg.Receipt) != string(receiptData) {
		t.Errorf("expected receipt data to be stored")
	}
}

func TestMessageTracker_RecordReceipt_NotTracked(t *testing.T) {
	tracker := NewMessageTracker(time.Hour)

	err := tracker.RecordReceipt("nonexistent", []byte("receipt"))
	if err == nil {
		t.Error("expected error for untracked message")
	}
}

func TestMessageTracker_RecordError(t *testing.T) {
	tracker := NewMessageTracker(time.Hour)

	tracker.Track("msg-1", 3, time.Minute, 2.0)
	tracker.MarkSending("msg-1")

	err := tracker.RecordError("msg-1", errors.New("connection failed"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	msg, _ := tracker.GetMessage("msg-1")
	if len(msg.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(msg.Errors))
	}
	if msg.Errors[0] != "connection failed" {
		t.Errorf("expected 'connection failed', got '%s'", msg.Errors[0])
	}
	// Should be back to submitted for retry (attempt 1 < max 3)
	if msg.State != StateSubmitted {
		t.Errorf("expected StateSubmitted (for retry), got %d", msg.State)
	}
}

func TestMessageTracker_RecordError_MaxRetries(t *testing.T) {
	tracker := NewMessageTracker(time.Hour)

	tracker.Track("msg-1", 2, time.Minute, 2.0)

	// Simulate 2 failed attempts
	tracker.MarkSending("msg-1")
	tracker.RecordError("msg-1", errors.New("error 1"))
	tracker.MarkSending("msg-1")
	tracker.RecordError("msg-1", errors.New("error 2"))

	msg, _ := tracker.GetMessage("msg-1")
	if msg.State != StateFailed {
		t.Errorf("expected StateFailed after max retries, got %d", msg.State)
	}
	if len(msg.Errors) != 2 {
		t.Errorf("expected 2 errors, got %d", len(msg.Errors))
	}
}

func TestMessageTracker_RecordError_NotTracked(t *testing.T) {
	tracker := NewMessageTracker(time.Hour)

	err := tracker.RecordError("nonexistent", errors.New("error"))
	if err == nil {
		t.Error("expected error for untracked message")
	}
}

func TestMessageTracker_ShouldRetry(t *testing.T) {
	tracker := NewMessageTracker(time.Hour)

	// Use small retry interval with multiplier 1.0 for predictable timing
	// delay = interval * multiplier * attemptCount = 50ms * 1.0 * 1 = 50ms
	tracker.Track("msg-1", 3, 50*time.Millisecond, 1.0)

	// Newly submitted - should retry (hasn't been sent yet, AttemptCount=0)
	shouldRetry, _ := tracker.ShouldRetry("msg-1")
	if !shouldRetry {
		t.Error("expected shouldRetry true for newly tracked message")
	}

	// After marking as sending, state changes
	tracker.MarkSending("msg-1")
	shouldRetry, _ = tracker.ShouldRetry("msg-1")
	if shouldRetry {
		t.Error("expected shouldRetry false while sending")
	}

	// After error, message goes back to submitted state
	tracker.RecordError("msg-1", errors.New("error"))

	// Check state is back to submitted
	msg, _ := tracker.GetMessage("msg-1")
	if msg.State != StateSubmitted {
		t.Errorf("expected StateSubmitted after error, got %d", msg.State)
	}

	// Wait for retry delay: 50ms * 1.0 * 1 = 50ms (plus buffer)
	time.Sleep(100 * time.Millisecond)
	shouldRetry, _ = tracker.ShouldRetry("msg-1")
	if !shouldRetry {
		t.Error("expected shouldRetry true after error and delay")
	}
}

func TestMessageTracker_ShouldRetry_NotTracked(t *testing.T) {
	tracker := NewMessageTracker(time.Hour)

	shouldRetry, delay := tracker.ShouldRetry("nonexistent")
	if shouldRetry {
		t.Error("expected shouldRetry false for untracked message")
	}
	if delay != 0 {
		t.Errorf("expected delay 0, got %v", delay)
	}
}

func TestMessageTracker_ShouldRetry_MaxRetriesReached(t *testing.T) {
	tracker := NewMessageTracker(time.Hour)

	tracker.Track("msg-1", 1, time.Millisecond, 1.0)
	tracker.MarkSending("msg-1")
	tracker.RecordError("msg-1", errors.New("error"))

	// Should be failed now (1 attempt = max 1)
	msg, _ := tracker.GetMessage("msg-1")
	if msg.State != StateFailed {
		t.Errorf("expected StateFailed, got %d", msg.State)
	}

	shouldRetry, _ := tracker.ShouldRetry("msg-1")
	if shouldRetry {
		t.Error("expected shouldRetry false after max retries")
	}
}

func TestMessageTracker_RemoveMessage(t *testing.T) {
	tracker := NewMessageTracker(time.Hour)

	tracker.Track("msg-1", 3, time.Minute, 2.0)

	// Verify it exists
	_, exists := tracker.GetMessage("msg-1")
	if !exists {
		t.Fatal("message should exist before removal")
	}

	tracker.RemoveMessage("msg-1")

	_, exists = tracker.GetMessage("msg-1")
	if exists {
		t.Error("message should be removed")
	}
}

func TestMessageTracker_IsDuplicate(t *testing.T) {
	tracker := NewMessageTracker(100 * time.Millisecond)

	// Not received yet
	if tracker.IsDuplicate("msg-1") {
		t.Error("expected not duplicate before marking received")
	}

	// Mark as received
	tracker.MarkReceived("msg-1")

	// Should be duplicate now
	if !tracker.IsDuplicate("msg-1") {
		t.Error("expected duplicate after marking received")
	}

	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)

	// Should no longer be duplicate
	if tracker.IsDuplicate("msg-1") {
		t.Error("expected not duplicate after window expiry")
	}
}

func TestMessageTracker_MarkReceived(t *testing.T) {
	tracker := NewMessageTracker(time.Hour)

	tracker.MarkReceived("msg-1")

	// Check it was recorded
	tracker.mu.RLock()
	_, exists := tracker.receivedMessages["msg-1"]
	tracker.mu.RUnlock()

	if !exists {
		t.Error("expected message to be in receivedMessages")
	}
}

func TestComputeMessageHash(t *testing.T) {
	content := []byte("test message content")

	hash1 := ComputeMessageHash(content)
	hash2 := ComputeMessageHash(content)

	// Should be deterministic
	if hash1 != hash2 {
		t.Error("hash should be deterministic")
	}

	// Should be hex string
	if len(hash1) != 64 { // SHA256 = 32 bytes = 64 hex chars
		t.Errorf("expected 64 char hash, got %d", len(hash1))
	}

	// Different content should produce different hash
	hash3 := ComputeMessageHash([]byte("different content"))
	if hash1 == hash3 {
		t.Error("different content should produce different hash")
	}
}

func TestNewReceiptValidator(t *testing.T) {
	validator := NewReceiptValidator()
	if validator == nil {
		t.Fatal("expected non-nil validator")
	}
}

func TestReceiptValidator_ValidateReceipt(t *testing.T) {
	validator := NewReceiptValidator()

	// Current implementation is a placeholder
	err := validator.ValidateReceipt([]byte("receipt"), []byte("original"))
	if err != nil {
		t.Errorf("placeholder should not error: %v", err)
	}
}

func TestMessageState_Values(t *testing.T) {
	// Verify state constants are distinct
	states := []MessageState{
		StateSubmitted,
		StateSending,
		StateAwaitingReceipt,
		StateReceived,
		StateFailed,
	}

	seen := make(map[MessageState]bool)
	for _, state := range states {
		if seen[state] {
			t.Errorf("duplicate state value: %d", state)
		}
		seen[state] = true
	}
}

func TestErrorCodes(t *testing.T) {
	// Verify error codes are properly defined
	tests := []struct {
		name     string
		code     ErrorCode
		expected string
	}{
		{
			name:     "DeliveryFailure",
			code:     ErrorDeliveryFailure,
			expected: "EBMS:0202",
		},
		{
			name:     "MissingReceipt",
			code:     ErrorMissingReceipt,
			expected: "EBMS:0301",
		},
		{
			name:     "DecompressionFailure",
			code:     ErrorDecompressionFailure,
			expected: "EBMS:0303",
		},
		{
			name:     "EmptyMessagePartition",
			code:     ErrorEmptyMessagePartition,
			expected: "EBMS:0006",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.code.Code != tt.expected {
				t.Errorf("expected code '%s', got '%s'", tt.expected, tt.code.Code)
			}
			if tt.code.ShortDescription == "" {
				t.Error("expected ShortDescription to be set")
			}
			if tt.code.Severity == "" {
				t.Error("expected Severity to be set")
			}
		})
	}
}

func TestTrackedMessage_Fields(t *testing.T) {
	msg := &TrackedMessage{
		MessageID:       "msg-123",
		State:           StateSubmitted,
		SubmittedAt:     time.Now(),
		MaxRetries:      5,
		RetryInterval:   time.Minute,
		RetryMultiplier: 1.5,
		Errors:          []string{"error1", "error2"},
	}

	if msg.MessageID != "msg-123" {
		t.Error("MessageID mismatch")
	}
	if msg.State != StateSubmitted {
		t.Error("State mismatch")
	}
	if msg.MaxRetries != 5 {
		t.Error("MaxRetries mismatch")
	}
	if len(msg.Errors) != 2 {
		t.Error("Errors mismatch")
	}
}
