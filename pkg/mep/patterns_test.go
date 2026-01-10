package mep

import (
	"context"
	"errors"
	"testing"
)

func TestMEPTypeConstants(t *testing.T) {
	// Verify MEP type URIs are correct per ebMS 3.0 spec
	if OneWayPush != "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/oneWay" {
		t.Errorf("unexpected OneWayPush URI: %s", OneWayPush)
	}
	if TwoWay != "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/twoWay" {
		t.Errorf("unexpected TwoWay URI: %s", TwoWay)
	}
}

func TestMEPBindingConstants(t *testing.T) {
	// Verify MEP binding URIs are correct
	if Push != "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/push" {
		t.Errorf("unexpected Push URI: %s", Push)
	}
	if PushAndPush != "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/pushAndPush" {
		t.Errorf("unexpected PushAndPush URI: %s", PushAndPush)
	}
	if Pull != "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/pull" {
		t.Errorf("unexpected Pull URI: %s", Pull)
	}
}

func TestExchange(t *testing.T) {
	exchange := Exchange{
		Type:           OneWayPush,
		Binding:        Push,
		ConversationID: "conv-123",
		MessageID:      "msg-456",
		RefToMessageID: "msg-455",
	}

	if exchange.Type != OneWayPush {
		t.Errorf("expected OneWayPush, got %s", exchange.Type)
	}
	if exchange.Binding != Push {
		t.Errorf("expected Push, got %s", exchange.Binding)
	}
	if exchange.ConversationID != "conv-123" {
		t.Errorf("expected conv-123, got %s", exchange.ConversationID)
	}
	if exchange.MessageID != "msg-456" {
		t.Errorf("expected msg-456, got %s", exchange.MessageID)
	}
	if exchange.RefToMessageID != "msg-455" {
		t.Errorf("expected msg-455, got %s", exchange.RefToMessageID)
	}
}

func TestNewOneWayPushHandler(t *testing.T) {
	handler := NewOneWayPushHandler()
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
	if handler.receiptHandler == nil {
		t.Error("expected default receiptHandler to be set")
	}
	if handler.errorHandler == nil {
		t.Error("expected default errorHandler to be set")
	}
}

func TestOneWayPushHandler_HandleRequest(t *testing.T) {
	handler := NewOneWayPushHandler()
	ctx := context.Background()

	// One-way push handler should not handle requests
	response, err := handler.HandleRequest(ctx, []byte("test"))
	if err == nil {
		t.Error("expected error for HandleRequest on one-way push")
	}
	if response != nil {
		t.Error("expected nil response")
	}
	if err.Error() != "one-way push handler does not handle requests" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestOneWayPushHandler_HandleResponse(t *testing.T) {
	handler := NewOneWayPushHandler()
	ctx := context.Background()

	// Default implementation returns nil
	err := handler.HandleResponse(ctx, []byte("test"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestOneWayPushHandler_HandleReceipt(t *testing.T) {
	handler := NewOneWayPushHandler()
	ctx := context.Background()

	// Test default handler
	err := handler.HandleReceipt(ctx, []byte("receipt"))
	if err != nil {
		t.Errorf("default handler should not error: %v", err)
	}

	// Test custom handler
	receiptReceived := false
	handler.SetReceiptHandler(func(ctx context.Context, receipt []byte) error {
		receiptReceived = true
		if string(receipt) != "custom-receipt" {
			t.Errorf("expected 'custom-receipt', got '%s'", string(receipt))
		}
		return nil
	})

	err = handler.HandleReceipt(ctx, []byte("custom-receipt"))
	if err != nil {
		t.Errorf("custom handler should not error: %v", err)
	}
	if !receiptReceived {
		t.Error("custom receipt handler was not called")
	}
}

func TestOneWayPushHandler_HandleError(t *testing.T) {
	handler := NewOneWayPushHandler()
	ctx := context.Background()

	// Test default handler
	err := handler.HandleError(ctx, []byte("error"))
	if err != nil {
		t.Errorf("default handler should not error: %v", err)
	}

	// Test custom handler
	errorReceived := false
	handler.SetErrorHandler(func(ctx context.Context, errorMsg []byte) error {
		errorReceived = true
		return nil
	})

	err = handler.HandleError(ctx, []byte("custom-error"))
	if err != nil {
		t.Errorf("custom handler should not error: %v", err)
	}
	if !errorReceived {
		t.Error("custom error handler was not called")
	}
}

func TestOneWayPushHandler_HandlerReturnsError(t *testing.T) {
	handler := NewOneWayPushHandler()
	ctx := context.Background()

	expectedErr := errors.New("processing failed")

	handler.SetReceiptHandler(func(ctx context.Context, receipt []byte) error {
		return expectedErr
	})

	err := handler.HandleReceipt(ctx, []byte("receipt"))
	if err != expectedErr {
		t.Errorf("expected error '%v', got '%v'", expectedErr, err)
	}
}

func TestNewTwoWayPushHandler(t *testing.T) {
	handler := NewTwoWayPushHandler()
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
	if handler.requestHandler == nil {
		t.Error("expected default requestHandler to be set")
	}
	if handler.responseHandler == nil {
		t.Error("expected default responseHandler to be set")
	}
	if handler.receiptHandler == nil {
		t.Error("expected default receiptHandler to be set")
	}
	if handler.errorHandler == nil {
		t.Error("expected default errorHandler to be set")
	}
}

func TestTwoWayPushHandler_HandleRequest(t *testing.T) {
	handler := NewTwoWayPushHandler()
	ctx := context.Background()

	// Test default handler
	response, err := handler.HandleRequest(ctx, []byte("request"))
	if err != nil {
		t.Errorf("default handler should not error: %v", err)
	}
	if response != nil {
		t.Error("default handler should return nil response")
	}

	// Test custom handler
	handler.SetRequestHandler(func(ctx context.Context, request []byte) ([]byte, error) {
		return []byte("response-to-" + string(request)), nil
	})

	response, err = handler.HandleRequest(ctx, []byte("test-request"))
	if err != nil {
		t.Errorf("custom handler should not error: %v", err)
	}
	if string(response) != "response-to-test-request" {
		t.Errorf("expected 'response-to-test-request', got '%s'", string(response))
	}
}

func TestTwoWayPushHandler_HandleResponse(t *testing.T) {
	handler := NewTwoWayPushHandler()
	ctx := context.Background()

	// Test default handler
	err := handler.HandleResponse(ctx, []byte("response"))
	if err != nil {
		t.Errorf("default handler should not error: %v", err)
	}

	// Test custom handler
	responseReceived := false
	handler.SetResponseHandler(func(ctx context.Context, response []byte) error {
		responseReceived = true
		return nil
	})

	err = handler.HandleResponse(ctx, []byte("custom-response"))
	if err != nil {
		t.Errorf("custom handler should not error: %v", err)
	}
	if !responseReceived {
		t.Error("custom response handler was not called")
	}
}

func TestTwoWayPushHandler_HandleReceipt(t *testing.T) {
	handler := NewTwoWayPushHandler()
	ctx := context.Background()

	receiptReceived := false
	handler.SetReceiptHandler(func(ctx context.Context, receipt []byte) error {
		receiptReceived = true
		return nil
	})

	err := handler.HandleReceipt(ctx, []byte("receipt"))
	if err != nil {
		t.Errorf("handler should not error: %v", err)
	}
	if !receiptReceived {
		t.Error("receipt handler was not called")
	}
}

func TestTwoWayPushHandler_HandleError(t *testing.T) {
	handler := NewTwoWayPushHandler()
	ctx := context.Background()

	errorReceived := false
	handler.SetErrorHandler(func(ctx context.Context, errorMsg []byte) error {
		errorReceived = true
		return nil
	})

	err := handler.HandleError(ctx, []byte("error"))
	if err != nil {
		t.Errorf("handler should not error: %v", err)
	}
	if !errorReceived {
		t.Error("error handler was not called")
	}
}

func TestTwoWayPushHandler_AllSetters(t *testing.T) {
	handler := NewTwoWayPushHandler()

	// Verify all setters work without panic
	handler.SetRequestHandler(func(ctx context.Context, request []byte) ([]byte, error) {
		return nil, nil
	})
	handler.SetResponseHandler(func(ctx context.Context, response []byte) error {
		return nil
	})
	handler.SetReceiptHandler(func(ctx context.Context, receipt []byte) error {
		return nil
	})
	handler.SetErrorHandler(func(ctx context.Context, errorMsg []byte) error {
		return nil
	})

	// If we get here without panic, all setters work
}

func TestHandlerInterface(t *testing.T) {
	// Verify OneWayPushHandler implements Handler interface
	var _ Handler = (*OneWayPushHandler)(nil)

	// Verify TwoWayPushHandler implements Handler interface
	var _ Handler = (*TwoWayPushHandler)(nil)
}
