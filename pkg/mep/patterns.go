// Package mep implements Message Exchange Patterns for AS4package mep

package mep

import (
	"context"
	"fmt"
)

// MEPType represents a Message Exchange Pattern type
type MEPType string

const (
	// OneWayPush is a one-way push MEP
	OneWayPush MEPType = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/oneWay"

	// TwoWay is a two-way MEP
	TwoWay MEPType = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/twoWay"

	// OneWayPull is a one-way pull MEP
	OneWayPull MEPType = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/oneWay"
)

// MEPBinding represents a MEP binding
type MEPBinding string

const (
	// Push binding
	Push MEPBinding = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/push"

	// PushAndPush binding for two-way
	PushAndPush MEPBinding = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/pushAndPush"

	// Pull binding
	Pull MEPBinding = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/pull"

	// PullAndPush binding
	PullAndPush MEPBinding = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/pullAndPush"

	// PushAndPull binding
	PushAndPull MEPBinding = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/pushAndPull"
)

// Exchange represents a message exchange
type Exchange struct {
	Type    MEPType
	Binding MEPBinding

	// For correlation
	ConversationID string
	MessageID      string
	RefToMessageID string
}

// Handler processes message exchanges
type Handler interface {
	// HandleRequest processes an incoming request message
	HandleRequest(ctx context.Context, message []byte) (response []byte, err error)

	// HandleResponse processes an incoming response message
	HandleResponse(ctx context.Context, message []byte) error

	// HandleReceipt processes an incoming receipt
	HandleReceipt(ctx context.Context, receipt []byte) error

	// HandleError processes an incoming error
	HandleError(ctx context.Context, errorMsg []byte) error
}

// OneWayPushHandler handles one-way push exchanges
type OneWayPushHandler struct {
	receiptHandler func(ctx context.Context, receipt []byte) error
	errorHandler   func(ctx context.Context, errorMsg []byte) error
}

// NewOneWayPushHandler creates a new one-way push handler
func NewOneWayPushHandler() *OneWayPushHandler {
	return &OneWayPushHandler{
		receiptHandler: func(ctx context.Context, receipt []byte) error { return nil },
		errorHandler:   func(ctx context.Context, errorMsg []byte) error { return nil },
	}
}

// HandleRequest processes a request (not used in one-way push from sender perspective)
func (h *OneWayPushHandler) HandleRequest(ctx context.Context, message []byte) ([]byte, error) {
	return nil, fmt.Errorf("one-way push handler does not handle requests")
}

// HandleResponse processes a response (receipt or error)
func (h *OneWayPushHandler) HandleResponse(ctx context.Context, message []byte) error {
	// Determine if it's a receipt or error and dispatch accordingly
	// This would parse the SOAP envelope to determine the type
	return nil
}

// HandleReceipt processes a receipt
func (h *OneWayPushHandler) HandleReceipt(ctx context.Context, receipt []byte) error {
	return h.receiptHandler(ctx, receipt)
}

// HandleError processes an error
func (h *OneWayPushHandler) HandleError(ctx context.Context, errorMsg []byte) error {
	return h.errorHandler(ctx, errorMsg)
}

// SetReceiptHandler sets the receipt handler
func (h *OneWayPushHandler) SetReceiptHandler(handler func(ctx context.Context, receipt []byte) error) {
	h.receiptHandler = handler
}

// SetErrorHandler sets the error handler
func (h *OneWayPushHandler) SetErrorHandler(handler func(ctx context.Context, errorMsg []byte) error) {
	h.errorHandler = handler
}

// TwoWayPushHandler handles two-way push-and-push exchanges
type TwoWayPushHandler struct {
	requestHandler  func(ctx context.Context, request []byte) ([]byte, error)
	responseHandler func(ctx context.Context, response []byte) error
	receiptHandler  func(ctx context.Context, receipt []byte) error
	errorHandler    func(ctx context.Context, errorMsg []byte) error
}

// NewTwoWayPushHandler creates a new two-way push handler
func NewTwoWayPushHandler() *TwoWayPushHandler {
	return &TwoWayPushHandler{
		requestHandler:  func(ctx context.Context, request []byte) ([]byte, error) { return nil, nil },
		responseHandler: func(ctx context.Context, response []byte) error { return nil },
		receiptHandler:  func(ctx context.Context, receipt []byte) error { return nil },
		errorHandler:    func(ctx context.Context, errorMsg []byte) error { return nil },
	}
}

// HandleRequest processes an incoming request message
func (h *TwoWayPushHandler) HandleRequest(ctx context.Context, message []byte) ([]byte, error) {
	return h.requestHandler(ctx, message)
}

// HandleResponse processes an incoming response message
func (h *TwoWayPushHandler) HandleResponse(ctx context.Context, message []byte) error {
	return h.responseHandler(ctx, message)
}

// HandleReceipt processes a receipt
func (h *TwoWayPushHandler) HandleReceipt(ctx context.Context, receipt []byte) error {
	return h.receiptHandler(ctx, receipt)
}

// HandleError processes an error
func (h *TwoWayPushHandler) HandleError(ctx context.Context, errorMsg []byte) error {
	return h.errorHandler(ctx, errorMsg)
}

// SetRequestHandler sets the request handler
func (h *TwoWayPushHandler) SetRequestHandler(handler func(ctx context.Context, request []byte) ([]byte, error)) {
	h.requestHandler = handler
}

// SetResponseHandler sets the response handler
func (h *TwoWayPushHandler) SetResponseHandler(handler func(ctx context.Context, response []byte) error) {
	h.responseHandler = handler
}

// SetReceiptHandler sets the receipt handler
func (h *TwoWayPushHandler) SetReceiptHandler(handler func(ctx context.Context, receipt []byte) error) {
	h.receiptHandler = handler
}

// SetErrorHandler sets the error handler
func (h *TwoWayPushHandler) SetErrorHandler(handler func(ctx context.Context, errorMsg []byte) error) {
	h.errorHandler = handler
}
