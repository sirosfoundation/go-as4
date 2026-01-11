// Package jmap implements a JMAP (JSON Meta Application Protocol) server
// extension for AS4 message exchange, as defined in RFC 8620.
//
// This package provides a custom JMAP capability "urn:ietf:params:jmap:as4"
// for managing AS4 messages, mailboxes, and trading partners through a
// stateless, RESTful JSON API optimized for efficient client synchronization.
//
// # Supported Methods
//
// The following JMAP methods are implemented:
//
//   - AS4Message/get: Retrieve messages by ID
//   - AS4Message/changes: Get IDs of changed messages since a state
//   - AS4Message/query: Search messages with filters and sorting
//   - AS4Message/queryChanges: Get changes to a query result since a state
//   - AS4Message/set: Create, update, or destroy messages
//   - AS4Mailbox/get: Retrieve mailboxes by ID
//   - AS4Mailbox/changes: Get IDs of changed mailboxes since a state
//   - AS4Participant/get: Retrieve trading partners by ID
//   - AS4Participant/set: Create, update, or destroy trading partners
//
// # Authentication
//
// All JMAP endpoints require OAuth2/JWT authentication. The tenant ID is
// extracted from the JWT claims and used to scope all operations.
//
// # State Management
//
// Each data type (AS4Message, AS4Mailbox, AS4Participant) maintains an
// independent state string that changes whenever any object of that type
// is modified. Clients use these states for efficient synchronization.
package jmap

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/sirosfoundation/go-as4/internal/storage"
)

// Handler processes JMAP requests
type Handler struct {
	store  storage.Store
	logger *slog.Logger
	apiURL string
}

// NewHandler creates a new JMAP handler
func NewHandler(store storage.Store, apiURL string, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		store:  store,
		logger: logger,
		apiURL: apiURL,
	}
}

// getSessionState returns a combined state string representing all data types
func (h *Handler) getSessionState(ctx context.Context, tenantID string) string {
	// Get individual states for each data type and combine them
	// The session state changes when any data type changes
	var latestTime time.Time

	for _, dataType := range []string{"AS4Message", "Mailbox", "Participant"} {
		state, err := h.store.GetState(ctx, tenantID, dataType)
		if err != nil || state == "" {
			continue
		}
		// Decode state to get timestamp
		ts, err := decodeStateTime(state)
		if err != nil {
			continue
		}
		if ts.After(latestTime) {
			latestTime = ts
		}
	}

	if latestTime.IsZero() {
		latestTime = time.Now()
	}

	return encodeStateTime(latestTime)
}

// encodeStateTime converts a time to a state string
func encodeStateTime(t time.Time) string {
	return fmt.Sprintf("%016x", t.UnixNano())
}

// decodeStateTime converts a state string back to a time
func decodeStateTime(state string) (time.Time, error) {
	var nanos int64
	_, err := fmt.Sscanf(state, "%016x", &nanos)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(0, nanos), nil
}

// GetSession returns the JMAP session for a tenant
func (h *Handler) GetSession(ctx context.Context, tenantID, username string) (*Session, error) {
	tenant, err := h.store.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("getting tenant: %w", err)
	}
	if tenant == nil {
		return nil, fmt.Errorf("tenant not found: %s", tenantID)
	}

	session := &Session{
		Capabilities: map[string]any{
			"urn:ietf:params:jmap:core": map[string]any{
				"maxSizeUpload":         104857600, // 100MB
				"maxConcurrentUpload":   4,
				"maxSizeRequest":        10485760, // 10MB
				"maxConcurrentRequests": 8,
				"maxCallsInRequest":     16,
				"maxObjectsInGet":       500,
				"maxObjectsInSet":       500,
				"collationAlgorithms":   []string{"i;ascii-casemap"},
			},
			CapabilityAS4: map[string]any{},
		},
		Accounts: map[string]Account{
			tenantID: {
				Name:       tenant.Name,
				IsPersonal: true,
				IsReadOnly: false,
				AccountCapabilities: map[string]any{
					CapabilityAS4: AS4Capability{
						MaxPayloadSize:    104857600, // 100MB
						SupportedServices: []string{"*"},
						SupportedActions:  []string{"*"},
					},
				},
			},
		},
		PrimaryAccounts: map[string]string{
			CapabilityAS4: tenantID,
		},
		Username:       username,
		APIUrl:         fmt.Sprintf("%s/tenant/%s/jmap", h.apiURL, tenantID),
		DownloadUrl:    fmt.Sprintf("%s/tenant/%s/jmap/download/{accountId}/{blobId}/{name}", h.apiURL, tenantID),
		UploadUrl:      fmt.Sprintf("%s/tenant/%s/jmap/upload/{accountId}", h.apiURL, tenantID),
		EventSourceUrl: fmt.Sprintf("%s/tenant/%s/jmap/eventsource?types={types}&closeafter={closeafter}&ping={ping}", h.apiURL, tenantID),
		State:          h.getSessionState(ctx, tenantID),
	}

	return session, nil
}

// ProcessRequest handles a JMAP API request
func (h *Handler) ProcessRequest(ctx context.Context, tenantID string, req *Request) (*Response, error) {
	// Validate capabilities
	hasAS4 := false
	for _, cap := range req.Using {
		if cap == CapabilityAS4 || cap == "urn:ietf:params:jmap:core" {
			hasAS4 = true
		}
	}
	if !hasAS4 {
		return nil, fmt.Errorf("missing required capability: %s", CapabilityAS4)
	}

	resp := &Response{
		MethodResponses: make([]MethodResponse, 0, len(req.MethodCalls)),
		CreatedIDs:      make(map[string]string),
		SessionState:    h.getSessionState(ctx, tenantID),
	}

	// Process each method call
	for _, call := range req.MethodCalls {
		result, err := h.processMethodCall(ctx, tenantID, call, req.CreatedIDs, resp.CreatedIDs)
		if err != nil {
			// Return error response for this method
			resp.MethodResponses = append(resp.MethodResponses, MethodResponse{
				Name: "error",
				Args: map[string]any{
					"type":        ErrorServerFail,
					"description": err.Error(),
				},
				CallID: call.CallID,
			})
			continue
		}
		resp.MethodResponses = append(resp.MethodResponses, *result)
	}

	return resp, nil
}

func (h *Handler) processMethodCall(
	ctx context.Context,
	tenantID string,
	call MethodCall,
	requestCreatedIDs map[string]string,
	responseCreatedIDs map[string]string,
) (*MethodResponse, error) {
	switch call.Name {
	case "AS4Message/get":
		return h.messageGet(ctx, tenantID, call)
	case "AS4Message/changes":
		return h.messageChanges(ctx, tenantID, call)
	case "AS4Message/query":
		return h.messageQuery(ctx, tenantID, call)
	case "AS4Message/queryChanges":
		return h.messageQueryChanges(ctx, tenantID, call)
	case "AS4Message/set":
		return h.messageSet(ctx, tenantID, call, requestCreatedIDs, responseCreatedIDs)
	case "AS4Mailbox/get":
		return h.mailboxGet(ctx, tenantID, call)
	case "AS4Mailbox/changes":
		return h.mailboxChanges(ctx, tenantID, call)
	case "AS4Participant/get":
		return h.participantGet(ctx, tenantID, call)
	case "AS4Participant/set":
		return h.participantSet(ctx, tenantID, call, responseCreatedIDs)
	default:
		return &MethodResponse{
			Name: "error",
			Args: map[string]any{
				"type":        "unknownMethod",
				"description": fmt.Sprintf("unknown method: %s", call.Name),
			},
			CallID: call.CallID,
		}, nil
	}
}

// messageGet implements AS4Message/get
func (h *Handler) messageGet(ctx context.Context, tenantID string, call MethodCall) (*MethodResponse, error) {
	// Parse request
	reqBytes, _ := json.Marshal(call.Args)
	var req GetRequest
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		return nil, fmt.Errorf("parsing request: %w", err)
	}

	// Validate accountId
	if req.AccountID != tenantID {
		return &MethodResponse{
			Name: "error",
			Args: map[string]any{
				"type":        ErrorForbidden,
				"description": "accountId does not match tenant",
			},
			CallID: call.CallID,
		}, nil
	}

	// Get messages
	var list []AS4Message
	var notFound []string

	if req.IDs == nil {
		// Get all messages (with reasonable limit)
		messages, err := h.store.ListMessages(ctx, tenantID, &storage.MessageFilter{Limit: 500})
		if err != nil {
			return nil, fmt.Errorf("listing messages: %w", err)
		}
		for _, msg := range messages {
			list = append(list, storageToJMAPMessage(msg))
		}
	} else {
		for _, id := range req.IDs {
			msg, err := h.store.GetMessage(ctx, tenantID, id)
			if err != nil {
				return nil, fmt.Errorf("getting message %s: %w", id, err)
			}
			if msg == nil {
				notFound = append(notFound, id)
			} else {
				list = append(list, storageToJMAPMessage(msg))
			}
		}
	}

	// Filter properties if specified
	listAny := make([]any, len(list))
	for i, msg := range list {
		if len(req.Properties) > 0 {
			listAny[i] = filterProperties(msg, req.Properties)
		} else {
			listAny[i] = msg
		}
	}

	// Get current state from storage
	state, err := h.store.GetState(ctx, tenantID, "AS4Message")
	if err != nil {
		return nil, fmt.Errorf("getting state: %w", err)
	}

	return &MethodResponse{
		Name: "AS4Message/get",
		Args: map[string]any{
			"accountId": tenantID,
			"state":     state,
			"list":      listAny,
			"notFound":  notFound,
		},
		CallID: call.CallID,
	}, nil
}

// messageChanges implements AS4Message/changes
func (h *Handler) messageChanges(ctx context.Context, tenantID string, call MethodCall) (*MethodResponse, error) {
	reqBytes, _ := json.Marshal(call.Args)
	var req ChangesRequest
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		return nil, fmt.Errorf("parsing request: %w", err)
	}

	if req.AccountID != tenantID {
		return &MethodResponse{
			Name: "error",
			Args: map[string]any{
				"type":        ErrorForbidden,
				"description": "accountId does not match tenant",
			},
			CallID: call.CallID,
		}, nil
	}

	maxChanges := req.MaxChanges
	if maxChanges <= 0 {
		maxChanges = 500
	}

	// Use storage layer's state tracking
	changes, err := h.store.GetChanges(ctx, tenantID, "AS4Message", req.SinceState, maxChanges)
	if err == storage.ErrStateNotFound {
		return &MethodResponse{
			Name: "error",
			Args: map[string]any{
				"type":        ErrorCannotCalculateChanges,
				"description": "invalid or expired state",
			},
			CallID: call.CallID,
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting changes: %w", err)
	}

	return &MethodResponse{
		Name: "AS4Message/changes",
		Args: map[string]any{
			"accountId":      tenantID,
			"oldState":       changes.OldState,
			"newState":       changes.NewState,
			"hasMoreChanges": changes.HasMoreChanges,
			"created":        changes.Created,
			"updated":        changes.Updated,
			"destroyed":      changes.Destroyed,
		},
		CallID: call.CallID,
	}, nil
}

// messageQuery implements AS4Message/query
func (h *Handler) messageQuery(ctx context.Context, tenantID string, call MethodCall) (*MethodResponse, error) {
	reqBytes, _ := json.Marshal(call.Args)
	var req QueryRequest
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		return nil, fmt.Errorf("parsing request: %w", err)
	}

	if req.AccountID != tenantID {
		return &MethodResponse{
			Name: "error",
			Args: map[string]any{
				"type":        ErrorForbidden,
				"description": "accountId does not match tenant",
			},
			CallID: call.CallID,
		}, nil
	}

	// Build storage filter
	filter := &storage.MessageFilter{
		Offset: req.Position,
		Limit:  req.Limit,
	}
	if filter.Limit == 0 {
		filter.Limit = 50
	}

	if req.Filter != nil {
		filter.MailboxID = req.Filter.MailboxID
		if req.Filter.Direction != "" {
			filter.Direction = storage.MessageDirection(req.Filter.Direction)
		}
		if req.Filter.Status != "" {
			filter.Status = storage.MessageStatus(req.Filter.Status)
		}
		filter.Service = req.Filter.Service
		filter.Action = req.Filter.Action
		filter.Since = req.Filter.ReceivedAfter
	}

	messages, err := h.store.ListMessages(ctx, tenantID, filter)
	if err != nil {
		return nil, fmt.Errorf("querying messages: %w", err)
	}

	ids := make([]string, len(messages))
	for i, msg := range messages {
		ids[i] = msg.ID
	}

	queryState, _ := h.store.GetState(ctx, tenantID, "AS4Message")
	resp := map[string]any{
		"accountId":           tenantID,
		"queryState":          queryState,
		"canCalculateChanges": true,
		"position":            req.Position,
		"ids":                 ids,
	}

	if req.CalculateTotal {
		total, err := h.store.CountMessages(ctx, tenantID, filter)
		if err != nil {
			return nil, fmt.Errorf("counting messages: %w", err)
		}
		resp["total"] = total
	}

	return &MethodResponse{
		Name:   "AS4Message/query",
		Args:   resp,
		CallID: call.CallID,
	}, nil
}

// messageQueryChanges implements AS4Message/queryChanges
// This method returns the changes to a query result since a given state
func (h *Handler) messageQueryChanges(ctx context.Context, tenantID string, call MethodCall) (*MethodResponse, error) {
	reqBytes, _ := json.Marshal(call.Args)
	var req QueryChangesRequest
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		return nil, fmt.Errorf("parsing request: %w", err)
	}

	if req.AccountID != tenantID {
		return &MethodResponse{
			Name: "error",
			Args: map[string]any{
				"type":        ErrorForbidden,
				"description": "accountId does not match tenant",
			},
			CallID: call.CallID,
		}, nil
	}

	// Get current query state
	currentState, err := h.store.GetState(ctx, tenantID, "AS4Message")
	if err != nil {
		return nil, fmt.Errorf("getting state: %w", err)
	}

	// Build storage filter (same as messageQuery)
	filter := &storage.MessageFilter{
		Limit: 1000, // Get all results for comparison
	}

	if req.Filter != nil {
		filter.MailboxID = req.Filter.MailboxID
		if req.Filter.Direction != "" {
			filter.Direction = storage.MessageDirection(req.Filter.Direction)
		}
		if req.Filter.Status != "" {
			filter.Status = storage.MessageStatus(req.Filter.Status)
		}
		filter.Service = req.Filter.Service
		filter.Action = req.Filter.Action
		filter.Since = req.Filter.ReceivedAfter
	}

	// Get changes since the given state
	maxChanges := req.MaxChanges
	if maxChanges == 0 {
		maxChanges = 500 // Default limit
	}
	changes, err := h.store.GetChanges(ctx, tenantID, "AS4Message", req.SinceQueryState, maxChanges)
	if err != nil {
		// State is too old or invalid - return cannotCalculateChanges
		return &MethodResponse{
			Name: "error",
			Args: map[string]any{
				"type":        "cannotCalculateChanges",
				"description": "sinceQueryState is invalid or too old",
			},
			CallID: call.CallID,
		}, nil
	}

	// Run current query to get current result set
	messages, err := h.store.ListMessages(ctx, tenantID, filter)
	if err != nil {
		return nil, fmt.Errorf("querying messages: %w", err)
	}

	// Build set of current IDs with their positions
	currentIDs := make(map[string]int)
	for i, msg := range messages {
		currentIDs[msg.ID] = i
	}

	// Calculate removed and added based on changes
	var removed []string
	var added []AddedItem

	// Check destroyed IDs - these are definitely removed
	for _, id := range changes.Destroyed {
		removed = append(removed, id)
	}

	// Check created IDs - add those that match current query
	for _, id := range changes.Created {
		if idx, exists := currentIDs[id]; exists {
			added = append(added, AddedItem{ID: id, Index: idx})
		}
	}

	// Check updated IDs - they might have moved in/out of the query
	for _, id := range changes.Updated {
		if idx, exists := currentIDs[id]; exists {
			// Still in query - might have changed position
			added = append(added, AddedItem{ID: id, Index: idx})
			removed = append(removed, id)
		} else {
			// No longer matches query
			removed = append(removed, id)
		}
	}

	// Apply maxChanges limit if specified
	if req.MaxChanges > 0 {
		totalChanges := len(removed) + len(added)
		if totalChanges > req.MaxChanges {
			// Too many changes - return cannotCalculateChanges
			return &MethodResponse{
				Name: "error",
				Args: map[string]any{
					"type":        "cannotCalculateChanges",
					"description": "too many changes to calculate",
				},
				CallID: call.CallID,
			}, nil
		}
	}

	// Handle upToId - only return changes up to specified ID
	if req.UpToID != "" {
		upToIdx := -1
		for _, item := range added {
			if item.ID == req.UpToID {
				upToIdx = item.Index
				break
			}
		}
		if upToIdx >= 0 {
			// Filter added items
			var filteredAdded []AddedItem
			for _, item := range added {
				if item.Index <= upToIdx {
					filteredAdded = append(filteredAdded, item)
				}
			}
			added = filteredAdded
		}
	}

	// Ensure non-nil slices for JSON
	if removed == nil {
		removed = []string{}
	}
	if added == nil {
		added = []AddedItem{}
	}

	resp := map[string]any{
		"accountId":     tenantID,
		"oldQueryState": req.SinceQueryState,
		"newQueryState": currentState,
		"removed":       removed,
		"added":         added,
	}

	if req.CalculateTotal {
		total, err := h.store.CountMessages(ctx, tenantID, filter)
		if err == nil {
			resp["total"] = total
		}
	}

	return &MethodResponse{
		Name:   "AS4Message/queryChanges",
		Args:   resp,
		CallID: call.CallID,
	}, nil
}

// messageSet implements AS4Message/set
func (h *Handler) messageSet(
	ctx context.Context,
	tenantID string,
	call MethodCall,
	requestCreatedIDs map[string]string,
	responseCreatedIDs map[string]string,
) (*MethodResponse, error) {
	reqBytes, _ := json.Marshal(call.Args)
	var req SetRequest
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		return nil, fmt.Errorf("parsing request: %w", err)
	}

	if req.AccountID != tenantID {
		return &MethodResponse{
			Name: "error",
			Args: map[string]any{
				"type":        ErrorForbidden,
				"description": "accountId does not match tenant",
			},
			CallID: call.CallID,
		}, nil
	}

	// Get current state before making changes
	oldState, _ := h.store.GetState(ctx, tenantID, "AS4Message")

	// Validate ifInState - if provided, must match current state
	if req.IfInState != "" && req.IfInState != oldState {
		return &MethodResponse{
			Name: "error",
			Args: map[string]any{
				"type":        "stateMismatch",
				"description": "server state does not match ifInState",
			},
			CallID: call.CallID,
		}, nil
	}

	created := make(map[string]AS4Message)
	updated := make(map[string]any)
	notCreated := make(map[string]SetError)
	notUpdated := make(map[string]SetError)

	// Process creates
	for clientID, create := range req.Create {
		msg, err := h.createMessage(ctx, tenantID, &create)
		if err != nil {
			notCreated[clientID] = SetError{
				Type:        ErrorInvalidArguments,
				Description: err.Error(),
			}
			continue
		}
		created[clientID] = *msg
		responseCreatedIDs[clientID] = msg.ID
	}

	// Process updates
	for id, update := range req.Update {
		// Resolve reference IDs
		resolvedID := resolveID(id, requestCreatedIDs, responseCreatedIDs)

		if err := h.updateMessage(ctx, tenantID, resolvedID, &update); err != nil {
			notUpdated[id] = SetError{
				Type:        ErrorInvalidArguments,
				Description: err.Error(),
			}
			continue
		}
		updated[id] = nil // null indicates success with no server-set changes
	}

	// Get new state after changes
	newState, _ := h.store.GetState(ctx, tenantID, "AS4Message")
	resp := map[string]any{
		"accountId": tenantID,
		"oldState":  oldState,
		"newState":  newState,
	}

	if len(created) > 0 {
		resp["created"] = created
	}
	if len(updated) > 0 {
		resp["updated"] = updated
	}
	if len(notCreated) > 0 {
		resp["notCreated"] = notCreated
	}
	if len(notUpdated) > 0 {
		resp["notUpdated"] = notUpdated
	}

	return &MethodResponse{
		Name:   "AS4Message/set",
		Args:   resp,
		CallID: call.CallID,
	}, nil
}

func (h *Handler) createMessage(ctx context.Context, tenantID string, create *AS4MessageCreate) (*AS4Message, error) {
	// Validate required fields
	if create.MailboxID == "" {
		return nil, fmt.Errorf("mailboxId is required")
	}
	if create.ToParty.Value == "" {
		return nil, fmt.Errorf("toParty is required")
	}
	if create.Service == "" {
		return nil, fmt.Errorf("service is required")
	}
	if create.Action == "" {
		return nil, fmt.Errorf("action is required")
	}
	if len(create.Payloads) == 0 {
		return nil, fmt.Errorf("at least one payload is required")
	}

	// Get mailbox to determine sender
	mailbox, err := h.store.GetMailbox(ctx, tenantID, create.MailboxID)
	if err != nil {
		return nil, fmt.Errorf("getting mailbox: %w", err)
	}
	if mailbox == nil {
		return nil, fmt.Errorf("mailbox not found")
	}

	// Get participant for from party
	participant, err := h.store.GetParticipant(ctx, tenantID, mailbox.ParticipantID)
	if err != nil {
		return nil, fmt.Errorf("getting participant: %w", err)
	}
	if participant == nil {
		return nil, fmt.Errorf("participant not found")
	}

	// Generate IDs
	msgID := uuid.New().String()
	as4MsgID := fmt.Sprintf("%s@%s", uuid.New().String(), tenantID)
	convID := create.ConversationID
	if convID == "" {
		convID = uuid.New().String()
	}

	// Build payload references (payloads should be uploaded separately)
	var payloads []storage.PayloadRef
	for i, ref := range create.Payloads {
		payloads = append(payloads, storage.PayloadRef{
			ID:        ref.BlobID,
			ContentID: ref.ContentID,
			MimeType:  ref.MimeType,
		})
		if payloads[i].ContentID == "" {
			payloads[i].ContentID = fmt.Sprintf("payload-%d", i)
		}
	}

	now := time.Now()
	msg := &storage.Message{
		ID:             msgID,
		TenantID:       tenantID,
		MailboxID:      create.MailboxID,
		Direction:      storage.DirectionOutbound,
		Status:         storage.StatusPending,
		AS4MessageID:   as4MsgID,
		ConversationID: convID,
		RefToMessageID: create.RefToMessageID,
		FromParty:      storage.PartyID{Type: participant.PartyID.Type, Value: participant.PartyID.Value},
		ToParty:        storage.PartyID{Type: create.ToParty.Type, Value: create.ToParty.Value},
		Service:        create.Service,
		Action:         create.Action,
		Payloads:       payloads,
		ReceivedAt:     now,
		SignatureValid: true, // Will be signed on send
	}

	if err := h.store.CreateMessage(ctx, msg); err != nil {
		return nil, fmt.Errorf("creating message: %w", err)
	}

	return &AS4Message{
		ID:             msg.ID,
		MailboxID:      msg.MailboxID,
		Direction:      string(msg.Direction),
		Status:         string(msg.Status),
		AS4MessageID:   msg.AS4MessageID,
		ConversationID: msg.ConversationID,
		FromParty:      Party{Type: msg.FromParty.Type, Value: msg.FromParty.Value},
		ToParty:        Party{Type: msg.ToParty.Type, Value: msg.ToParty.Value},
		Service:        msg.Service,
		Action:         msg.Action,
		ReceivedAt:     msg.ReceivedAt,
		SignatureValid: msg.SignatureValid,
	}, nil
}

func (h *Handler) updateMessage(ctx context.Context, tenantID, msgID string, update *AS4MessageUpdate) error {
	msg, err := h.store.GetMessage(ctx, tenantID, msgID)
	if err != nil {
		return fmt.Errorf("getting message: %w", err)
	}
	if msg == nil {
		return fmt.Errorf("message not found")
	}

	// Only allow marking as read
	if update.Status != "" {
		if update.Status == "read" && msg.Direction == storage.DirectionInbound {
			now := time.Now()
			msg.Status = storage.StatusRead
			msg.ReadAt = &now
		} else {
			return fmt.Errorf("invalid status transition")
		}
	}

	return h.store.UpdateMessage(ctx, msg)
}

// mailboxGet implements AS4Mailbox/get
func (h *Handler) mailboxGet(ctx context.Context, tenantID string, call MethodCall) (*MethodResponse, error) {
	reqBytes, _ := json.Marshal(call.Args)
	var req GetRequest
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		return nil, fmt.Errorf("parsing request: %w", err)
	}

	if req.AccountID != tenantID {
		return &MethodResponse{
			Name: "error",
			Args: map[string]any{
				"type":        ErrorForbidden,
				"description": "accountId does not match tenant",
			},
			CallID: call.CallID,
		}, nil
	}

	var list []AS4Mailbox
	var notFound []string

	if req.IDs == nil {
		mailboxes, err := h.store.ListMailboxes(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("listing mailboxes: %w", err)
		}
		for _, mb := range mailboxes {
			list = append(list, storageToJMAPMailbox(mb))
		}
	} else {
		for _, id := range req.IDs {
			mb, err := h.store.GetMailbox(ctx, tenantID, id)
			if err != nil {
				return nil, fmt.Errorf("getting mailbox %s: %w", id, err)
			}
			if mb == nil {
				notFound = append(notFound, id)
			} else {
				list = append(list, storageToJMAPMailbox(mb))
			}
		}
	}

	listAny := make([]any, len(list))
	for i, mb := range list {
		listAny[i] = mb
	}

	// Get current state from storage
	state, err := h.store.GetState(ctx, tenantID, "AS4Mailbox")
	if err != nil {
		return nil, fmt.Errorf("getting state: %w", err)
	}

	return &MethodResponse{
		Name: "AS4Mailbox/get",
		Args: map[string]any{
			"accountId": tenantID,
			"state":     state,
			"list":      listAny,
			"notFound":  notFound,
		},
		CallID: call.CallID,
	}, nil
}

// mailboxChanges implements AS4Mailbox/changes
func (h *Handler) mailboxChanges(ctx context.Context, tenantID string, call MethodCall) (*MethodResponse, error) {
	reqBytes, _ := json.Marshal(call.Args)
	var req ChangesRequest
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		return nil, fmt.Errorf("parsing request: %w", err)
	}

	if req.AccountID != tenantID {
		return &MethodResponse{
			Name: "error",
			Args: map[string]any{
				"type":        ErrorForbidden,
				"description": "accountId does not match tenant",
			},
			CallID: call.CallID,
		}, nil
	}

	maxChanges := req.MaxChanges
	if maxChanges <= 0 {
		maxChanges = 500
	}

	changes, err := h.store.GetChanges(ctx, tenantID, "AS4Mailbox", req.SinceState, maxChanges)
	if err == storage.ErrStateNotFound {
		return &MethodResponse{
			Name: "error",
			Args: map[string]any{
				"type":        ErrorCannotCalculateChanges,
				"description": "invalid or expired state",
			},
			CallID: call.CallID,
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting changes: %w", err)
	}

	return &MethodResponse{
		Name: "AS4Mailbox/changes",
		Args: map[string]any{
			"accountId":      tenantID,
			"oldState":       changes.OldState,
			"newState":       changes.NewState,
			"hasMoreChanges": changes.HasMoreChanges,
			"created":        changes.Created,
			"updated":        changes.Updated,
			"destroyed":      changes.Destroyed,
		},
		CallID: call.CallID,
	}, nil
}

// participantGet implements AS4Participant/get
func (h *Handler) participantGet(ctx context.Context, tenantID string, call MethodCall) (*MethodResponse, error) {
	reqBytes, _ := json.Marshal(call.Args)
	var req GetRequest
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		return nil, fmt.Errorf("parsing request: %w", err)
	}

	if req.AccountID != tenantID {
		return &MethodResponse{
			Name: "error",
			Args: map[string]any{
				"type":        ErrorForbidden,
				"description": "accountId does not match tenant",
			},
			CallID: call.CallID,
		}, nil
	}

	var list []AS4Participant
	var notFound []string

	if req.IDs == nil {
		participants, err := h.store.ListParticipants(ctx, tenantID, nil)
		if err != nil {
			return nil, fmt.Errorf("listing participants: %w", err)
		}
		for _, p := range participants {
			list = append(list, storageToJMAPParticipant(p))
		}
	} else {
		for _, id := range req.IDs {
			p, err := h.store.GetParticipant(ctx, tenantID, id)
			if err != nil {
				return nil, fmt.Errorf("getting participant %s: %w", id, err)
			}
			if p == nil {
				notFound = append(notFound, id)
			} else {
				list = append(list, storageToJMAPParticipant(p))
			}
		}
	}

	listAny := make([]any, len(list))
	for i, p := range list {
		listAny[i] = p
	}

	// Get current state from storage
	state, err := h.store.GetState(ctx, tenantID, "AS4Participant")
	if err != nil {
		return nil, fmt.Errorf("getting state: %w", err)
	}

	return &MethodResponse{
		Name: "AS4Participant/get",
		Args: map[string]any{
			"accountId": tenantID,
			"state":     state,
			"list":      listAny,
			"notFound":  notFound,
		},
		CallID: call.CallID,
	}, nil
}

// participantSet implements AS4Participant/set
func (h *Handler) participantSet(
	ctx context.Context,
	tenantID string,
	call MethodCall,
	responseCreatedIDs map[string]string,
) (*MethodResponse, error) {
	reqBytes, _ := json.Marshal(call.Args)
	var req ParticipantSetRequest
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		return nil, fmt.Errorf("parsing request: %w", err)
	}

	if req.AccountID != tenantID {
		return &MethodResponse{
			Name: "error",
			Args: map[string]any{
				"type":        ErrorForbidden,
				"description": "accountId does not match tenant",
			},
			CallID: call.CallID,
		}, nil
	}

	// Get current state before making changes
	oldState, _ := h.store.GetState(ctx, tenantID, "AS4Participant")

	// Validate ifInState - if provided, must match current state
	if req.IfInState != "" && req.IfInState != oldState {
		return &MethodResponse{
			Name: "error",
			Args: map[string]any{
				"type":        "stateMismatch",
				"description": "server state does not match ifInState",
			},
			CallID: call.CallID,
		}, nil
	}

	created := make(map[string]AS4Participant)
	updated := make(map[string]any)
	destroyed := make([]string, 0)
	notCreated := make(map[string]SetError)
	notUpdated := make(map[string]SetError)
	notDestroyed := make(map[string]SetError)

	// Process creates
	for clientID, create := range req.Create {
		participant, err := h.createParticipant(ctx, tenantID, &create)
		if err != nil {
			notCreated[clientID] = SetError{
				Type:        ErrorInvalidArguments,
				Description: err.Error(),
			}
			continue
		}
		created[clientID] = *participant
		responseCreatedIDs[clientID] = participant.ID
	}

	// Process updates
	for id, update := range req.Update {
		// Resolve reference IDs
		resolvedID := resolveID(id, nil, responseCreatedIDs)

		if err := h.updateParticipant(ctx, tenantID, resolvedID, &update); err != nil {
			notUpdated[id] = SetError{
				Type:        ErrorInvalidArguments,
				Description: err.Error(),
			}
			continue
		}
		updated[id] = nil // null indicates success with no server-set changes
	}

	// Process destroys
	for _, id := range req.Destroy {
		resolvedID := resolveID(id, nil, responseCreatedIDs)
		if err := h.destroyParticipant(ctx, tenantID, resolvedID); err != nil {
			notDestroyed[id] = SetError{
				Type:        ErrorNotFound,
				Description: err.Error(),
			}
			continue
		}
		destroyed = append(destroyed, id)
	}

	// Get new state after changes
	newState, _ := h.store.GetState(ctx, tenantID, "AS4Participant")

	resp := map[string]any{
		"accountId": tenantID,
		"oldState":  oldState,
		"newState":  newState,
	}

	if len(created) > 0 {
		resp["created"] = created
	}
	if len(updated) > 0 {
		resp["updated"] = updated
	}
	if len(destroyed) > 0 {
		resp["destroyed"] = destroyed
	}
	if len(notCreated) > 0 {
		resp["notCreated"] = notCreated
	}
	if len(notUpdated) > 0 {
		resp["notUpdated"] = notUpdated
	}
	if len(notDestroyed) > 0 {
		resp["notDestroyed"] = notDestroyed
	}

	return &MethodResponse{
		Name:   "AS4Participant/set",
		Args:   resp,
		CallID: call.CallID,
	}, nil
}

func (h *Handler) createParticipant(ctx context.Context, tenantID string, create *AS4ParticipantCreate) (*AS4Participant, error) {
	// Validate required fields
	if create.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if create.PartyID.Value == "" {
		return nil, fmt.Errorf("partyId.value is required")
	}

	// Check if participant with same party ID already exists
	existing, err := h.store.GetParticipantByPartyID(ctx, tenantID, storage.PartyID{
		Type:  create.PartyID.Type,
		Value: create.PartyID.Value,
	})
	if err != nil {
		return nil, fmt.Errorf("checking existing participant: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("participant with party ID %s already exists", create.PartyID.Value)
	}

	now := time.Now()
	status := create.Status
	if status == "" {
		status = "active"
	}

	participant := &storage.Participant{
		ID:       uuid.New().String(),
		TenantID: tenantID,
		Name:     create.Name,
		PartyID: storage.PartyID{
			Type:  create.PartyID.Type,
			Value: create.PartyID.Value,
		},
		Status:    status,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := h.store.CreateParticipant(ctx, participant); err != nil {
		return nil, fmt.Errorf("creating participant: %w", err)
	}

	// Create mailbox for participant
	mailbox := &storage.Mailbox{
		ID:            uuid.New().String(),
		TenantID:      tenantID,
		ParticipantID: participant.ID,
		Name:          create.Name + " Mailbox",
		CreatedAt:     now,
	}
	if err := h.store.CreateMailbox(ctx, mailbox); err != nil {
		h.logger.Warn("failed to create mailbox for participant", "error", err)
	} else {
		participant.MailboxID = mailbox.ID
		h.store.UpdateParticipant(ctx, participant)
	}

	return &AS4Participant{
		ID:        participant.ID,
		Name:      participant.Name,
		PartyID:   Party{Type: participant.PartyID.Type, Value: participant.PartyID.Value},
		MailboxID: participant.MailboxID,
		Status:    participant.Status,
		CreatedAt: participant.CreatedAt,
	}, nil
}

func (h *Handler) updateParticipant(ctx context.Context, tenantID, id string, update *AS4ParticipantUpdate) error {
	participant, err := h.store.GetParticipant(ctx, tenantID, id)
	if err != nil {
		return fmt.Errorf("getting participant: %w", err)
	}
	if participant == nil {
		return fmt.Errorf("participant not found")
	}

	// Apply updates
	if update.Name != nil {
		participant.Name = *update.Name
	}
	if update.Status != nil {
		// Validate status
		switch *update.Status {
		case "active", "suspended", "pending":
			participant.Status = *update.Status
		default:
			return fmt.Errorf("invalid status: %s", *update.Status)
		}
	}

	participant.UpdatedAt = time.Now()

	if err := h.store.UpdateParticipant(ctx, participant); err != nil {
		return fmt.Errorf("updating participant: %w", err)
	}

	return nil
}

func (h *Handler) destroyParticipant(ctx context.Context, tenantID, id string) error {
	participant, err := h.store.GetParticipant(ctx, tenantID, id)
	if err != nil {
		return fmt.Errorf("getting participant: %w", err)
	}
	if participant == nil {
		return fmt.Errorf("participant not found")
	}

	// Check if there are any messages for this participant
	filter := &storage.MessageFilter{MailboxID: participant.MailboxID, Limit: 1}
	messages, err := h.store.ListMessages(ctx, tenantID, filter)
	if err != nil {
		return fmt.Errorf("checking messages: %w", err)
	}
	if len(messages) > 0 {
		return fmt.Errorf("cannot delete participant with existing messages")
	}

	if err := h.store.DeleteParticipant(ctx, tenantID, id); err != nil {
		return fmt.Errorf("deleting participant: %w", err)
	}

	return nil
}

// Helper functions

func storageToJMAPMessage(msg *storage.Message) AS4Message {
	jmsg := AS4Message{
		ID:             msg.ID,
		MailboxID:      msg.MailboxID,
		Direction:      string(msg.Direction),
		Status:         string(msg.Status),
		AS4MessageID:   msg.AS4MessageID,
		ConversationID: msg.ConversationID,
		FromParty:      Party{Type: msg.FromParty.Type, Value: msg.FromParty.Value},
		ToParty:        Party{Type: msg.ToParty.Type, Value: msg.ToParty.Value},
		Service:        msg.Service,
		Action:         msg.Action,
		ReceivedAt:     msg.ReceivedAt,
		ProcessedAt:    msg.ProcessedAt,
		DeliveredAt:    msg.DeliveredAt,
		ReadAt:         msg.ReadAt,
		SignatureValid: msg.SignatureValid,
		RetryCount:     msg.RetryCount,
	}

	if msg.RefToMessageID != "" {
		jmsg.RefToMessageID = &msg.RefToMessageID
	}
	if msg.ReceiptID != "" {
		jmsg.ReceiptID = &msg.ReceiptID
	}
	if msg.LastError != "" {
		jmsg.LastError = &msg.LastError
	}

	for _, p := range msg.Payloads {
		jmsg.Payloads = append(jmsg.Payloads, AS4Payload{
			ID:         p.ID,
			ContentID:  p.ContentID,
			MimeType:   p.MimeType,
			Size:       p.Size,
			Compressed: p.Compressed,
			Checksum:   p.Checksum,
		})
	}

	return jmsg
}

func storageToJMAPMailbox(mb *storage.Mailbox) AS4Mailbox {
	return AS4Mailbox{
		ID:            mb.ID,
		ParticipantID: mb.ParticipantID,
		Name:          mb.Name,
		TotalMessages: mb.TotalMessages,
		UnreadCount:   mb.UnreadCount,
		Role:          "inbox", // TODO: determine from mailbox type
	}
}

func storageToJMAPParticipant(p *storage.Participant) AS4Participant {
	return AS4Participant{
		ID:        p.ID,
		Name:      p.Name,
		PartyID:   Party{Type: p.PartyID.Type, Value: p.PartyID.Value},
		MailboxID: p.MailboxID,
		Status:    p.Status,
		CreatedAt: p.CreatedAt,
	}
}

func filterProperties(msg AS4Message, props []string) map[string]any {
	result := make(map[string]any)
	result["id"] = msg.ID // id is always included

	for _, prop := range props {
		switch prop {
		case "mailboxId":
			result["mailboxId"] = msg.MailboxID
		case "direction":
			result["direction"] = msg.Direction
		case "status":
			result["status"] = msg.Status
		case "as4MessageId":
			result["as4MessageId"] = msg.AS4MessageID
		case "conversationId":
			result["conversationId"] = msg.ConversationID
		case "refToMessageId":
			result["refToMessageId"] = msg.RefToMessageID
		case "fromParty":
			result["fromParty"] = msg.FromParty
		case "toParty":
			result["toParty"] = msg.ToParty
		case "service":
			result["service"] = msg.Service
		case "action":
			result["action"] = msg.Action
		case "payloads":
			result["payloads"] = msg.Payloads
		case "receivedAt":
			result["receivedAt"] = msg.ReceivedAt
		case "processedAt":
			result["processedAt"] = msg.ProcessedAt
		case "deliveredAt":
			result["deliveredAt"] = msg.DeliveredAt
		case "readAt":
			result["readAt"] = msg.ReadAt
		case "signatureValid":
			result["signatureValid"] = msg.SignatureValid
		case "receiptId":
			result["receiptId"] = msg.ReceiptID
		case "retryCount":
			result["retryCount"] = msg.RetryCount
		case "lastError":
			result["lastError"] = msg.LastError
		}
	}
	return result
}

func resolveID(id string, requestIDs, responseIDs map[string]string) string {
	// Check if this is a reference to a created ID
	if len(id) > 0 && id[0] == '#' {
		ref := id[1:]
		if resolved, ok := responseIDs[ref]; ok {
			return resolved
		}
		if resolved, ok := requestIDs[ref]; ok {
			return resolved
		}
	}
	return id
}
