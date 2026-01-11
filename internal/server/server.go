// Package server provides the HTTP server for the AS4 multi-tenant service.
//
// The server exposes multiple API surfaces:
//
// # AS4 Endpoint
//
// POST /as4 - Receives inbound AS4 messages over HTTP. This endpoint
// handles ebMS3/AS4 SOAP messages with WS-Security signatures and
// optional encryption. Authentication is via AS4 message-level security.
//
// # REST API (requires JWT authentication)
//
//   - GET    /api/tenants/{id}              - Get tenant details
//   - GET    /api/tenants/{id}/participants - List trading partners
//   - POST   /api/tenants/{id}/participants - Create trading partner
//   - GET    /api/tenants/{id}/messages     - List messages
//   - POST   /api/tenants/{id}/messages     - Send a message
//   - GET    /api/tenants/{id}/messages/{id} - Get message details
//
// # JMAP API (requires JWT authentication)
//
//   - GET  /.well-known/jmap - JMAP session/capability discovery
//   - POST /jmap             - JMAP method invocations
//   - GET  /jmap/download/{accountId}/{blobId}/{name} - Download blobs
//   - POST /jmap/upload/{accountId} - Upload blobs
//
// # Health & Metrics
//
//   - GET /health  - Liveness probe
//   - GET /metrics - Prometheus metrics (if enabled)
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sirosfoundation/go-as4/internal/as4"
	"github.com/sirosfoundation/go-as4/internal/auth"
	"github.com/sirosfoundation/go-as4/internal/config"
	"github.com/sirosfoundation/go-as4/internal/jmap"
	"github.com/sirosfoundation/go-as4/internal/keystore"
	"github.com/sirosfoundation/go-as4/internal/storage"
)

// Server is the AS4 multi-tenant HTTP server
type Server struct {
	config        *config.Config
	logger        *slog.Logger
	httpSrv       *http.Server
	keystore      keystore.SignerProvider
	store         storage.Store
	as4Handler    *as4.Handler
	jmapHandler   *jmap.Handler
	authenticator *auth.Authenticator
}

// New creates a new AS4 server
func New(cfg *config.Config, store storage.Store, logger *slog.Logger) (*Server, error) {
	s := &Server{
		config: cfg,
		logger: logger,
		store:  store,
	}

	// Initialize keystore provider
	// For PRF mode, use the store's EncryptedKeyStore interface
	var encryptedKeyStore keystore.EncryptedKeyStore
	if cfg.Signing.Mode == "prf" {
		encryptedKeyStore = store
	}

	ks, err := keystore.NewProvider(&cfg.Signing, encryptedKeyStore)
	if err != nil {
		return nil, fmt.Errorf("initializing keystore: %w", err)
	}
	s.keystore = ks

	// Initialize AS4 handler
	s.as4Handler = as4.NewHandler(&as4.Config{
		MessageStore:   store,
		SignerProvider: ks,
		Logger:         logger,
	})

	// Initialize JMAP handler
	apiURL := fmt.Sprintf("http://localhost:%d", cfg.Server.Port)
	if cfg.Server.TLS.Enabled {
		apiURL = fmt.Sprintf("https://localhost:%d", cfg.Server.Port)
	}
	s.jmapHandler = jmap.NewHandler(store, apiURL, logger)

	// Initialize authenticator for OAuth2/JWT
	s.authenticator = auth.NewAuthenticator(&cfg.OAuth2, logger)
	if s.authenticator.IsEnabled() {
		logger.Info("OAuth2 authentication enabled", "issuer", cfg.OAuth2.Issuer)
	} else {
		logger.Warn("OAuth2 authentication disabled - JMAP endpoints will accept unauthenticated requests")
	}

	// Set up HTTP routes
	mux := http.NewServeMux()
	s.registerRoutes(mux)

	s.httpSrv = &http.Server{
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return s, nil
}

// Start begins listening on the specified address
func (s *Server) Start(addr string) error {
	s.httpSrv.Addr = addr
	s.logger.Info("starting server", "addr", addr, "tls", s.config.Server.TLS.Enabled)
	if s.config.Server.TLS.Enabled {
		return s.httpSrv.ListenAndServeTLS(
			s.config.Server.TLS.CertFile,
			s.config.Server.TLS.KeyFile,
		)
	}
	return s.httpSrv.ListenAndServe()
}

// Shutdown gracefully stops the server
func (s *Server) Shutdown(ctx context.Context) error {
	if err := s.httpSrv.Shutdown(ctx); err != nil {
		return err
	}
	if s.keystore != nil {
		if err := s.keystore.Close(); err != nil {
			return err
		}
	}
	if s.store != nil {
		return s.store.Close(ctx)
	}
	return nil
}

func (s *Server) registerRoutes(mux *http.ServeMux) {
	basePath := strings.TrimSuffix(s.config.Server.BasePath, "/")
	if basePath == "" {
		basePath = "/tenant"
	}

	// Health check (no auth required)
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /ready", s.handleReady)

	// AS4 endpoints (tenant-scoped, no OAuth - uses AS4 security)
	mux.HandleFunc("POST "+basePath+"/{tenantID}/as4", s.withTenant(s.handleAS4Inbound))

	// REST API for mailbox access (requires auth)
	mux.HandleFunc("GET "+basePath+"/{tenantID}/api/mailboxes", s.withAuth(s.withTenant(s.handleListMailboxes)))
	mux.HandleFunc("GET "+basePath+"/{tenantID}/api/mailboxes/{mailboxID}", s.withAuth(s.withTenant(s.handleGetMailbox)))

	mux.HandleFunc("GET "+basePath+"/{tenantID}/api/messages", s.withAuth(s.withTenant(s.handleListMessages)))
	mux.HandleFunc("POST "+basePath+"/{tenantID}/api/messages", s.withAuth(s.withTenant(s.handleSendMessage)))
	mux.HandleFunc("GET "+basePath+"/{tenantID}/api/messages/{messageID}", s.withAuth(s.withTenant(s.handleGetMessage)))
	mux.HandleFunc("GET "+basePath+"/{tenantID}/api/messages/{messageID}/payloads/{payloadID}", s.withAuth(s.withTenant(s.handleGetPayload)))

	// Tenant management API (admin-only)
	mux.HandleFunc("GET /admin/tenants", s.withAdmin(s.handleListTenants))
	mux.HandleFunc("POST /admin/tenants", s.withAdmin(s.handleCreateTenant))
	mux.HandleFunc("GET /admin/tenants/{tenantID}", s.withAdmin(s.handleGetTenant))
	mux.HandleFunc("PUT /admin/tenants/{tenantID}", s.withAdmin(s.handleUpdateTenant))
	mux.HandleFunc("DELETE /admin/tenants/{tenantID}", s.withAdmin(s.handleDeleteTenant))

	// Participant management (requires auth)
	mux.HandleFunc("GET "+basePath+"/{tenantID}/api/participants", s.withAuth(s.withTenant(s.handleListParticipants)))
	mux.HandleFunc("POST "+basePath+"/{tenantID}/api/participants", s.withAuth(s.withTenant(s.handleCreateParticipant)))
	mux.HandleFunc("GET "+basePath+"/{tenantID}/api/participants/{participantID}", s.withAuth(s.withTenant(s.handleGetParticipant)))

	// Key management (requires auth)
	mux.HandleFunc("GET "+basePath+"/{tenantID}/api/keys", s.withAuth(s.withTenant(s.handleListKeys)))
	mux.HandleFunc("GET "+basePath+"/{tenantID}/api/keys/{keyID}/certificate", s.withAuth(s.withTenant(s.handleGetCertificate)))

	// JMAP API (requires auth)
	mux.HandleFunc("GET "+basePath+"/{tenantID}/jmap/session", s.withAuth(s.withTenant(s.handleJMAPSession)))
	mux.HandleFunc("POST "+basePath+"/{tenantID}/jmap", s.withAuth(s.withTenant(s.handleJMAPRequest)))
	mux.HandleFunc("GET "+basePath+"/{tenantID}/jmap/download/{blobID}/{name}", s.withAuth(s.withTenant(s.handleJMAPDownload)))
	mux.HandleFunc("POST "+basePath+"/{tenantID}/jmap/upload", s.withAuth(s.withTenant(s.handleJMAPUpload)))
	mux.HandleFunc("GET "+basePath+"/{tenantID}/jmap/eventsource", s.withAuth(s.withTenant(s.handleJMAPEventSource)))
}

// Middleware

// withAuth validates OAuth2/JWT tokens for authenticated endpoints
func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip auth if not configured (development mode)
		if !s.authenticator.IsEnabled() {
			next(w, r)
			return
		}

		claims, err := s.authenticator.ValidateRequest(r)
		if err != nil {
			s.logger.Debug("authentication failed", "error", err, "path", r.URL.Path)
			switch err {
			case auth.ErrNoToken:
				w.Header().Set("WWW-Authenticate", `Bearer realm="AS4 API"`)
				s.jsonError(w, "authentication required", http.StatusUnauthorized)
			case auth.ErrTokenExpired:
				s.jsonError(w, "token expired", http.StatusUnauthorized)
			case auth.ErrInvalidAudience, auth.ErrInvalidIssuer:
				s.jsonError(w, "invalid token", http.StatusForbidden)
			default:
				s.jsonError(w, "authentication failed", http.StatusUnauthorized)
			}
			return
		}

		// Check tenant access if tenant ID is in the path
		tenantID := r.PathValue("tenantID")
		if tenantID != "" && !claims.HasTenant(tenantID) {
			s.logger.Warn("tenant access denied",
				"user", claims.Subject,
				"tenant", tenantID,
				"allowed_tenants", claims.Tenants,
			)
			s.jsonError(w, "access denied for this tenant", http.StatusForbidden)
			return
		}

		// Add claims to context
		ctx := auth.ContextWithClaims(r.Context(), claims)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) withTenant(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.PathValue("tenantID")
		if tenantID == "" {
			s.jsonError(w, "tenant ID required", http.StatusBadRequest)
			return
		}

		// Validate tenant exists and is active
		tenant, err := s.store.GetTenant(r.Context(), tenantID)
		if err != nil {
			s.logger.Error("error looking up tenant", "tenant_id", tenantID, "error", err)
			s.jsonError(w, "internal error", http.StatusInternalServerError)
			return
		}
		if tenant == nil {
			s.jsonError(w, "tenant not found", http.StatusNotFound)
			return
		}
		if tenant.Status != storage.TenantStatusActive {
			s.jsonError(w, "tenant is not active", http.StatusForbidden)
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, tenantContextKey, tenant)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) withAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check for admin API key in header
		apiKey := r.Header.Get("X-Admin-Key")
		if apiKey == "" || apiKey != s.config.Server.AdminKey {
			s.jsonError(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

type contextKey string

const tenantContextKey contextKey = "tenant"

// TenantFromContext extracts the tenant from the request context
func TenantFromContext(ctx context.Context) *storage.Tenant {
	if v := ctx.Value(tenantContextKey); v != nil {
		return v.(*storage.Tenant)
	}
	return nil
}

// Health handlers

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, map[string]string{"status": "ok"}, http.StatusOK)
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		s.jsonError(w, "database not ready", http.StatusServiceUnavailable)
		return
	}
	s.jsonResponse(w, map[string]string{"status": "ready"}, http.StatusOK)
}

// AS4 handlers

func (s *Server) handleAS4Inbound(w http.ResponseWriter, r *http.Request) {
	tenant := TenantFromContext(r.Context())

	s.logger.Info("received AS4 message",
		"tenant", tenant.ID,
		"content-type", r.Header.Get("Content-Type"),
		"content-length", r.ContentLength,
	)

	result, err := s.as4Handler.HandleInbound(r.Context(), tenant.ID, r)
	if err != nil {
		s.logger.Error("AS4 processing failed", "tenant", tenant.ID, "error", err)

		// Generate AS4 error response
		errorMsg, _ := s.as4Handler.GenerateError(r.Context(), &as4.AS4Error{
			Code:        "EBMS:0004",
			Severity:    "failure",
			ShortDesc:   "ProcessingError",
			Description: err.Error(),
		})

		w.Header().Set("Content-Type", "application/soap+xml")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(errorMsg)
		return
	}

	s.logger.Info("AS4 message processed",
		"tenant", tenant.ID,
		"message_id", result.AS4MessageID,
		"payloads", result.Payloads,
	)

	// Generate receipt (unsigned for now)
	receipt, err := s.as4Handler.GenerateReceipt(r.Context(), tenant.ID, result.AS4MessageID, nil)
	if err != nil {
		s.logger.Error("receipt generation failed", "error", err)
		http.Error(w, "receipt generation failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/soap+xml")
	w.WriteHeader(http.StatusOK)
	w.Write(receipt)
}

// Mailbox handlers

func (s *Server) handleListMailboxes(w http.ResponseWriter, r *http.Request) {
	tenant := TenantFromContext(r.Context())

	mailboxes, err := s.store.ListMailboxes(r.Context(), tenant.ID)
	if err != nil {
		s.logger.Error("failed to list mailboxes", "error", err)
		s.jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, map[string]interface{}{
		"mailboxes": mailboxes,
		"total":     len(mailboxes),
	}, http.StatusOK)
}

func (s *Server) handleGetMailbox(w http.ResponseWriter, r *http.Request) {
	tenant := TenantFromContext(r.Context())
	mailboxID := r.PathValue("mailboxID")

	mailbox, err := s.store.GetMailbox(r.Context(), tenant.ID, mailboxID)
	if err != nil {
		s.logger.Error("failed to get mailbox", "error", err)
		s.jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if mailbox == nil {
		s.jsonError(w, "mailbox not found", http.StatusNotFound)
		return
	}

	s.jsonResponse(w, mailbox, http.StatusOK)
}

// Message handlers

func (s *Server) handleListMessages(w http.ResponseWriter, r *http.Request) {
	tenant := TenantFromContext(r.Context())

	// Parse query parameters
	filter := &storage.MessageFilter{}
	if mailboxID := r.URL.Query().Get("mailboxId"); mailboxID != "" {
		filter.MailboxID = mailboxID
	}
	if direction := r.URL.Query().Get("direction"); direction != "" {
		filter.Direction = storage.MessageDirection(direction)
	}
	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = storage.MessageStatus(status)
	}
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil {
			filter.Limit = limit
		}
	}
	if filter.Limit == 0 || filter.Limit > 100 {
		filter.Limit = 50 // Default limit
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil {
			filter.Offset = offset
		}
	}

	messages, err := s.store.ListMessages(r.Context(), tenant.ID, filter)
	if err != nil {
		s.logger.Error("failed to list messages", "error", err)
		s.jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	total, _ := s.store.CountMessages(r.Context(), tenant.ID, filter)

	s.jsonResponse(w, map[string]interface{}{
		"messages": messages,
		"total":    total,
		"limit":    filter.Limit,
		"offset":   filter.Offset,
	}, http.StatusOK)
}

func (s *Server) handleGetMessage(w http.ResponseWriter, r *http.Request) {
	tenant := TenantFromContext(r.Context())
	messageID := r.PathValue("messageID")

	message, err := s.store.GetMessage(r.Context(), tenant.ID, messageID)
	if err != nil {
		s.logger.Error("failed to get message", "error", err)
		s.jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if message == nil {
		s.jsonError(w, "message not found", http.StatusNotFound)
		return
	}

	s.jsonResponse(w, message, http.StatusOK)
}

func (s *Server) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	tenant := TenantFromContext(r.Context())

	// Parse request body
	var req SendMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.ToParty.Value == "" {
		s.jsonError(w, "toParty is required", http.StatusBadRequest)
		return
	}
	if req.Service == "" {
		s.jsonError(w, "service is required", http.StatusBadRequest)
		return
	}
	if req.Action == "" {
		s.jsonError(w, "action is required", http.StatusBadRequest)
		return
	}

	// Create message in pending state
	message := &storage.Message{
		TenantID:       tenant.ID,
		MailboxID:      req.MailboxID,
		Direction:      storage.DirectionOutbound,
		ConversationID: req.ConversationID,
		RefToMessageID: req.RefToMessageID,
		FromParty: storage.PartyID{
			Type:  req.FromParty.Type,
			Value: req.FromParty.Value,
		},
		ToParty: storage.PartyID{
			Type:  req.ToParty.Type,
			Value: req.ToParty.Value,
		},
		Service:    req.Service,
		Action:     req.Action,
		Status:     storage.StatusPending,
		ReceivedAt: time.Now(),
	}

	// Store payloads
	for _, p := range req.Payloads {
		payloadID, err := s.store.StorePayload(r.Context(), tenant.ID, &storage.PayloadData{
			ContentID: p.ContentID,
			MimeType:  p.MimeType,
			Data:      p.Data,
		})
		if err != nil {
			s.logger.Error("failed to store payload", "error", err)
			s.jsonError(w, "failed to store payload", http.StatusInternalServerError)
			return
		}
		message.Payloads = append(message.Payloads, storage.PayloadRef{
			ID:        payloadID,
			ContentID: p.ContentID,
			MimeType:  p.MimeType,
			Size:      int64(len(p.Data)),
		})
	}

	if err := s.store.CreateMessage(r.Context(), message); err != nil {
		s.logger.Error("failed to create message", "error", err)
		s.jsonError(w, "failed to create message", http.StatusInternalServerError)
		return
	}

	s.logger.Info("message queued for sending",
		"tenant", tenant.ID,
		"message_id", message.ID,
		"to", req.ToParty.Value,
	)

	s.jsonResponse(w, map[string]interface{}{
		"id":        message.ID,
		"status":    message.Status,
		"createdAt": message.ReceivedAt,
	}, http.StatusAccepted)
}

func (s *Server) handleGetPayload(w http.ResponseWriter, r *http.Request) {
	tenant := TenantFromContext(r.Context())
	messageID := r.PathValue("messageID")
	payloadID := r.PathValue("payloadID")

	// Verify message belongs to tenant
	message, err := s.store.GetMessage(r.Context(), tenant.ID, messageID)
	if err != nil {
		s.logger.Error("failed to get message", "error", err)
		s.jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if message == nil {
		s.jsonError(w, "message not found", http.StatusNotFound)
		return
	}

	// Find payload reference in message
	var payloadRef *storage.PayloadRef
	for i := range message.Payloads {
		if message.Payloads[i].ID == payloadID || message.Payloads[i].ContentID == payloadID {
			payloadRef = &message.Payloads[i]
			break
		}
	}
	if payloadRef == nil {
		s.jsonError(w, "payload not found", http.StatusNotFound)
		return
	}

	// Get payload data
	payload, err := s.store.GetPayload(r.Context(), tenant.ID, payloadRef.ID)
	if err != nil {
		s.logger.Error("failed to get payload", "error", err)
		s.jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", payload.MimeType)
	w.Header().Set("Content-Length", strconv.Itoa(len(payload.Data)))
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, payload.ContentID))
	w.Write(payload.Data)
}

// Participant handlers

func (s *Server) handleListParticipants(w http.ResponseWriter, r *http.Request) {
	tenant := TenantFromContext(r.Context())

	participants, err := s.store.ListParticipants(r.Context(), tenant.ID, nil)
	if err != nil {
		s.logger.Error("failed to list participants", "error", err)
		s.jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, map[string]interface{}{
		"participants": participants,
		"total":        len(participants),
	}, http.StatusOK)
}

func (s *Server) handleCreateParticipant(w http.ResponseWriter, r *http.Request) {
	tenant := TenantFromContext(r.Context())

	var req CreateParticipantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.PartyID.Value == "" {
		s.jsonError(w, "partyId.value is required", http.StatusBadRequest)
		return
	}

	participant := &storage.Participant{
		TenantID: tenant.ID,
		PartyID: storage.PartyID{
			Type:  req.PartyID.Type,
			Value: req.PartyID.Value,
		},
		Name:      req.Name,
		Status:    "active",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.store.CreateParticipant(r.Context(), participant); err != nil {
		s.logger.Error("failed to create participant", "error", err)
		s.jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Create mailbox for participant
	mailbox := &storage.Mailbox{
		TenantID:      tenant.ID,
		ParticipantID: participant.ID,
		Name:          req.Name + " Mailbox",
		CreatedAt:     time.Now(),
	}
	if err := s.store.CreateMailbox(r.Context(), mailbox); err != nil {
		s.logger.Error("failed to create mailbox", "error", err)
		// Don't fail the request, participant was created
	} else {
		participant.MailboxID = mailbox.ID
		s.store.UpdateParticipant(r.Context(), participant)
	}

	s.jsonResponse(w, participant, http.StatusCreated)
}

func (s *Server) handleGetParticipant(w http.ResponseWriter, r *http.Request) {
	tenant := TenantFromContext(r.Context())
	participantID := r.PathValue("participantID")

	participant, err := s.store.GetParticipant(r.Context(), tenant.ID, participantID)
	if err != nil {
		s.logger.Error("failed to get participant", "error", err)
		s.jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if participant == nil {
		s.jsonError(w, "participant not found", http.StatusNotFound)
		return
	}

	s.jsonResponse(w, participant, http.StatusOK)
}

// Key management handlers

func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	tenant := TenantFromContext(r.Context())

	keys, err := s.keystore.ListKeys(r.Context(), tenant.ID)
	if err != nil {
		s.logger.Error("failed to list keys", "error", err)
		s.jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, map[string]interface{}{
		"keys":  keys,
		"total": len(keys),
	}, http.StatusOK)
}

func (s *Server) handleGetCertificate(w http.ResponseWriter, r *http.Request) {
	tenant := TenantFromContext(r.Context())
	keyID := r.PathValue("keyID")

	cert, err := s.keystore.GetCertificate(r.Context(), tenant.ID, keyID)
	if err != nil {
		if err == keystore.ErrKeyNotFound {
			s.jsonError(w, "key not found", http.StatusNotFound)
			return
		}
		s.logger.Error("failed to get certificate", "error", err)
		s.jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Return PEM encoded certificate
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write([]byte("-----BEGIN CERTIFICATE-----\n"))
	// Base64 encode the certificate
	encoded := make([]byte, ((len(cert.Raw)+2)/3)*4)
	base64Encode(encoded, cert.Raw)
	// Write in 64-byte lines
	for i := 0; i < len(encoded); i += 64 {
		end := i + 64
		if end > len(encoded) {
			end = len(encoded)
		}
		w.Write(encoded[i:end])
		w.Write([]byte("\n"))
	}
	w.Write([]byte("-----END CERTIFICATE-----\n"))
}

// Admin handlers

func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request) {
	filter := &storage.TenantFilter{}
	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = storage.TenantStatus(status)
	}
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil {
			filter.Limit = limit
		}
	}

	tenants, err := s.store.ListTenants(r.Context(), filter)
	if err != nil {
		s.logger.Error("failed to list tenants", "error", err)
		s.jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, map[string]interface{}{
		"tenants": tenants,
		"total":   len(tenants),
	}, http.StatusOK)
}

func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	var req CreateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Domain == "" {
		s.jsonError(w, "domain is required", http.StatusBadRequest)
		return
	}

	tenant := &storage.Tenant{
		Name:                req.Name,
		Domain:              req.Domain,
		AdminEmail:          req.AdminEmail,
		Status:              storage.TenantStatusPending,
		DefaultSigningKeyID: req.SigningKeyID,
		SMPEndpoint:         req.SMPEndpoint,
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}

	if err := s.store.CreateTenant(r.Context(), tenant); err != nil {
		s.logger.Error("failed to create tenant", "error", err)
		s.jsonError(w, "failed to create tenant", http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, tenant, http.StatusCreated)
}

func (s *Server) handleGetTenant(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenantID")

	tenant, err := s.store.GetTenant(r.Context(), tenantID)
	if err != nil {
		s.logger.Error("failed to get tenant", "error", err)
		s.jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if tenant == nil {
		s.jsonError(w, "tenant not found", http.StatusNotFound)
		return
	}

	s.jsonResponse(w, tenant, http.StatusOK)
}

func (s *Server) handleUpdateTenant(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenantID")

	tenant, err := s.store.GetTenant(r.Context(), tenantID)
	if err != nil {
		s.logger.Error("failed to get tenant", "error", err)
		s.jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if tenant == nil {
		s.jsonError(w, "tenant not found", http.StatusNotFound)
		return
	}

	var req UpdateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name != "" {
		tenant.Name = req.Name
	}
	if req.Status != "" {
		tenant.Status = storage.TenantStatus(req.Status)
	}
	if req.AdminEmail != "" {
		tenant.AdminEmail = req.AdminEmail
	}
	if req.SigningKeyID != "" {
		tenant.DefaultSigningKeyID = req.SigningKeyID
	}
	tenant.UpdatedAt = time.Now()

	if err := s.store.UpdateTenant(r.Context(), tenant); err != nil {
		s.logger.Error("failed to update tenant", "error", err)
		s.jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.jsonResponse(w, tenant, http.StatusOK)
}

func (s *Server) handleDeleteTenant(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenantID")

	if err := s.store.DeleteTenant(r.Context(), tenantID); err != nil {
		s.logger.Error("failed to delete tenant", "error", err)
		s.jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Request/Response types

type SendMessageRequest struct {
	MailboxID      string           `json:"mailboxId,omitempty"`
	ConversationID string           `json:"conversationId,omitempty"`
	RefToMessageID string           `json:"refToMessageId,omitempty"`
	FromParty      PartyIDRequest   `json:"fromParty"`
	ToParty        PartyIDRequest   `json:"toParty"`
	Service        string           `json:"service"`
	Action         string           `json:"action"`
	Payloads       []PayloadRequest `json:"payloads,omitempty"`
}

type PartyIDRequest struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value"`
}

type PayloadRequest struct {
	ContentID string `json:"contentId"`
	MimeType  string `json:"mimeType"`
	Data      []byte `json:"data"` // Base64 encoded in JSON
}

type CreateParticipantRequest struct {
	PartyID PartyIDRequest `json:"partyId"`
	Name    string         `json:"name"`
}

type CreateTenantRequest struct {
	Name         string `json:"name"`
	Domain       string `json:"domain"`
	AdminEmail   string `json:"adminEmail,omitempty"`
	SigningKeyID string `json:"signingKeyId,omitempty"`
	SMPEndpoint  string `json:"smpEndpoint,omitempty"`
}

type UpdateTenantRequest struct {
	Name         string `json:"name,omitempty"`
	Status       string `json:"status,omitempty"`
	AdminEmail   string `json:"adminEmail,omitempty"`
	SigningKeyID string `json:"signingKeyId,omitempty"`
}

// Helper functions

func (s *Server) jsonResponse(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (s *Server) jsonError(w http.ResponseWriter, message string, status int) {
	s.jsonResponse(w, map[string]string{"error": message}, status)
}

// base64Encode encodes src to dst using standard base64
func base64Encode(dst, src []byte) {
	const encode = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	di, si := 0, 0
	n := (len(src) / 3) * 3
	for si < n {
		val := uint(src[si])<<16 | uint(src[si+1])<<8 | uint(src[si+2])
		dst[di] = encode[val>>18&0x3F]
		dst[di+1] = encode[val>>12&0x3F]
		dst[di+2] = encode[val>>6&0x3F]
		dst[di+3] = encode[val&0x3F]
		si += 3
		di += 4
	}
	remain := len(src) - si
	if remain == 0 {
		return
	}
	val := uint(src[si]) << 16
	if remain == 2 {
		val |= uint(src[si+1]) << 8
	}
	dst[di] = encode[val>>18&0x3F]
	dst[di+1] = encode[val>>12&0x3F]
	if remain == 2 {
		dst[di+2] = encode[val>>6&0x3F]
		dst[di+3] = '='
	} else {
		dst[di+2] = '='
		dst[di+3] = '='
	}
}

// Ensure io is imported for PayloadRequest's JSON decoding
var _ = io.EOF

// JMAP handlers

func (s *Server) handleJMAPSession(w http.ResponseWriter, r *http.Request) {
	tenant := r.Context().Value(tenantContextKey).(*storage.Tenant)

	// Get username from auth context (for now, use tenant ID)
	username := tenant.ID

	session, err := s.jmapHandler.GetSession(r.Context(), tenant.ID, username)
	if err != nil {
		s.logger.Error("failed to get JMAP session", "error", err)
		s.jsonError(w, "failed to get session", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session)
}

func (s *Server) handleJMAPRequest(w http.ResponseWriter, r *http.Request) {
	tenant := r.Context().Value(tenantContextKey).(*storage.Tenant)

	// Parse JMAP request
	var req jmap.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Process request
	resp, err := s.jmapHandler.ProcessRequest(r.Context(), tenant.ID, &req)
	if err != nil {
		s.logger.Error("JMAP request failed", "error", err)
		s.jsonError(w, "request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleJMAPDownload(w http.ResponseWriter, r *http.Request) {
	tenant := r.Context().Value(tenantContextKey).(*storage.Tenant)
	blobID := r.PathValue("blobID")
	name := r.PathValue("name")

	if blobID == "" {
		s.jsonError(w, "blobId required", http.StatusBadRequest)
		return
	}

	// Get payload from storage
	payload, err := s.store.GetPayload(r.Context(), tenant.ID, blobID)
	if err != nil {
		s.logger.Error("failed to get payload", "blob_id", blobID, "error", err)
		s.jsonError(w, "failed to get payload", http.StatusInternalServerError)
		return
	}
	if payload == nil {
		s.jsonError(w, "blob not found", http.StatusNotFound)
		return
	}

	// Set headers
	contentType := payload.MimeType
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(payload.Data)))
	if name != "" {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	}

	w.Write(payload.Data)
}

func (s *Server) handleJMAPUpload(w http.ResponseWriter, r *http.Request) {
	tenant := r.Context().Value(tenantContextKey).(*storage.Tenant)

	// Read request body (limited to max upload size)
	maxSize := int64(104857600) // 100MB
	r.Body = http.MaxBytesReader(w, r.Body, maxSize)

	data, err := io.ReadAll(r.Body)
	if err != nil {
		s.jsonError(w, "failed to read upload: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Get content type
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	// Store payload
	payload := &storage.PayloadData{
		MimeType: contentType,
		Data:     data,
	}

	blobID, err := s.store.StorePayload(r.Context(), tenant.ID, payload)
	if err != nil {
		s.logger.Error("failed to store upload", "error", err)
		s.jsonError(w, "failed to store upload", http.StatusInternalServerError)
		return
	}

	// Return upload response
	s.jsonResponse(w, map[string]any{
		"accountId": tenant.ID,
		"blobId":    blobID,
		"type":      contentType,
		"size":      len(data),
	}, http.StatusCreated)
}

func (s *Server) handleJMAPEventSource(w http.ResponseWriter, r *http.Request) {
	tenant := r.Context().Value(tenantContextKey).(*storage.Tenant)

	// Parse query parameters
	typesParam := r.URL.Query().Get("types")
	pingStr := r.URL.Query().Get("ping")
	closeAfter := r.URL.Query().Get("closeafter")

	ping := 30 // default ping interval
	if pingStr != "" {
		if p, err := strconv.Atoi(pingStr); err == nil && p > 0 {
			ping = p
		}
	}

	// Parse types to subscribe to
	var dataTypes []string
	if typesParam == "*" || typesParam == "" {
		dataTypes = []string{"AS4Message", "AS4Mailbox", "AS4Participant"}
	} else {
		dataTypes = strings.Split(typesParam, ",")
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		s.jsonError(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	s.logger.Info("JMAP EventSource connected",
		"tenant", tenant.ID,
		"types", dataTypes,
		"ping", ping,
		"closeafter", closeAfter)

	// Send initial ping
	fmt.Fprintf(w, "event: ping\ndata: {}\n\n")
	flusher.Flush()

	// Subscribe to state changes from storage
	changeCh, err := s.store.Subscribe(r.Context(), tenant.ID, dataTypes)
	if err != nil {
		s.logger.Error("failed to subscribe to changes", "error", err)
		fmt.Fprintf(w, "event: error\ndata: {\"error\":\"subscription failed\"}\n\n")
		flusher.Flush()
		return
	}

	ticker := time.NewTicker(time.Duration(ping) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			s.logger.Info("JMAP EventSource disconnected", "tenant", tenant.ID)
			return
		case change, ok := <-changeCh:
			if !ok {
				// Channel closed
				s.logger.Info("JMAP EventSource channel closed", "tenant", tenant.ID)
				return
			}
			// Send state change event
			// Format: {"changed":{"accountId":{"DataType":"newState"}}}
			eventData := map[string]any{
				"changed": map[string]any{
					change.TenantID: change.DataTypes,
				},
			}
			data, _ := json.Marshal(eventData)
			fmt.Fprintf(w, "event: state\ndata: %s\n\n", data)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, "event: ping\ndata: {}\n\n")
			flusher.Flush()
		}
	}
}
