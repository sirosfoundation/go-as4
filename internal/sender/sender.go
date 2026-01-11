// Package sender provides background message sending for the AS4 server.
//
// The Sender runs as a background worker that polls for outbound messages
// in "pending" status and delivers them to the recipient's AS4 endpoint.
//
// # Endpoint Resolution
//
// The sender resolves recipient endpoints in the following priority order:
//
//  1. Participant.Endpoint - if the trading partner has an explicit endpoint configured
//  2. Tenant SMP - if the tenant has an SMP URL configured for static discovery
//  3. BDXL/SMP - dynamic discovery via CEF eDelivery infrastructure
//
// For BDXL discovery, the sender uses the participant's PartyID to construct
// an SMP lookup, finding the AS4 endpoint URL from the service metadata.
//
// # Retry Policy
//
// Failed deliveries are retried with exponential backoff. The retry count
// and backoff parameters are configurable. After MaxRetries attempts,
// the message status is set to "failed".
//
// # Concurrency
//
// The sender processes messages sequentially within each polling batch.
// Multiple sender instances can run concurrently for horizontal scaling,
// using optimistic locking on message status updates to prevent duplicates.
package sender

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/sirosfoundation/go-as4/internal/as4"
	"github.com/sirosfoundation/go-as4/internal/keystore"
	"github.com/sirosfoundation/go-as4/internal/storage"
	"github.com/sirosfoundation/go-as4/pkg/discovery"
)

// Sender handles background delivery of outbound AS4 messages
type Sender struct {
	store           storage.Store
	as4Handler      *as4.Handler
	signerProvider  keystore.SignerProvider
	discoveryClient *discovery.DiscoveryClient
	logger          *slog.Logger

	// Configuration
	pollInterval    time.Duration
	batchSize       int
	maxRetries      int
	initialBackoff  time.Duration
	maxBackoff      time.Duration
	backoffMultiple float64

	// Discovery configuration
	bdxlDomain string // e.g., "edelivery.tech.ec.europa.eu" for CEF/Peppol

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Config holds sender configuration
type Config struct {
	PollInterval    time.Duration
	BatchSize       int
	MaxRetries      int
	InitialBackoff  time.Duration
	MaxBackoff      time.Duration
	BackoffMultiple float64
	BDXLDomain      string // Default BDXL domain for SMP discovery
}

// DefaultConfig returns sensible defaults
func DefaultConfig() *Config {
	return &Config{
		PollInterval:    10 * time.Second,
		BatchSize:       10,
		MaxRetries:      5,
		InitialBackoff:  5 * time.Minute,
		MaxBackoff:      24 * time.Hour,
		BackoffMultiple: 2.0,
		BDXLDomain:      "edelivery.tech.ec.europa.eu", // CEF eDelivery
	}
}

// NewSender creates a new background sender
func NewSender(
	store storage.Store,
	as4Handler *as4.Handler,
	signerProvider keystore.SignerProvider,
	cfg *Config,
	logger *slog.Logger,
) *Sender {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	// Initialize discovery client
	bdxlDomain := cfg.BDXLDomain
	if bdxlDomain == "" {
		bdxlDomain = "edelivery.tech.ec.europa.eu"
	}

	return &Sender{
		store:           store,
		as4Handler:      as4Handler,
		signerProvider:  signerProvider,
		discoveryClient: discovery.NewDiscoveryClient(bdxlDomain),
		logger:          logger,
		bdxlDomain:      bdxlDomain,
		pollInterval:    cfg.PollInterval,
		batchSize:       cfg.BatchSize,
		maxRetries:      cfg.MaxRetries,
		initialBackoff:  cfg.InitialBackoff,
		maxBackoff:      cfg.MaxBackoff,
		backoffMultiple: cfg.BackoffMultiple,
	}
}

// Start begins background message processing
func (s *Sender) Start(ctx context.Context) {
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.wg.Add(1)
	go s.run()
	s.logger.Info("sender started", "poll_interval", s.pollInterval)
}

// Stop gracefully stops the sender
func (s *Sender) Stop() {
	s.cancel()
	s.wg.Wait()
	s.logger.Info("sender stopped")
}

func (s *Sender) run() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.processPendingMessages()
		}
	}
}

func (s *Sender) processPendingMessages() {
	// Get all active tenants
	tenants, err := s.store.ListTenants(s.ctx, &storage.TenantFilter{
		Status: storage.TenantStatusActive,
	})
	if err != nil {
		s.logger.Error("failed to list tenants", "error", err)
		return
	}

	for _, tenant := range tenants {
		s.processTenantsMessages(tenant)
	}
}

func (s *Sender) processTenantsMessages(tenant *storage.Tenant) {
	// Get pending outbound messages for this tenant
	messages, err := s.store.GetPendingOutbound(s.ctx, tenant.ID, s.batchSize)
	if err != nil {
		s.logger.Error("failed to get pending messages", "tenant", tenant.ID, "error", err)
		return
	}

	for _, msg := range messages {
		s.sendMessage(tenant, msg)
	}
}

func (s *Sender) sendMessage(tenant *storage.Tenant, msg *storage.Message) {
	log := s.logger.With(
		"tenant", tenant.ID,
		"message_id", msg.ID,
		"as4_message_id", msg.AS4MessageID,
	)

	// Mark as sending
	if err := s.store.UpdateMessageStatus(s.ctx, tenant.ID, msg.ID, storage.StatusSending); err != nil {
		log.Error("failed to update message status", "error", err)
		return
	}

	// Resolve endpoint for the recipient
	endpoint, err := s.resolveEndpoint(tenant, msg)
	if err != nil {
		log.Error("endpoint resolution failed", "party_id", msg.ToParty, "error", err)
		s.markFailed(tenant.ID, msg, "endpoint resolution failed: "+err.Error())
		return
	}

	if endpoint == "" {
		s.markFailed(tenant.ID, msg, "no endpoint found for recipient")
		return
	}

	// Deliver the message
	s.deliverMessage(tenant, msg, endpoint)
}

// resolveEndpoint determines the AS4 endpoint URL for the message recipient.
// It follows this priority:
// 1. If the recipient is a known participant with an endpoint configured, use that
// 2. If the tenant has an SMP endpoint configured, use direct SMP lookup
// 3. Otherwise, use BDXL + SMP dynamic discovery
func (s *Sender) resolveEndpoint(tenant *storage.Tenant, msg *storage.Message) (string, error) {
	log := s.logger.With(
		"tenant", tenant.ID,
		"to_party", msg.ToParty.Value,
		"service", msg.Service,
		"action", msg.Action,
	)

	// Check if the recipient is a known participant
	recipient, err := s.store.GetParticipantByPartyID(s.ctx, tenant.ID, msg.ToParty)
	if err != nil {
		return "", err
	}

	if recipient != nil && recipient.Endpoint != "" {
		log.Debug("using configured participant endpoint", "endpoint", recipient.Endpoint)
		return recipient.Endpoint, nil
	}

	// Build the party ID identifier for SMP lookup
	// Format: iso6523-actorid-upis::<scheme>::<id>
	partyID := formatPartyIDForSMP(msg.ToParty)

	// Use the document type (action) as the document type identifier
	// In Peppol, this would be the document type ID
	documentTypeID := msg.Action

	// Use the service as the process ID
	processID := msg.Service

	log.Debug("performing SMP discovery",
		"party_id", partyID,
		"document_type", documentTypeID,
		"process_id", processID,
	)

	// If tenant has a specific SMP endpoint, use direct lookup
	if tenant.SMPEndpoint != "" {
		endpoint, err := s.discoveryClient.SMPClient().GetEndpoint(
			s.ctx,
			tenant.SMPEndpoint,
			partyID,
			documentTypeID,
			processID,
		)
		if err != nil {
			return "", err
		}
		if endpoint != nil {
			log.Info("resolved endpoint via tenant SMP", "endpoint", endpoint.EndpointURL)
			return endpoint.EndpointURL, nil
		}
	}

	// Use full BDXL + SMP discovery
	endpoint, err := s.discoveryClient.DiscoverAS4Endpoint(
		s.ctx,
		partyID,
		documentTypeID,
		processID,
	)
	if err != nil {
		return "", err
	}

	if endpoint != nil {
		log.Info("resolved endpoint via BDXL discovery", "endpoint", endpoint.EndpointURL)
		return endpoint.EndpointURL, nil
	}

	return "", nil
}

// formatPartyIDForSMP converts a PartyID to the format expected by SMP
func formatPartyIDForSMP(partyID storage.PartyID) string {
	// Extract scheme from type URI
	// e.g., "urn:oasis:names:tc:ebcore:partyid-type:iso6523:0088" -> "0088"
	scheme := partyID.Type
	if idx := lastIndexOf(scheme, ':'); idx >= 0 {
		scheme = scheme[idx+1:]
	}
	// Return in iso6523-actorid-upis format
	return scheme + "::" + partyID.Value
}

func lastIndexOf(s string, char byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == char {
			return i
		}
	}
	return -1
}

func (s *Sender) deliverMessage(tenant *storage.Tenant, msg *storage.Message, endpoint string) {
	log := s.logger.With(
		"tenant", tenant.ID,
		"message_id", msg.ID,
		"endpoint", endpoint,
	)

	// Load payloads
	var payloads []as4.PayloadPart
	for _, ref := range msg.Payloads {
		data, err := s.store.GetPayload(s.ctx, tenant.ID, ref.ID)
		if err != nil {
			log.Error("failed to load payload", "payload_id", ref.ID, "error", err)
			s.markFailed(tenant.ID, msg, "failed to load payload: "+err.Error())
			return
		}
		payloads = append(payloads, as4.PayloadPart{
			ContentID:   ref.ContentID,
			ContentType: ref.MimeType,
			Data:        data.Data,
		})
	}

	// For now, we can't send without authentication credentials
	// This would need to be handled differently in production:
	// - PRF mode: Not suitable for background sending (requires user auth)
	// - PKCS#11: Could work with PIN cached or no PIN required
	// - File mode: Works without authentication

	// Get signing key ID
	keyID := tenant.DefaultSigningKeyID
	if keyID == "" {
		log.Warn("tenant has no signing key, sending unsigned")
	}

	// Build send request
	req := &as4.SendRequest{
		EndpointURL:    endpoint,
		MessageID:      msg.AS4MessageID,
		ConversationID: msg.ConversationID,
		RefToMessageID: msg.RefToMessageID,
		FromParty:      msg.FromParty,
		ToParty:        msg.ToParty,
		Service:        msg.Service,
		Action:         msg.Action,
		SigningKeyID:   keyID,
		Payloads:       payloads,
	}

	// For background sending, we need credentials
	// This is a limitation - in production, you'd either:
	// 1. Use PKCS#11 with persistent session
	// 2. Have the PRF key cached from recent user session
	// 3. Use file-based keys for development
	var creds *keystore.SessionCredentials
	// creds would be set based on signing mode

	result, err := s.as4Handler.SendMessage(s.ctx, tenant.ID, req, creds)
	if err != nil {
		log.Error("send failed", "error", err)
		s.handleSendError(tenant.ID, msg, err)
		return
	}

	// Mark as sent
	msg.Status = storage.StatusSent
	now := time.Now()
	msg.DeliveredAt = &now
	if err := s.store.UpdateMessage(s.ctx, msg); err != nil {
		log.Error("failed to update message after send", "error", err)
	}

	log.Info("message sent successfully", "result_message_id", result.MessageID)
}

func (s *Sender) handleSendError(tenantID string, msg *storage.Message, sendErr error) {
	msg.RetryCount++
	msg.LastError = sendErr.Error()

	if msg.RetryCount >= s.maxRetries {
		// Max retries exceeded
		s.markFailed(tenantID, msg, "max retries exceeded")
		return
	}

	// Calculate next retry time with exponential backoff
	backoff := s.initialBackoff
	for i := 1; i < msg.RetryCount; i++ {
		backoff = time.Duration(float64(backoff) * s.backoffMultiple)
		if backoff > s.maxBackoff {
			backoff = s.maxBackoff
			break
		}
	}

	nextRetry := time.Now().Add(backoff)
	msg.NextRetryAt = &nextRetry
	msg.Status = storage.StatusPending

	if err := s.store.UpdateMessage(s.ctx, msg); err != nil {
		s.logger.Error("failed to schedule retry", "message_id", msg.ID, "error", err)
	} else {
		s.logger.Info("message scheduled for retry",
			"message_id", msg.ID,
			"retry_count", msg.RetryCount,
			"next_retry", nextRetry,
		)
	}
}

func (s *Sender) markFailed(tenantID string, msg *storage.Message, reason string) {
	msg.Status = storage.StatusFailed
	msg.LastError = reason

	if err := s.store.UpdateMessage(s.ctx, msg); err != nil {
		s.logger.Error("failed to mark message as failed", "message_id", msg.ID, "error", err)
	} else {
		s.logger.Warn("message marked as failed", "message_id", msg.ID, "reason", reason)
	}
}
