// Package tenant provides multi-tenant business logic for the AS4 server
package tenant

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/sirosfoundation/go-as4/internal/keystore"
	"github.com/sirosfoundation/go-as4/internal/storage"
)

// Service manages tenants and their resources
type Service struct {
	store          *storage.Store
	signerProvider keystore.SignerProvider
	logger         *slog.Logger

	// Cache for tenant lookups
	mu          sync.RWMutex
	tenantCache map[string]*storage.Tenant
	cacheTTL    time.Duration
	lastRefresh time.Time
}

// Store aggregates all storage interfaces required by the tenant service.
// It embeds the individual store interfaces for tenants, participants,
// mailboxes, messages, and payloads, providing a unified access point
// for all persistence operations within a tenant context.
type Store struct {
	storage.TenantStore
	storage.ParticipantStore
	storage.MailboxStore
	storage.MessageStore
	storage.PayloadStore
}

// Config holds service configuration
type Config struct {
	CacheTTL time.Duration
	Logger   *slog.Logger
}

// NewService creates a new tenant service
func NewService(store *Store, signerProvider keystore.SignerProvider, cfg *Config) *Service {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	cacheTTL := cfg.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute
	}

	return &Service{
		store:          (*storage.Store)(nil), // Will use individual stores
		signerProvider: signerProvider,
		logger:         logger,
		tenantCache:    make(map[string]*storage.Tenant),
		cacheTTL:       cacheTTL,
	}
}

// Tenant operations

// GetTenant returns a tenant by ID, using cache
func (s *Service) GetTenant(ctx context.Context, id string) (*storage.Tenant, error) {
	// Check cache first
	s.mu.RLock()
	if tenant, ok := s.tenantCache[id]; ok {
		s.mu.RUnlock()
		return tenant, nil
	}
	s.mu.RUnlock()

	// Cache miss - load from store
	// Note: This method signature will be updated when we have the store interface properly connected
	return nil, fmt.Errorf("tenant store not configured")
}

// GetTenantByDomain returns a tenant by domain
func (s *Service) GetTenantByDomain(ctx context.Context, domain string) (*storage.Tenant, error) {
	// Check cache
	s.mu.RLock()
	for _, tenant := range s.tenantCache {
		if tenant.Domain == domain {
			s.mu.RUnlock()
			return tenant, nil
		}
	}
	s.mu.RUnlock()

	return nil, fmt.Errorf("tenant store not configured")
}

// CreateTenant creates a new tenant
func (s *Service) CreateTenant(ctx context.Context, req *CreateTenantRequest) (*storage.Tenant, error) {
	tenant := &storage.Tenant{
		Name:                req.Name,
		Domain:              req.Domain,
		Status:              storage.TenantStatusPending,
		DefaultSigningKeyID: req.SigningKeyID,
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}

	// Validate that signing key exists
	if req.SigningKeyID != "" {
		_, err := s.signerProvider.GetCertificate(ctx, tenant.ID, req.SigningKeyID)
		if err != nil {
			return nil, fmt.Errorf("invalid signing key: %w", err)
		}
	}

	return tenant, nil
}

// CreateTenantRequest holds parameters for creating a tenant
type CreateTenantRequest struct {
	Name               string
	Domain             string
	SigningKeyID       string
	EncryptionKeyID    string
	DefaultPartnerType string
}

// UpdateTenantRequest holds parameters for updating a tenant
type UpdateTenantRequest struct {
	Name         *string
	Status       *storage.TenantStatus
	SigningKeyID *string
}

// UpdateTenant updates a tenant
func (s *Service) UpdateTenant(ctx context.Context, id string, req *UpdateTenantRequest) (*storage.Tenant, error) {
	tenant, err := s.GetTenant(ctx, id)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, fmt.Errorf("tenant not found")
	}

	if req.Name != nil {
		tenant.Name = *req.Name
	}
	if req.Status != nil {
		tenant.Status = *req.Status
	}
	if req.SigningKeyID != nil {
		tenant.DefaultSigningKeyID = *req.SigningKeyID
	}

	tenant.UpdatedAt = time.Now()

	// Invalidate cache
	s.mu.Lock()
	delete(s.tenantCache, id)
	s.mu.Unlock()

	return tenant, nil
}

// Participant operations

// RegisterParticipant registers a new participant for a tenant
func (s *Service) RegisterParticipant(ctx context.Context, tenantID string, req *RegisterParticipantRequest) (*storage.Participant, error) {
	tenant, err := s.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, fmt.Errorf("tenant not found")
	}

	participant := &storage.Participant{
		TenantID:     tenantID,
		PartyID:      req.PartyID,
		Name:         req.Name,
		Status:       "active",
		SigningKeyID: req.SigningKeyID,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	return participant, nil
}

// RegisterParticipantRequest holds parameters for registering a participant
type RegisterParticipantRequest struct {
	PartyID      storage.PartyID
	Name         string
	SigningKeyID string
}

// Mailbox operations

// GetOrCreateMailbox gets or creates a mailbox for a participant
func (s *Service) GetOrCreateMailbox(ctx context.Context, tenantID, participantID string) (*storage.Mailbox, error) {
	// Implementation will use MailboxStore
	mailbox := &storage.Mailbox{
		TenantID:      tenantID,
		ParticipantID: participantID,
		CreatedAt:     time.Now(),
	}
	return mailbox, nil
}

// Message operations

// SubmitMessage submits a message for sending
func (s *Service) SubmitMessage(ctx context.Context, tenantID string, msg *SubmitMessageRequest) (*storage.Message, error) {
	tenant, err := s.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, fmt.Errorf("tenant not found")
	}

	message := &storage.Message{
		TenantID:       tenantID,
		MailboxID:      msg.MailboxID,
		Direction:      storage.DirectionOutbound,
		AS4MessageID:   msg.AS4MessageID,
		ConversationID: msg.ConversationID,
		RefToMessageID: msg.RefToMessageID,
		FromParty:      msg.FromParty,
		ToParty:        msg.ToParty,
		Service:        msg.Service,
		Action:         msg.Action,
		Status:         storage.StatusPending,
		Payloads:       msg.Payloads,
		ReceivedAt:     time.Now(),
		RetryCount:     0,
	}

	return message, nil
}

// SubmitMessageRequest holds parameters for submitting a message
type SubmitMessageRequest struct {
	MailboxID      string
	AS4MessageID   string
	ConversationID string
	RefToMessageID string
	FromParty      storage.PartyID
	ToParty        storage.PartyID
	Service        string
	Action         string
	Payloads       []storage.PayloadRef
}

// GetMessages retrieves messages for a mailbox
func (s *Service) GetMessages(ctx context.Context, tenantID, mailboxID string, filter *storage.MessageFilter) ([]*storage.Message, error) {
	if filter == nil {
		filter = &storage.MessageFilter{}
	}
	filter.MailboxID = mailboxID
	return nil, fmt.Errorf("message store not configured")
}

// Signing operations

// GetSigner returns a signer for a tenant with the provided session credentials
func (s *Service) GetSigner(ctx context.Context, tenantID string, creds *keystore.SessionCredentials) (keystore.Signer, error) {
	tenant, err := s.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, fmt.Errorf("tenant not found")
	}

	keyID := tenant.DefaultSigningKeyID
	if keyID == "" {
		return nil, fmt.Errorf("tenant has no signing key configured")
	}

	// Add credentials to context
	ctx = keystore.ContextWithCredentials(ctx, creds)

	return s.signerProvider.GetSigner(ctx, tenantID, keyID)
}

// GetSigningCertificate returns the tenant's signing certificate
func (s *Service) GetSigningCertificate(ctx context.Context, tenantID string) ([]byte, error) {
	tenant, err := s.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, fmt.Errorf("tenant not found")
	}

	keyID := tenant.DefaultSigningKeyID
	if keyID == "" {
		return nil, fmt.Errorf("tenant has no signing key configured")
	}

	cert, err := s.signerProvider.GetCertificate(ctx, tenantID, keyID)
	if err != nil {
		return nil, err
	}

	return cert.Raw, nil
}

// Health check

// HealthCheck verifies the service is operational
func (s *Service) HealthCheck(ctx context.Context) error {
	// Check signer provider
	if s.signerProvider == nil {
		return fmt.Errorf("signer provider not configured")
	}
	return nil
}
