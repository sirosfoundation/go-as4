package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirosfoundation/go-as4/internal/config"
)

func TestAuthenticator_DevMode(t *testing.T) {
	cfg := &config.OAuth2Config{
		DevMode:    true,
		DevTenants: []string{"test-tenant", "demo-tenant"},
	}

	auth := NewAuthenticator(cfg, nil)

	if !auth.IsDevMode() {
		t.Fatal("expected dev mode to be enabled")
	}

	if !auth.IsEnabled() {
		t.Fatal("expected auth to be enabled in dev mode")
	}

	tests := []struct {
		name       string
		tenant     string
		wantErr    bool
		wantTenant string
	}{
		{
			name:       "valid dev tenant",
			tenant:     "test-tenant",
			wantErr:    false,
			wantTenant: "test-tenant",
		},
		{
			name:       "another valid tenant",
			tenant:     "demo-tenant",
			wantErr:    false,
			wantTenant: "demo-tenant",
		},
		{
			name:    "unauthorized tenant",
			tenant:  "other-tenant",
			wantErr: true,
		},
		{
			name:    "no tenant header",
			tenant:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.tenant != "" {
				req.Header.Set("X-Dev-Tenant", tt.tenant)
			}

			claims, err := auth.ValidateRequest(req)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if claims.TenantID != tt.wantTenant {
				t.Errorf("expected tenant %q, got %q", tt.wantTenant, claims.TenantID)
			}

			if !claims.HasTenant(tt.wantTenant) {
				t.Errorf("claims.HasTenant(%q) = false, want true", tt.wantTenant)
			}
		})
	}
}

func TestAuthenticator_DevModeAllTenants(t *testing.T) {
	// Empty DevTenants list means all tenants allowed
	cfg := &config.OAuth2Config{
		DevMode:    true,
		DevTenants: []string{}, // Empty = allow all
	}

	auth := NewAuthenticator(cfg, nil)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Dev-Tenant", "any-tenant")

	claims, err := auth.ValidateRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if claims.TenantID != "any-tenant" {
		t.Errorf("expected tenant 'any-tenant', got %q", claims.TenantID)
	}
}

func TestAuthenticator_DevModeDisabled(t *testing.T) {
	cfg := &config.OAuth2Config{
		DevMode: false,
		Issuer:  "https://auth.example.com",
	}

	auth := NewAuthenticator(cfg, nil)

	if auth.IsDevMode() {
		t.Fatal("expected dev mode to be disabled")
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Dev-Tenant", "test-tenant")

	// Without JWT, should fail
	_, err := auth.ValidateRequest(req)
	if err != ErrNoToken {
		t.Errorf("expected ErrNoToken, got %v", err)
	}
}

func TestClaims_HasTenant(t *testing.T) {
	tests := []struct {
		name     string
		claims   *Claims
		tenant   string
		expected bool
	}{
		{
			name:     "direct match",
			claims:   &Claims{TenantID: "tenant-a"},
			tenant:   "tenant-a",
			expected: true,
		},
		{
			name:     "tenants list match",
			claims:   &Claims{Tenants: []string{"tenant-a", "tenant-b"}},
			tenant:   "tenant-b",
			expected: true,
		},
		{
			name:     "wildcard",
			claims:   &Claims{Tenants: []string{"*"}},
			tenant:   "any-tenant",
			expected: true,
		},
		{
			name:     "no match",
			claims:   &Claims{TenantID: "tenant-a", Tenants: []string{"tenant-b"}},
			tenant:   "tenant-c",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.claims.HasTenant(tt.tenant)
			if got != tt.expected {
				t.Errorf("HasTenant(%q) = %v, want %v", tt.tenant, got, tt.expected)
			}
		})
	}
}
