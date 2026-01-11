// Package auth provides authentication and authorization for the AS4 server
package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirosfoundation/go-as4/internal/config"
)

// Sentinel errors for authentication failures.
// These errors are returned by [Authenticator.ValidateToken] and
// [Authenticator.ValidateRequest] to indicate specific failure modes.
var (
	// ErrNoToken indicates no Authorization header or Bearer token was provided.
	ErrNoToken = errors.New("no authorization token provided")

	// ErrInvalidToken indicates the token is malformed or has an invalid signature.
	ErrInvalidToken = errors.New("invalid authorization token")

	// ErrTokenExpired indicates the token's exp claim is in the past.
	ErrTokenExpired = errors.New("token has expired")

	// ErrInvalidAudience indicates the token's aud claim doesn't include the configured audience.
	ErrInvalidAudience = errors.New("invalid audience")

	// ErrInvalidIssuer indicates the token's iss claim doesn't match the configured issuer.
	ErrInvalidIssuer = errors.New("invalid issuer")

	// ErrNoTenantClaim indicates the token lacks both tenant_id and tenants claims.
	ErrNoTenantClaim = errors.New("no tenant claim in token")

	// ErrTenantMismatch indicates the requested tenant is not in the token's allowed tenants.
	ErrTenantMismatch = errors.New("token tenant does not match request")
)

// Claims represents the JWT claims we care about
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf,omitempty"`

	// Custom claims
	TenantID string   `json:"tenant_id,omitempty"`
	Tenants  []string `json:"tenants,omitempty"` // Alternative: list of allowed tenants
	Scope    string   `json:"scope,omitempty"`
	Email    string   `json:"email,omitempty"`
	Name     string   `json:"name,omitempty"`
}

// UnmarshalJSON handles both string and array audience
func (c *Claims) UnmarshalJSON(data []byte) error {
	type Alias Claims
	aux := &struct {
		Audience interface{} `json:"aud"`
		*Alias
	}{
		Alias: (*Alias)(c),
	}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	switch v := aux.Audience.(type) {
	case string:
		c.Audience = []string{v}
	case []interface{}:
		c.Audience = make([]string, len(v))
		for i, a := range v {
			c.Audience[i], _ = a.(string)
		}
	}
	return nil
}

// HasAudience checks if the claims include the given audience
func (c *Claims) HasAudience(aud string) bool {
	for _, a := range c.Audience {
		if a == aud {
			return true
		}
	}
	return false
}

// HasTenant checks if the token allows access to the given tenant
func (c *Claims) HasTenant(tenantID string) bool {
	if c.TenantID == tenantID {
		return true
	}
	for _, t := range c.Tenants {
		if t == tenantID || t == "*" {
			return true
		}
	}
	return false
}

// IsExpired checks if the token has expired
func (c *Claims) IsExpired() bool {
	return time.Now().Unix() > c.ExpiresAt
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// ToRSAPublicKey converts a JWK to an RSA public key
func (j *JWK) ToRSAPublicKey() (*rsa.PublicKey, error) {
	if j.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type: %s", j.Kty)
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil {
		return nil, fmt.Errorf("decoding modulus: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(j.E)
	if err != nil {
		return nil, fmt.Errorf("decoding exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

// Authenticator handles JWT validation
type Authenticator struct {
	config *config.OAuth2Config
	logger *slog.Logger
	client *http.Client

	// Cached JWKS
	jwksMu     sync.RWMutex
	jwks       *JWKS
	jwksKeys   map[string]*rsa.PublicKey
	jwksExpiry time.Time
}

// NewAuthenticator creates a new JWT authenticator
func NewAuthenticator(cfg *config.OAuth2Config, logger *slog.Logger) *Authenticator {
	if logger == nil {
		logger = slog.Default()
	}
	return &Authenticator{
		config:   cfg,
		logger:   logger,
		client:   &http.Client{Timeout: 10 * time.Second},
		jwksKeys: make(map[string]*rsa.PublicKey),
	}
}

// IsEnabled returns true if OAuth2 authentication is configured
func (a *Authenticator) IsEnabled() bool {
	return a.config != nil && a.config.Issuer != ""
}

// ValidateRequest extracts and validates the JWT from an HTTP request
func (a *Authenticator) ValidateRequest(r *http.Request) (*Claims, error) {
	token := extractBearerToken(r)
	if token == "" {
		return nil, ErrNoToken
	}
	return a.ValidateToken(r.Context(), token)
}

// ValidateToken validates a JWT and returns its claims
func (a *Authenticator) ValidateToken(ctx context.Context, token string) (*Claims, error) {
	// Parse JWT parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding header: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("parsing header: %w", err)
	}

	// Decode claims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding claims: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("parsing claims: %w", err)
	}

	// Validate signature
	if err := a.verifySignature(ctx, token, header.Kid, header.Alg); err != nil {
		return nil, fmt.Errorf("verifying signature: %w", err)
	}

	// Validate claims
	if err := a.validateClaims(&claims); err != nil {
		return nil, err
	}

	return &claims, nil
}

func (a *Authenticator) verifySignature(ctx context.Context, token, kid, alg string) error {
	// Get the public key
	key, err := a.getKey(ctx, kid)
	if err != nil {
		return fmt.Errorf("getting key: %w", err)
	}

	// Parse token parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ErrInvalidToken
	}

	// Decode signature
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}

	// Verify based on algorithm
	message := []byte(parts[0] + "." + parts[1])
	switch alg {
	case "RS256":
		return verifyRS256(key, message, sig)
	case "RS384":
		return verifyRS384(key, message, sig)
	case "RS512":
		return verifyRS512(key, message, sig)
	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

func (a *Authenticator) validateClaims(claims *Claims) error {
	// Check expiration
	if claims.IsExpired() {
		return ErrTokenExpired
	}

	// Check not-before
	if claims.NotBefore > 0 && time.Now().Unix() < claims.NotBefore {
		return errors.New("token not yet valid")
	}

	// Check issuer
	if a.config.Issuer != "" && claims.Issuer != a.config.Issuer {
		return ErrInvalidIssuer
	}

	// Check audience
	if a.config.Audience != "" && !claims.HasAudience(a.config.Audience) {
		return ErrInvalidAudience
	}

	return nil
}

func (a *Authenticator) getKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	// Check cache first
	a.jwksMu.RLock()
	if key, ok := a.jwksKeys[kid]; ok && time.Now().Before(a.jwksExpiry) {
		a.jwksMu.RUnlock()
		return key, nil
	}
	a.jwksMu.RUnlock()

	// Fetch JWKS
	if err := a.refreshJWKS(ctx); err != nil {
		return nil, err
	}

	a.jwksMu.RLock()
	defer a.jwksMu.RUnlock()

	key, ok := a.jwksKeys[kid]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", kid)
	}
	return key, nil
}

func (a *Authenticator) refreshJWKS(ctx context.Context) error {
	a.jwksMu.Lock()
	defer a.jwksMu.Unlock()

	// Double-check after acquiring write lock
	if time.Now().Before(a.jwksExpiry) {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.config.JWKSUrl, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetching JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS fetch failed: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading JWKS: %w", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("parsing JWKS: %w", err)
	}

	// Convert keys
	keys := make(map[string]*rsa.PublicKey)
	for _, k := range jwks.Keys {
		if k.Use == "sig" || k.Use == "" {
			pk, err := k.ToRSAPublicKey()
			if err != nil {
				a.logger.Warn("failed to parse JWK", "kid", k.Kid, "error", err)
				continue
			}
			keys[k.Kid] = pk
		}
	}

	a.jwks = &jwks
	a.jwksKeys = keys
	a.jwksExpiry = time.Now().Add(1 * time.Hour) // Cache for 1 hour

	a.logger.Info("refreshed JWKS", "keys", len(keys))
	return nil
}

// extractBearerToken extracts the Bearer token from the Authorization header
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return parts[1]
}

// Context key for storing claims
type contextKey string

const ClaimsContextKey contextKey = "auth_claims"

// ClaimsFromContext retrieves claims from context
func ClaimsFromContext(ctx context.Context) *Claims {
	if v := ctx.Value(ClaimsContextKey); v != nil {
		return v.(*Claims)
	}
	return nil
}

// ContextWithClaims adds claims to context
func ContextWithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, ClaimsContextKey, claims)
}
