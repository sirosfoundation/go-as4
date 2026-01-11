// Package security implements certificate revocation checking via OCSP and CRL.
// This file provides OCSP and CRL checking as required by Swedish SDK federation.
package security

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// RevocationChecker defines the interface for certificate revocation checking
type RevocationChecker interface {
	// CheckRevocation checks if a certificate has been revoked
	// Returns nil if the certificate is valid (not revoked)
	// Returns ErrCertificateRevoked if revoked
	// Returns other errors for check failures
	CheckRevocation(ctx context.Context, cert, issuer *x509.Certificate) error
}

// OCSPConfig configures OCSP checking behavior
type OCSPConfig struct {
	// HTTPClient for OCSP requests (optional)
	HTTPClient *http.Client
	// Timeout for OCSP requests
	Timeout time.Duration
	// CRLFallback enables CRL checking if OCSP fails
	CRLFallback bool
	// CacheTimeout for caching OCSP responses
	CacheTimeout time.Duration
	// StrictMode fails if revocation status cannot be determined
	StrictMode bool
}

// DefaultOCSPConfig returns default configuration
func DefaultOCSPConfig() *OCSPConfig {
	return &OCSPConfig{
		Timeout:      10 * time.Second,
		CRLFallback:  true,
		CacheTimeout: 1 * time.Hour,
		StrictMode:   false,
	}
}

// OCSPRevocationChecker implements RevocationChecker using OCSP with optional CRL fallback
type OCSPRevocationChecker struct {
	config     *OCSPConfig
	httpClient *http.Client
	crlCache   *CRLCache
	ocspCache  *OCSPCache
}

// NewOCSPRevocationChecker creates a new OCSP-based revocation checker
func NewOCSPRevocationChecker(config *OCSPConfig) *OCSPRevocationChecker {
	if config == nil {
		config = DefaultOCSPConfig()
	}

	client := config.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: config.Timeout,
		}
	}

	return &OCSPRevocationChecker{
		config:     config,
		httpClient: client,
		crlCache:   NewCRLCache(config.CacheTimeout),
		ocspCache:  NewOCSPCache(config.CacheTimeout),
	}
}

// CheckRevocation checks certificate revocation status
func (c *OCSPRevocationChecker) CheckRevocation(ctx context.Context, cert, issuer *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("certificate is nil")
	}
	if issuer == nil {
		return fmt.Errorf("issuer certificate is nil")
	}

	// Try OCSP first
	ocspErr := c.checkOCSP(ctx, cert, issuer)
	if ocspErr == nil {
		return nil // Certificate is valid
	}
	if ocspErr == ErrCertificateRevoked {
		return ocspErr // Certificate is definitely revoked
	}

	// OCSP failed for other reasons, try CRL if configured
	if c.config.CRLFallback {
		crlErr := c.checkCRL(ctx, cert, issuer)
		if crlErr == nil {
			return nil // Certificate is valid per CRL
		}
		if crlErr == ErrCertificateRevoked {
			return crlErr
		}
		// Both OCSP and CRL failed
		if c.config.StrictMode {
			return fmt.Errorf("revocation check failed: OCSP: %v, CRL: %v", ocspErr, crlErr)
		}
	}

	// In non-strict mode, return nil if we couldn't determine status
	if c.config.StrictMode {
		return fmt.Errorf("OCSP check failed: %w", ocspErr)
	}
	return nil
}

// checkOCSP performs OCSP checking
func (c *OCSPRevocationChecker) checkOCSP(ctx context.Context, cert, issuer *x509.Certificate) error {
	// Check cache first
	if cached, ok := c.ocspCache.Get(cert.SerialNumber.String()); ok {
		return cached
	}

	// Get OCSP server URL from certificate
	if len(cert.OCSPServer) == 0 {
		return fmt.Errorf("no OCSP server URL in certificate")
	}

	ocspURL := cert.OCSPServer[0]

	// Create OCSP request
	ocspRequest, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{
		Hash: crypto.SHA256,
	})
	if err != nil {
		return fmt.Errorf("failed to create OCSP request: %w", err)
	}

	// Try HTTP POST first (preferred), then GET
	resp, err := c.doOCSPRequest(ctx, ocspURL, ocspRequest)
	if err != nil {
		return fmt.Errorf("OCSP request failed: %w", err)
	}

	// Parse response
	ocspResp, err := ocsp.ParseResponse(resp, issuer)
	if err != nil {
		return fmt.Errorf("failed to parse OCSP response: %w", err)
	}

	// Check status
	var result error
	switch ocspResp.Status {
	case ocsp.Good:
		result = nil
	case ocsp.Revoked:
		result = ErrCertificateRevoked
	case ocsp.Unknown:
		result = fmt.Errorf("OCSP status unknown")
	default:
		result = fmt.Errorf("unexpected OCSP status: %d", ocspResp.Status)
	}

	// Cache the result
	c.ocspCache.Set(cert.SerialNumber.String(), result)

	return result
}

// doOCSPRequest performs the HTTP request to OCSP server
func (c *OCSPRevocationChecker) doOCSPRequest(ctx context.Context, ocspURL string, request []byte) ([]byte, error) {
	// Try POST first
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ocspURL, bytes.NewReader(request))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")
	httpReq.Header.Set("Accept", "application/ocsp-response")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		// Try GET as fallback
		return c.doOCSPGET(ctx, ocspURL, request)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return c.doOCSPGET(ctx, ocspURL, request)
	}

	return io.ReadAll(resp.Body)
}

// doOCSPGET performs OCSP request via HTTP GET
func (c *OCSPRevocationChecker) doOCSPGET(ctx context.Context, ocspURL string, request []byte) ([]byte, error) {
	encoded := base64.StdEncoding.EncodeToString(request)
	reqURL := ocspURL + "/" + url.PathEscape(encoded)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Accept", "application/ocsp-response")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OCSP server returned status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// checkCRL performs CRL checking
func (c *OCSPRevocationChecker) checkCRL(ctx context.Context, cert, issuer *x509.Certificate) error {
	if len(cert.CRLDistributionPoints) == 0 {
		return fmt.Errorf("no CRL distribution points in certificate")
	}

	// Try each distribution point
	var lastErr error
	for _, dp := range cert.CRLDistributionPoints {
		crl, err := c.fetchCRL(ctx, dp)
		if err != nil {
			lastErr = err
			continue
		}

		// Check if certificate is in CRL
		for _, revoked := range crl.RevokedCertificateEntries {
			if revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return ErrCertificateRevoked
			}
		}

		// Certificate not in CRL = not revoked
		return nil
	}

	return fmt.Errorf("failed to check CRL: %w", lastErr)
}

// fetchCRL retrieves and caches a CRL
func (c *OCSPRevocationChecker) fetchCRL(ctx context.Context, url string) (*x509.RevocationList, error) {
	// Check cache first
	if cached, ok := c.crlCache.Get(url); ok {
		return cached, nil
	}

	// Fetch CRL
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CRL server returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL: %w", err)
	}

	// Cache the CRL
	c.crlCache.Set(url, crl)

	return crl, nil
}

// CRLCache provides thread-safe caching of CRLs
type CRLCache struct {
	mu      sync.RWMutex
	cache   map[string]*crlEntry
	timeout time.Duration
}

type crlEntry struct {
	crl       *x509.RevocationList
	fetchedAt time.Time
}

// NewCRLCache creates a new CRL cache
func NewCRLCache(timeout time.Duration) *CRLCache {
	return &CRLCache{
		cache:   make(map[string]*crlEntry),
		timeout: timeout,
	}
}

// Get retrieves a cached CRL
func (c *CRLCache) Get(url string) (*x509.RevocationList, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.cache[url]
	if !ok {
		return nil, false
	}

	// Check if expired
	if time.Since(entry.fetchedAt) > c.timeout {
		return nil, false
	}

	return entry.crl, true
}

// Set stores a CRL in the cache
func (c *CRLCache) Set(url string, crl *x509.RevocationList) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[url] = &crlEntry{
		crl:       crl,
		fetchedAt: time.Now(),
	}
}

// OCSPCache provides thread-safe caching of OCSP results
type OCSPCache struct {
	mu      sync.RWMutex
	cache   map[string]*ocspEntry
	timeout time.Duration
}

type ocspEntry struct {
	err       error
	checkedAt time.Time
}

// NewOCSPCache creates a new OCSP result cache
func NewOCSPCache(timeout time.Duration) *OCSPCache {
	return &OCSPCache{
		cache:   make(map[string]*ocspEntry),
		timeout: timeout,
	}
}

// Get retrieves a cached OCSP result
func (c *OCSPCache) Get(serial string) (error, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.cache[serial]
	if !ok {
		return nil, false
	}

	if time.Since(entry.checkedAt) > c.timeout {
		return nil, false
	}

	return entry.err, true
}

// Set stores an OCSP result in the cache
func (c *OCSPCache) Set(serial string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[serial] = &ocspEntry{
		err:       err,
		checkedAt: time.Now(),
	}
}

// RevocationAwareCertValidator wraps a CertificateValidator with revocation checking
type RevocationAwareCertValidator struct {
	base    CertificateValidator
	checker RevocationChecker
}

// NewRevocationAwareCertValidator creates a validator with revocation checking
func NewRevocationAwareCertValidator(base CertificateValidator, checker RevocationChecker) *RevocationAwareCertValidator {
	return &RevocationAwareCertValidator{
		base:    base,
		checker: checker,
	}
}

// ValidateCertificate validates a certificate including revocation check
func (v *RevocationAwareCertValidator) ValidateCertificate(cert *x509.Certificate, chain []*x509.Certificate, purpose string) error {
	// First do base validation
	if err := v.base.ValidateCertificate(cert, chain, purpose); err != nil {
		return err
	}

	// Then check revocation
	if v.checker != nil && len(chain) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Check the end-entity certificate against its issuer
		if err := v.checker.CheckRevocation(ctx, cert, chain[0]); err != nil {
			return err
		}
	}

	return nil
}

// ValidateCertificateChain validates a certificate chain with revocation checking
func (v *RevocationAwareCertValidator) ValidateCertificateChain(chain []*x509.Certificate, purpose string) error {
	if len(chain) == 0 {
		return fmt.Errorf("%w: empty chain", ErrInvalidCertificate)
	}

	// Validate first cert with remaining chain as intermediates
	return v.ValidateCertificate(chain[0], chain[1:], purpose)
}
