// Package transport implements HTTPS transport layer for AS4 with TLS 1.2/1.3package transport

package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"
)

// TLS version constants
const (
	TLS12 = tls.VersionTLS12
	TLS13 = tls.VersionTLS13
)

// Recommended TLS 1.2 cipher suites for AS4
var RecommendedTLS12CipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

// HTTPSConfig contains HTTPS client/server configuration
type HTTPSConfig struct {
	MinTLSVersion   uint16
	MaxTLSVersion   uint16
	CipherSuites    []uint16
	ClientAuth      tls.ClientAuthType
	Certificates    []tls.Certificate
	RootCAs         *x509.CertPool
	ClientCAs       *x509.CertPool
	Timeout         time.Duration
	IdleConnTimeout time.Duration
}

// DefaultHTTPSConfig returns a default HTTPS configuration
func DefaultHTTPSConfig() *HTTPSConfig {
	return &HTTPSConfig{
		MinTLSVersion:   TLS12,
		MaxTLSVersion:   TLS13,
		CipherSuites:    RecommendedTLS12CipherSuites,
		ClientAuth:      tls.NoClientCert,
		Timeout:         30 * time.Second,
		IdleConnTimeout: 90 * time.Second,
	}
}

// HTTPSClient handles AS4 message transmission over HTTPS
type HTTPSClient struct {
	client *http.Client
	config *HTTPSConfig
}

// NewHTTPSClient creates a new HTTPS client
func NewHTTPSClient(config *HTTPSConfig) *HTTPSClient {
	if config == nil {
		config = DefaultHTTPSConfig()
	}

	tlsConfig := &tls.Config{
		MinVersion:   config.MinTLSVersion,
		MaxVersion:   config.MaxTLSVersion,
		CipherSuites: config.CipherSuites,
		Certificates: config.Certificates,
		RootCAs:      config.RootCAs,
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		IdleConnTimeout:     config.IdleConnTimeout,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
	}

	return &HTTPSClient{
		client: &http.Client{
			Transport: transport,
			Timeout:   config.Timeout,
		},
		config: config,
	}
}

// Send sends an AS4 message to the specified endpoint
func (c *HTTPSClient) Send(ctx context.Context, endpoint string, message []byte, contentType string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(message))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "go-as4/1.0")
	req.Header.Set("SOAPAction", "") // Empty for AS4

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
	}

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return responseBody, nil
}

// HTTPSServer handles receiving AS4 messages over HTTPS
type HTTPSServer struct {
	server  *http.Server
	config  *HTTPSConfig
	handler AS4Handler
}

// AS4Handler processes incoming AS4 messages
type AS4Handler interface {
	HandleMessage(ctx context.Context, message []byte) ([]byte, error)
}

// NewHTTPSServer creates a new HTTPS server
func NewHTTPSServer(addr string, config *HTTPSConfig, handler AS4Handler) *HTTPSServer {
	if config == nil {
		config = DefaultHTTPSConfig()
	}

	tlsConfig := &tls.Config{
		MinVersion:   config.MinTLSVersion,
		MaxVersion:   config.MaxTLSVersion,
		CipherSuites: config.CipherSuites,
		Certificates: config.Certificates,
		ClientCAs:    config.ClientCAs,
		ClientAuth:   config.ClientAuth,
	}

	s := &HTTPSServer{
		config:  config,
		handler: handler,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/as4", s.handleAS4)

	s.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  config.Timeout,
		WriteTimeout: config.Timeout,
		IdleTimeout:  config.IdleConnTimeout,
	}

	return s
}

// handleAS4 handles incoming AS4 messages
func (s *HTTPSServer) handleAS4(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	response, err := s.handler.HandleMessage(r.Context(), body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to process message: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

// Start starts the HTTPS server
func (s *HTTPSServer) Start() error {
	if len(s.config.Certificates) == 0 {
		return fmt.Errorf("no TLS certificates configured")
	}

	// For production, use ListenAndServeTLS with cert files
	// For now, certificates are already in TLSConfig
	return s.server.ListenAndServeTLS("", "")
}

// Shutdown gracefully shuts down the server
func (s *HTTPSServer) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
