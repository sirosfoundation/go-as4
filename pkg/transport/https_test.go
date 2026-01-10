package transport

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDefaultHTTPSConfig(t *testing.T) {
	config := DefaultHTTPSConfig()

	if config == nil {
		t.Fatal("expected non-nil config")
	}

	if config.MinTLSVersion != TLS12 {
		t.Errorf("expected MinTLSVersion TLS12, got %d", config.MinTLSVersion)
	}
	if config.MaxTLSVersion != TLS13 {
		t.Errorf("expected MaxTLSVersion TLS13, got %d", config.MaxTLSVersion)
	}
	if len(config.CipherSuites) == 0 {
		t.Error("expected CipherSuites to be set")
	}
	if config.ClientAuth != tls.NoClientCert {
		t.Errorf("expected NoClientCert, got %d", config.ClientAuth)
	}
	if config.Timeout != 30*time.Second {
		t.Errorf("expected Timeout 30s, got %v", config.Timeout)
	}
	if config.IdleConnTimeout != 90*time.Second {
		t.Errorf("expected IdleConnTimeout 90s, got %v", config.IdleConnTimeout)
	}
}

func TestRecommendedTLS12CipherSuites(t *testing.T) {
	if len(RecommendedTLS12CipherSuites) == 0 {
		t.Error("expected recommended cipher suites to be defined")
	}

	// Check that all cipher suites are valid TLS 1.2 ECDHE suites
	for _, suite := range RecommendedTLS12CipherSuites {
		name := tls.CipherSuiteName(suite)
		if name == "" {
			t.Errorf("unknown cipher suite: %d", suite)
		}
	}
}

func TestNewHTTPSClient_NilConfig(t *testing.T) {
	client := NewHTTPSClient(nil)

	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.client == nil {
		t.Error("expected http.Client to be initialized")
	}
	if client.config == nil {
		t.Error("expected config to be set to default")
	}
}

func TestNewHTTPSClient_CustomConfig(t *testing.T) {
	config := &HTTPSConfig{
		MinTLSVersion:   TLS13,
		MaxTLSVersion:   TLS13,
		Timeout:         60 * time.Second,
		IdleConnTimeout: 120 * time.Second,
	}

	client := NewHTTPSClient(config)

	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.config.MinTLSVersion != TLS13 {
		t.Error("expected custom MinTLSVersion")
	}
	if client.config.Timeout != 60*time.Second {
		t.Error("expected custom Timeout")
	}
}

func TestHTTPSClient_Send(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/soap+xml" {
			t.Errorf("expected content-type 'application/soap+xml', got '%s'", ct)
		}
		if r.Header.Get("User-Agent") != "go-as4/1.0" {
			t.Errorf("expected User-Agent 'go-as4/1.0'")
		}

		w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<Response/>"))
	}))
	defer server.Close()

	client := NewHTTPSClient(nil)

	response, err := client.Send(context.Background(), server.URL, []byte("<Request/>"), "application/soap+xml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(response) != "<Response/>" {
		t.Errorf("unexpected response: %s", string(response))
	}
}

func TestHTTPSClient_Send_ErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	client := NewHTTPSClient(nil)

	_, err := client.Send(context.Background(), server.URL, []byte("<Request/>"), "application/soap+xml")
	if err == nil {
		t.Error("expected error for non-200 status")
	}
}

func TestHTTPSClient_Send_InvalidURL(t *testing.T) {
	client := NewHTTPSClient(nil)

	_, err := client.Send(context.Background(), "http://invalid.invalid.invalid:99999", []byte("<Request/>"), "application/soap+xml")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestHTTPSClient_Send_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // Simulate slow response
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewHTTPSClient(&HTTPSConfig{
		Timeout: 10 * time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := client.Send(ctx, server.URL, []byte("<Request/>"), "application/soap+xml")
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestNewHTTPSServer_NilConfig(t *testing.T) {
	handler := &mockAS4Handler{}
	server := NewHTTPSServer(":8443", nil, handler)

	if server == nil {
		t.Fatal("expected non-nil server")
	}
	if server.config == nil {
		t.Error("expected config to be set to default")
	}
	if server.handler != handler {
		t.Error("expected handler to be set")
	}
}

func TestNewHTTPSServer_CustomConfig(t *testing.T) {
	config := &HTTPSConfig{
		MinTLSVersion: TLS13,
		Timeout:       60 * time.Second,
	}
	handler := &mockAS4Handler{}

	server := NewHTTPSServer(":8443", config, handler)

	if server == nil {
		t.Fatal("expected non-nil server")
	}
	if server.config.MinTLSVersion != TLS13 {
		t.Error("expected custom config")
	}
}

func TestHTTPSServer_handleAS4_MethodNotAllowed(t *testing.T) {
	handler := &mockAS4Handler{}
	server := NewHTTPSServer(":8443", nil, handler)

	// Create request with wrong method
	req := httptest.NewRequest(http.MethodGet, "/as4", nil)
	w := httptest.NewRecorder()

	server.handleAS4(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

func TestHTTPSServer_handleAS4_Success(t *testing.T) {
	handler := &mockAS4Handler{
		response: []byte("<Receipt/>"),
	}
	server := NewHTTPSServer(":8443", nil, handler)

	req := httptest.NewRequest(http.MethodPost, "/as4", nil)
	req.Body = http.NoBody
	w := httptest.NewRecorder()

	server.handleAS4(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/soap+xml; charset=utf-8" {
		t.Errorf("expected content-type 'application/soap+xml; charset=utf-8', got '%s'", ct)
	}
}

func TestHTTPSServer_handleAS4_HandlerError(t *testing.T) {
	handler := &mockAS4Handler{
		err: http.ErrAbortHandler,
	}
	server := NewHTTPSServer(":8443", nil, handler)

	req := httptest.NewRequest(http.MethodPost, "/as4", nil)
	req.Body = http.NoBody
	w := httptest.NewRecorder()

	server.handleAS4(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", w.Code)
	}
}

func TestHTTPSServer_Start_NoCertificates(t *testing.T) {
	server := NewHTTPSServer(":0", &HTTPSConfig{}, nil)

	err := server.Start()
	if err == nil {
		t.Error("expected error when no certificates configured")
	}
}

func TestHTTPSConfig_Fields(t *testing.T) {
	config := &HTTPSConfig{
		MinTLSVersion:   TLS12,
		MaxTLSVersion:   TLS13,
		CipherSuites:    RecommendedTLS12CipherSuites,
		ClientAuth:      tls.RequireAndVerifyClientCert,
		Timeout:         45 * time.Second,
		IdleConnTimeout: 60 * time.Second,
	}

	if config.MinTLSVersion != TLS12 {
		t.Error("MinTLSVersion mismatch")
	}
	if config.MaxTLSVersion != TLS13 {
		t.Error("MaxTLSVersion mismatch")
	}
	if config.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Error("ClientAuth mismatch")
	}
}

func TestTLSConstants(t *testing.T) {
	if TLS12 != tls.VersionTLS12 {
		t.Errorf("TLS12 constant mismatch")
	}
	if TLS13 != tls.VersionTLS13 {
		t.Errorf("TLS13 constant mismatch")
	}
}

// mockAS4Handler is a test implementation of AS4Handler
type mockAS4Handler struct {
	response []byte
	err      error
}

func (h *mockAS4Handler) HandleMessage(ctx context.Context, message []byte) ([]byte, error) {
	if h.err != nil {
		return nil, h.err
	}
	return h.response, nil
}
