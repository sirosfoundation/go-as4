package as4

import (
	"testing"

	"github.com/sirosfoundation/go-as4/pkg/pmode"
	"github.com/sirosfoundation/go-as4/pkg/security"
	"github.com/sirosfoundation/go-as4/pkg/transport"
)

func TestNewClient_NilConfig(t *testing.T) {
	client, err := NewClient(nil)
	if err == nil {
		t.Error("expected error for nil config")
	}
	if client != nil {
		t.Error("expected nil client for nil config")
	}
}

func TestNewClient_ValidConfig(t *testing.T) {
	config := &ClientConfig{
		HTTPSConfig:    transport.DefaultHTTPSConfig(),
		SecurityConfig: &security.SecurityConfig{},
		PMode:          pmode.DefaultPMode(),
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.httpClient == nil {
		t.Error("expected httpClient to be initialized")
	}
	if client.pmodeManager == nil {
		t.Error("expected pmodeManager to be initialized")
	}
	if client.tracker == nil {
		t.Error("expected tracker to be initialized")
	}
	if client.compressor == nil {
		t.Error("expected compressor to be initialized")
	}
}

func TestNewClient_ConfigWithoutPMode(t *testing.T) {
	config := &ClientConfig{
		HTTPSConfig:    transport.DefaultHTTPSConfig(),
		SecurityConfig: &security.SecurityConfig{},
		// No PMode
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestNewClient_ConfigWithNilHTTPSConfig(t *testing.T) {
	config := &ClientConfig{
		HTTPSConfig: nil, // Will use default
		PMode:       pmode.DefaultPMode(),
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestNewServer_NilConfig(t *testing.T) {
	server, err := NewServer(nil)
	if err == nil {
		t.Error("expected error for nil config")
	}
	if server != nil {
		t.Error("expected nil server for nil config")
	}
}

func TestNewServer_ValidConfig(t *testing.T) {
	config := &ServerConfig{
		Address:        ":8443",
		HTTPSConfig:    transport.DefaultHTTPSConfig(),
		SecurityConfig: &security.SecurityConfig{},
		PModeManager:   pmode.NewPModeManager(),
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if server == nil {
		t.Fatal("expected non-nil server")
	}
	if server.tracker == nil {
		t.Error("expected tracker to be initialized")
	}
	if server.compressor == nil {
		t.Error("expected compressor to be initialized")
	}
	if server.httpServer == nil {
		t.Error("expected httpServer to be initialized")
	}
}

func TestNewServer_ConfigWithNilHTTPSConfig(t *testing.T) {
	config := &ServerConfig{
		Address:      ":8443",
		HTTPSConfig:  nil, // Will use default
		PModeManager: pmode.NewPModeManager(),
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if server == nil {
		t.Fatal("expected non-nil server")
	}
}

func TestClientConfig_Fields(t *testing.T) {
	httpsConfig := transport.DefaultHTTPSConfig()
	secConfig := &security.SecurityConfig{}
	pm := pmode.DefaultPMode()

	config := &ClientConfig{
		HTTPSConfig:    httpsConfig,
		SecurityConfig: secConfig,
		PMode:          pm,
	}

	if config.HTTPSConfig != httpsConfig {
		t.Error("HTTPSConfig mismatch")
	}
	if config.SecurityConfig != secConfig {
		t.Error("SecurityConfig mismatch")
	}
	if config.PMode != pm {
		t.Error("PMode mismatch")
	}
}

func TestServerConfig_Fields(t *testing.T) {
	httpsConfig := transport.DefaultHTTPSConfig()
	secConfig := &security.SecurityConfig{}
	pmManager := pmode.NewPModeManager()

	config := &ServerConfig{
		Address:        ":8443",
		HTTPSConfig:    httpsConfig,
		SecurityConfig: secConfig,
		PModeManager:   pmManager,
	}

	if config.Address != ":8443" {
		t.Error("Address mismatch")
	}
	if config.HTTPSConfig != httpsConfig {
		t.Error("HTTPSConfig mismatch")
	}
	if config.SecurityConfig != secConfig {
		t.Error("SecurityConfig mismatch")
	}
	if config.PModeManager != pmManager {
		t.Error("PModeManager mismatch")
	}
}
