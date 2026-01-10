package pmode

import (
	"testing"
	"time"
)

func TestNewPModeManager(t *testing.T) {
	manager := NewPModeManager()
	if manager == nil {
		t.Fatal("expected non-nil manager")
	}
	if manager.pmodes == nil {
		t.Error("expected pmodes map to be initialized")
	}
}

func TestPModeManager_AddAndGetPMode(t *testing.T) {
	manager := NewPModeManager()

	pmode := &ProcessingMode{
		ID:      "test-pmode-1",
		Service: "urn:test:service",
		Action:  "test-action",
	}

	manager.AddPMode(pmode)

	retrieved := manager.GetPMode("test-pmode-1")
	if retrieved == nil {
		t.Fatal("expected to retrieve pmode")
	}
	if retrieved.ID != "test-pmode-1" {
		t.Errorf("expected ID 'test-pmode-1', got '%s'", retrieved.ID)
	}
	if retrieved.Service != "urn:test:service" {
		t.Errorf("expected Service 'urn:test:service', got '%s'", retrieved.Service)
	}
}

func TestPModeManager_GetPMode_NotFound(t *testing.T) {
	manager := NewPModeManager()

	retrieved := manager.GetPMode("nonexistent")
	if retrieved != nil {
		t.Error("expected nil for nonexistent pmode")
	}
}

func TestPModeManager_RemovePMode(t *testing.T) {
	manager := NewPModeManager()

	pmode := &ProcessingMode{ID: "test-pmode-1"}
	manager.AddPMode(pmode)

	// Verify it exists
	if manager.GetPMode("test-pmode-1") == nil {
		t.Fatal("pmode should exist before removal")
	}

	manager.RemovePMode("test-pmode-1")

	// Verify it's gone
	if manager.GetPMode("test-pmode-1") != nil {
		t.Error("pmode should be removed")
	}
}

func TestPModeManager_FindPMode(t *testing.T) {
	manager := NewPModeManager()

	pmode1 := &ProcessingMode{
		ID:      "pmode-1",
		Service: "urn:service:a",
		Action:  "action-a",
	}
	pmode2 := &ProcessingMode{
		ID:      "pmode-2",
		Service: "urn:service:b",
		Action:  "action-b",
	}

	manager.AddPMode(pmode1)
	manager.AddPMode(pmode2)

	tests := []struct {
		name        string
		service     string
		action      string
		expectID    string
		expectFound bool
	}{
		{
			name:        "find first pmode",
			service:     "urn:service:a",
			action:      "action-a",
			expectID:    "pmode-1",
			expectFound: true,
		},
		{
			name:        "find second pmode",
			service:     "urn:service:b",
			action:      "action-b",
			expectID:    "pmode-2",
			expectFound: true,
		},
		{
			name:        "no match - wrong service",
			service:     "urn:service:c",
			action:      "action-a",
			expectFound: false,
		},
		{
			name:        "no match - wrong action",
			service:     "urn:service:a",
			action:      "action-wrong",
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found := manager.FindPMode(tt.service, tt.action, "", "")
			if tt.expectFound {
				if found == nil {
					t.Fatal("expected to find pmode")
				}
				if found.ID != tt.expectID {
					t.Errorf("expected ID '%s', got '%s'", tt.expectID, found.ID)
				}
			} else {
				if found != nil {
					t.Errorf("expected nil, got pmode with ID '%s'", found.ID)
				}
			}
		})
	}
}

func TestDefaultPMode(t *testing.T) {
	pmode := DefaultPMode()

	if pmode == nil {
		t.Fatal("expected non-nil default pmode")
	}

	// Check basic fields
	if pmode.ID != "default-pmode" {
		t.Errorf("expected ID 'default-pmode', got '%s'", pmode.ID)
	}

	if pmode.MEP == "" {
		t.Error("expected MEP to be set")
	}

	if pmode.MEPBinding == "" {
		t.Error("expected MEPBinding to be set")
	}

	// Check Protocol
	if pmode.Protocol == nil {
		t.Fatal("expected Protocol to be set")
	}
	if pmode.Protocol.SOAPVersion != "1.2" {
		t.Errorf("expected SOAP 1.2, got '%s'", pmode.Protocol.SOAPVersion)
	}

	// Check Security
	if pmode.Security == nil {
		t.Fatal("expected Security to be set")
	}
	if pmode.Security.WSSVersion != "1.1.1" {
		t.Errorf("expected WSS 1.1.1, got '%s'", pmode.Security.WSSVersion)
	}
	if pmode.Security.X509 == nil || pmode.Security.X509.Sign == nil {
		t.Error("expected X509 signing config")
	}

	// Check Reception Awareness
	if pmode.ReceptionAwareness == nil {
		t.Fatal("expected ReceptionAwareness to be set")
	}
	if !pmode.ReceptionAwareness.Enabled {
		t.Error("expected ReceptionAwareness to be enabled")
	}
	if pmode.ReceptionAwareness.Retry == nil {
		t.Fatal("expected Retry config")
	}
	if pmode.ReceptionAwareness.Retry.MaxRetries != 3 {
		t.Errorf("expected MaxRetries 3, got %d", pmode.ReceptionAwareness.Retry.MaxRetries)
	}

	// Check Payload Service
	if pmode.PayloadService == nil {
		t.Fatal("expected PayloadService to be set")
	}
	if pmode.PayloadService.CompressionType != "application/gzip" {
		t.Errorf("expected gzip compression, got '%s'", pmode.PayloadService.CompressionType)
	}

	// Check namespace and profile defaults
	if pmode.NamespaceVersion != NamespaceEBMS3 {
		t.Errorf("expected NamespaceEBMS3, got '%s'", pmode.NamespaceVersion)
	}
	if pmode.SecurityProfile != ProfileDomibus {
		t.Errorf("expected ProfileDomibus, got '%s'", pmode.SecurityProfile)
	}
}

func TestGetDefaultSignConfig(t *testing.T) {
	tests := []struct {
		name            string
		profile         SecurityProfile
		expectAlgorithm SignatureAlgorithm
		expectHash      HashAlgorithm
		expectC14N      CanonicalizationAlgorithm
	}{
		{
			name:            "AS4v2 profile uses Ed25519",
			profile:         ProfileAS4v2,
			expectAlgorithm: AlgoEd25519,
			expectHash:      HashSHA256,
			expectC14N:      C14NExclusive,
		},
		{
			name:            "Domibus profile uses RSA-SHA256",
			profile:         ProfileDomibus,
			expectAlgorithm: AlgoRSASHA256,
			expectHash:      HashSHA256,
			expectC14N:      C14NExclusive,
		},
		{
			name:            "EDelivery profile uses RSA-SHA256",
			profile:         ProfileEDelivery,
			expectAlgorithm: AlgoRSASHA256,
			expectHash:      HashSHA256,
			expectC14N:      C14NExclusive,
		},
		{
			name:            "Custom profile defaults to RSA-SHA256",
			profile:         ProfileCustom,
			expectAlgorithm: AlgoRSASHA256,
			expectHash:      HashSHA256,
			expectC14N:      C14NExclusive,
		},
		{
			name:            "Unknown profile defaults to RSA-SHA256",
			profile:         SecurityProfile("unknown"),
			expectAlgorithm: AlgoRSASHA256,
			expectHash:      HashSHA256,
			expectC14N:      C14NExclusive,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := GetDefaultSignConfig(tt.profile)
			if config == nil {
				t.Fatal("expected non-nil config")
			}
			if config.Algorithm != tt.expectAlgorithm {
				t.Errorf("expected algorithm '%s', got '%s'", tt.expectAlgorithm, config.Algorithm)
			}
			if config.HashFunction != tt.expectHash {
				t.Errorf("expected hash '%s', got '%s'", tt.expectHash, config.HashFunction)
			}
			if config.Canonicalization != tt.expectC14N {
				t.Errorf("expected C14N '%s', got '%s'", tt.expectC14N, config.Canonicalization)
			}
		})
	}
}

func TestGetDefaultEncryptionConfig(t *testing.T) {
	tests := []struct {
		name           string
		profile        SecurityProfile
		expectKeyAlgo  KeyEncryptionAlgorithm
		expectDataAlgo DataEncryptionAlgorithm
		expectKeyDeriv string
	}{
		{
			name:           "AS4v2 profile uses X25519",
			profile:        ProfileAS4v2,
			expectKeyAlgo:  KeyAlgoX25519,
			expectDataAlgo: DataAlgoAES128GCM,
			expectKeyDeriv: "HKDF-SHA256",
		},
		{
			name:           "Domibus profile uses RSA-OAEP",
			profile:        ProfileDomibus,
			expectKeyAlgo:  KeyAlgoRSAOAEP,
			expectDataAlgo: DataAlgoAES128GCM,
			expectKeyDeriv: "",
		},
		{
			name:           "EDelivery profile uses RSA-OAEP",
			profile:        ProfileEDelivery,
			expectKeyAlgo:  KeyAlgoRSAOAEP,
			expectDataAlgo: DataAlgoAES128GCM,
			expectKeyDeriv: "",
		},
		{
			name:           "Custom profile uses RSA-OAEP",
			profile:        ProfileCustom,
			expectKeyAlgo:  KeyAlgoRSAOAEP,
			expectDataAlgo: DataAlgoAES128GCM,
			expectKeyDeriv: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := GetDefaultEncryptionConfig(tt.profile)
			if config == nil {
				t.Fatal("expected non-nil config")
			}
			if config.Algorithm != tt.expectKeyAlgo {
				t.Errorf("expected key algo '%s', got '%s'", tt.expectKeyAlgo, config.Algorithm)
			}
			if config.DataEncryption != tt.expectDataAlgo {
				t.Errorf("expected data algo '%s', got '%s'", tt.expectDataAlgo, config.DataEncryption)
			}
			if config.KeyDerivation != tt.expectKeyDeriv {
				t.Errorf("expected key derivation '%s', got '%s'", tt.expectKeyDeriv, config.KeyDerivation)
			}
		})
	}
}

func TestProcessingMode_NamespaceHelpers(t *testing.T) {
	tests := []struct {
		name             string
		namespaceVersion NamespaceVersion
		expectGetNS      string
		expectIsEBMS3    bool
		expectIsAS4v2    bool
	}{
		{
			name:             "empty defaults to EBMS3",
			namespaceVersion: "",
			expectGetNS:      string(NamespaceEBMS3),
			expectIsEBMS3:    true,
			expectIsAS4v2:    false,
		},
		{
			name:             "explicit EBMS3",
			namespaceVersion: NamespaceEBMS3,
			expectGetNS:      string(NamespaceEBMS3),
			expectIsEBMS3:    true,
			expectIsAS4v2:    false,
		},
		{
			name:             "AS4v2 namespace",
			namespaceVersion: NamespaceAS4v2,
			expectGetNS:      string(NamespaceAS4v2),
			expectIsEBMS3:    false,
			expectIsAS4v2:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pmode := &ProcessingMode{
				NamespaceVersion: tt.namespaceVersion,
			}

			if got := pmode.GetNamespaceURI(); got != tt.expectGetNS {
				t.Errorf("GetNamespaceURI() = '%s', want '%s'", got, tt.expectGetNS)
			}
			if got := pmode.IsEBMS3(); got != tt.expectIsEBMS3 {
				t.Errorf("IsEBMS3() = %v, want %v", got, tt.expectIsEBMS3)
			}
			if got := pmode.IsAS4v2(); got != tt.expectIsAS4v2 {
				t.Errorf("IsAS4v2() = %v, want %v", got, tt.expectIsAS4v2)
			}
		})
	}
}

func TestConstants(t *testing.T) {
	// Verify important algorithm URIs are correct
	t.Run("signature algorithms", func(t *testing.T) {
		if AlgoRSASHA256 != "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" {
			t.Errorf("unexpected RSA-SHA256 URI: %s", AlgoRSASHA256)
		}
		if AlgoEd25519 != "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519" {
			t.Errorf("unexpected Ed25519 URI: %s", AlgoEd25519)
		}
	})

	t.Run("hash algorithms", func(t *testing.T) {
		if HashSHA256 != "http://www.w3.org/2001/04/xmlenc#sha256" {
			t.Errorf("unexpected SHA-256 URI: %s", HashSHA256)
		}
	})

	t.Run("encryption algorithms", func(t *testing.T) {
		if DataAlgoAES128GCM != "http://www.w3.org/2009/xmlenc11#aes128-gcm" {
			t.Errorf("unexpected AES-128-GCM URI: %s", DataAlgoAES128GCM)
		}
	})

	t.Run("canonicalization", func(t *testing.T) {
		if C14NExclusive != "http://www.w3.org/2001/10/xml-exc-c14n#" {
			t.Errorf("unexpected exc-c14n URI: %s", C14NExclusive)
		}
	})
}

func TestRetryConfig_Duration(t *testing.T) {
	config := &RetryConfig{
		Enabled:         true,
		MaxRetries:      5,
		RetryInterval:   30 * time.Second,
		RetryMultiplier: 2.0,
	}

	if !config.Enabled {
		t.Error("expected Enabled to be true")
	}
	if config.MaxRetries != 5 {
		t.Errorf("expected MaxRetries 5, got %d", config.MaxRetries)
	}
	if config.RetryInterval != 30*time.Second {
		t.Errorf("expected RetryInterval 30s, got %v", config.RetryInterval)
	}
	if config.RetryMultiplier != 2.0 {
		t.Errorf("expected RetryMultiplier 2.0, got %f", config.RetryMultiplier)
	}
}
