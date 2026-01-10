package discovery

import (
	"testing"
)

func TestHashPartyID(t *testing.T) {
	client := NewBDXLClient("bdxl.example.com")

	tests := []struct {
		name    string
		partyID string
		wantErr bool
		wantLen int
	}{
		{
			name:    "ebcore party ID",
			partyID: "urn:oasis:names:tc:ebcore:partyid-type:iso6523:0088:7315458756324",
			wantErr: false,
			wantLen: 52,
		},
		{
			name:    "PEPPOL party ID",
			partyID: "0088:7315458756324",
			wantErr: false,
			wantLen: 52,
		},
		{
			name:    "empty party ID",
			partyID: "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := client.hashPartyID(tt.partyID)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if len(hash) != tt.wantLen {
				t.Errorf("hash length = %d, want %d", len(hash), tt.wantLen)
			}
			if hash[len(hash)-1] == '=' {
				t.Error("hash should not have padding")
			}
		})
	}
}

func TestFormatQueryDomain(t *testing.T) {
	tests := []struct {
		name       string
		hashedID   string
		env        Environment
		domain     string
		wantSuffix string
	}{
		{
			name:       "production environment",
			hashedID:   "ABCDEF123456",
			env:        EnvProduction,
			domain:     "bdxl.example.com",
			wantSuffix: "ABCDEF123456.bdxl.example.com",
		},
		{
			name:       "acceptance environment",
			hashedID:   "ABCDEF123456",
			env:        EnvAcceptance,
			domain:     "bdxl.example.com",
			wantSuffix: "ABCDEF123456.acceptance.bdxl.example.com",
		},
		{
			name:       "test environment",
			hashedID:   "ABCDEF123456",
			env:        EnvTest,
			domain:     "bdxl.example.com",
			wantSuffix: "ABCDEF123456.test.bdxl.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewBDXLClientWithConfig(BDXLClientConfig{
				ServiceProviderDomain: tt.domain,
				Environment:           tt.env,
			})
			result := client.formatQueryDomain(tt.hashedID)
			if result != tt.wantSuffix {
				t.Errorf("formatQueryDomain() = %s, want %s", result, tt.wantSuffix)
			}
		})
	}
}

func TestFormatEbCorePartyID(t *testing.T) {
	tests := []struct {
		catalog    string
		scheme     string
		identifier string
		want       string
	}{
		{
			catalog:    "iso6523",
			scheme:     "0088",
			identifier: "7315458756324",
			want:       "urn:oasis:names:tc:ebcore:partyid-type:iso6523:0088:7315458756324",
		},
		{
			catalog:    "iso6523",
			scheme:     "0192",
			identifier: "987654321",
			want:       "urn:oasis:names:tc:ebcore:partyid-type:iso6523:0192:987654321",
		},
	}

	for _, tt := range tests {
		t.Run(tt.identifier, func(t *testing.T) {
			result := FormatEbCorePartyID(tt.catalog, tt.scheme, tt.identifier)
			if result != tt.want {
				t.Errorf("FormatEbCorePartyID() = %s, want %s", result, tt.want)
			}
		})
	}
}

func TestFormatPEPPOLPartyID(t *testing.T) {
	tests := []struct {
		scheme     string
		identifier string
		want       string
	}{
		{
			scheme:     "0088",
			identifier: "7315458756324",
			want:       "0088:7315458756324",
		},
		{
			scheme:     "0192",
			identifier: "987654321",
			want:       "0192:987654321",
		},
	}

	for _, tt := range tests {
		t.Run(tt.identifier, func(t *testing.T) {
			result := FormatPEPPOLPartyID(tt.scheme, tt.identifier)
			if result != tt.want {
				t.Errorf("FormatPEPPOLPartyID() = %s, want %s", result, tt.want)
			}
		})
	}
}

func TestParseEbCorePartyID(t *testing.T) {
	tests := []struct {
		name           string
		partyID        string
		wantCatalog    string
		wantScheme     string
		wantIdentifier string
		wantErr        bool
	}{
		{
			name:           "valid ebcore ID",
			partyID:        "urn:oasis:names:tc:ebcore:partyid-type:iso6523:0088:7315458756324",
			wantCatalog:    "iso6523",
			wantScheme:     "0088",
			wantIdentifier: "7315458756324",
			wantErr:        false,
		},
		{
			name:    "invalid format",
			partyID: "invalid:format",
			wantErr: true,
		},
		{
			name:    "missing parts",
			partyID: "urn:oasis:names:tc:ebcore:partyid-type:iso6523",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			catalog, scheme, identifier, err := ParseEbCorePartyID(tt.partyID)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if catalog != tt.wantCatalog {
				t.Errorf("catalog = %s, want %s", catalog, tt.wantCatalog)
			}
			if scheme != tt.wantScheme {
				t.Errorf("scheme = %s, want %s", scheme, tt.wantScheme)
			}
			if identifier != tt.wantIdentifier {
				t.Errorf("identifier = %s, want %s", identifier, tt.wantIdentifier)
			}
		})
	}
}

func TestParsePEPPOLPartyID(t *testing.T) {
	tests := []struct {
		name           string
		partyID        string
		wantScheme     string
		wantIdentifier string
		wantErr        bool
	}{
		{
			name:           "valid PEPPOL ID",
			partyID:        "0088:7315458756324",
			wantScheme:     "0088",
			wantIdentifier: "7315458756324",
			wantErr:        false,
		},
		{
			name:    "invalid format - no colon",
			partyID: "00887315458756324",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme, identifier, err := ParsePEPPOLPartyID(tt.partyID)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if scheme != tt.wantScheme {
				t.Errorf("scheme = %s, want %s", scheme, tt.wantScheme)
			}
			if identifier != tt.wantIdentifier {
				t.Errorf("identifier = %s, want %s", identifier, tt.wantIdentifier)
			}
		})
	}
}

func TestExtractURLFromRegexp(t *testing.T) {
	client := NewBDXLClient("bdxl.example.com")

	tests := []struct {
		name    string
		regexp  string
		want    string
		wantErr bool
	}{
		{
			name:    "standard NAPTR regexp",
			regexp:  "!.*!https://smp.example.com/!",
			want:    "https://smp.example.com/",
			wantErr: false,
		},
		{
			name:    "NAPTR regexp with path",
			regexp:  "!.*!https://smp.example.com/smp/!",
			want:    "https://smp.example.com/smp/",
			wantErr: false,
		},
		{
			name:    "HTTP URL",
			regexp:  "!.*!http://smp.example.com/!",
			want:    "http://smp.example.com/",
			wantErr: false,
		},
		{
			name:    "empty regexp",
			regexp:  "",
			wantErr: true,
		},
		{
			name:    "invalid format - too few parts",
			regexp:  "!.*!",
			wantErr: true,
		},
		{
			name:    "empty URL",
			regexp:  "!.*!!",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, err := client.extractURLFromRegexp(tt.regexp)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if url != tt.want {
				t.Errorf("extractURLFromRegexp() = %s, want %s", url, tt.want)
			}
		})
	}
}

func TestBDXLClientConfig(t *testing.T) {
	client := NewBDXLClient("bdxl.example.com")
	if client.config.PreferredService != ServiceTypeSMP2 {
		t.Errorf("default PreferredService = %s, want %s", client.config.PreferredService, ServiceTypeSMP2)
	}
	if client.config.IdentifierScheme != SchemeEbCore {
		t.Errorf("default IdentifierScheme = %s, want %s", client.config.IdentifierScheme, SchemeEbCore)
	}
	if client.config.Environment != EnvProduction {
		t.Errorf("default Environment = %s, want %s", client.config.Environment, EnvProduction)
	}

	customConfig := BDXLClientConfig{
		ServiceProviderDomain: "custom.bdxl.com",
		Environment:           EnvTest,
		PreferredService:      ServiceTypeSMP1,
		IdentifierScheme:      SchemePEPPOL,
	}
	customClient := NewBDXLClientWithConfig(customConfig)
	if customClient.config.PreferredService != ServiceTypeSMP1 {
		t.Errorf("custom PreferredService = %s, want %s", customClient.config.PreferredService, ServiceTypeSMP1)
	}
	if customClient.config.IdentifierScheme != SchemePEPPOL {
		t.Errorf("custom IdentifierScheme = %s, want %s", customClient.config.IdentifierScheme, SchemePEPPOL)
	}
}

func TestCustomDomainFormat(t *testing.T) {
	customFormat := func(hash string, env Environment, domain string) string {
		return hash + ".custom." + domain
	}

	client := NewBDXLClientWithConfig(BDXLClientConfig{
		ServiceProviderDomain: "bdxl.example.com",
		CustomDomainFormat:    customFormat,
	})

	result := client.formatQueryDomain("HASH123")
	expected := "HASH123.custom.bdxl.example.com"
	if result != expected {
		t.Errorf("custom format result = %s, want %s", result, expected)
	}
}
