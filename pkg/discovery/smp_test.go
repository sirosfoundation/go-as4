package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSMPClientConfig(t *testing.T) {
	// Test default values
	client := NewSMPClient()
	if client.config.Version != SMPV1 {
		t.Errorf("default Version = %d, want %d", client.config.Version, SMPV1)
	}
	if client.config.UserAgent != "go-as4-smp-client/1.0" {
		t.Errorf("default UserAgent = %s, want go-as4-smp-client/1.0", client.config.UserAgent)
	}
	if client.config.AcceptHeader != "application/xml" {
		t.Errorf("default AcceptHeader = %s, want application/xml", client.config.AcceptHeader)
	}
}

func TestSMPFormatURLs(t *testing.T) {
	client := NewSMPClient()

	tests := []struct {
		name          string
		smpURL        string
		participantID string
		documentType  string
		wantSG        string
		wantSM        string
	}{
		{
			name:          "simple URL",
			smpURL:        "https://smp.example.com",
			participantID: "0088:1234567890",
			documentType:  "urn:oasis:names:tc:ebcore:partyid-type:iso6523:0088",
			wantSG:        "https://smp.example.com/0088:1234567890",
			wantSM:        "https://smp.example.com/0088:1234567890/services/urn:oasis:names:tc:ebcore:partyid-type:iso6523:0088",
		},
		{
			name:          "URL with trailing slash",
			smpURL:        "https://smp.example.com/",
			participantID: "0088:1234567890",
			documentType:  "doc-type",
			wantSG:        "https://smp.example.com/0088:1234567890",
			wantSM:        "https://smp.example.com/0088:1234567890/services/doc-type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sg := client.formatServiceGroupURL(tt.smpURL, tt.participantID)
			if sg != tt.wantSG {
				t.Errorf("formatServiceGroupURL() = %s, want %s", sg, tt.wantSG)
			}

			sm := client.formatServiceMetadataURL(tt.smpURL, tt.participantID, tt.documentType)
			if sm != tt.wantSM {
				t.Errorf("formatServiceMetadataURL() = %s, want %s", sm, tt.wantSM)
			}
		})
	}
}

func TestParseServiceGroup(t *testing.T) {
	client := NewSMPClient()

	xml := `<?xml version="1.0" encoding="UTF-8"?>
<ServiceGroup xmlns="http://busdox.org/serviceMetadata/publishing/1.0/">
  <ParticipantIdentifier scheme="iso6523-actorid-upis">0088:7315458756324</ParticipantIdentifier>
  <ServiceMetadataReferenceCollection>
    <ServiceMetadataReference href="https://smp.example.com/0088%3A7315458756324/services/urn%3Aoasis%3Anames%3Aspecification%3Aubl%3Aschema%3Axsd%3AInvoice-2%3A%3AInvoice%23%23urn%3Awww.cenbii.eu%3Atransaction%3Abiicoretrdm010%3Aver1.0%3Aextended%3Aurn%3Awww.peppol.eu%3Abis%3Apeppol4a%3Aver1.0%3A%3A2.0"/>
    <ServiceMetadataReference href="https://smp.example.com/0088%3A7315458756324/services/urn%3Aoasis%3Anames%3Aspecification%3Aubl%3Aschema%3Axsd%3AOrder-2%3A%3AOrder"/>
  </ServiceMetadataReferenceCollection>
</ServiceGroup>`

	sg, err := client.parseServiceGroup([]byte(xml), "0088:7315458756324")
	if err != nil {
		t.Fatalf("parseServiceGroup() error = %v", err)
	}

	if sg.ParticipantID != "0088:7315458756324" {
		t.Errorf("ParticipantID = %s, want 0088:7315458756324", sg.ParticipantID)
	}

	if len(sg.ServiceReferences) != 2 {
		t.Errorf("ServiceReferences count = %d, want 2", len(sg.ServiceReferences))
	}
}

func TestParseServiceMetadata(t *testing.T) {
	client := NewSMPClient()

	xml := `<?xml version="1.0" encoding="UTF-8"?>
<SignedServiceMetadata xmlns="http://busdox.org/serviceMetadata/publishing/1.0/">
  <ServiceMetadata>
    <ServiceInformation>
      <ParticipantIdentifier scheme="iso6523-actorid-upis">0088:7315458756324</ParticipantIdentifier>
      <DocumentIdentifier scheme="busdox-docid-qns">urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice</DocumentIdentifier>
      <ProcessList>
        <Process>
          <ProcessIdentifier scheme="cenbii-procid-ubl">urn:www.cenbii.eu:profile:bii04:ver1.0</ProcessIdentifier>
          <ServiceEndpointList>
            <Endpoint transportProfile="bdxr-transport-ebms3-as4-v2p0">
              <EndpointURI>https://ap.example.com/as4</EndpointURI>
              <Certificate>MIICxTCCAa2gAwIBAgI...</Certificate>
              <ServiceActivationDate>2024-01-01T00:00:00Z</ServiceActivationDate>
              <ServiceExpirationDate>2025-12-31T23:59:59Z</ServiceExpirationDate>
              <TechnicalContactUrl>mailto:support@example.com</TechnicalContactUrl>
              <ServiceDescription>Production AS4 endpoint</ServiceDescription>
            </Endpoint>
          </ServiceEndpointList>
        </Process>
      </ProcessList>
    </ServiceInformation>
  </ServiceMetadata>
</SignedServiceMetadata>`

	sm, err := client.parseServiceMetadata([]byte(xml))
	if err != nil {
		t.Fatalf("parseServiceMetadata() error = %v", err)
	}

	if sm.ParticipantID != "0088:7315458756324" {
		t.Errorf("ParticipantID = %s, want 0088:7315458756324", sm.ParticipantID)
	}

	if sm.DocumentType != "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice" {
		t.Errorf("DocumentType = %s, want Invoice-2", sm.DocumentType)
	}

	if len(sm.Processes) != 1 {
		t.Fatalf("Processes count = %d, want 1", len(sm.Processes))
	}

	process := sm.Processes[0]
	if process.ProcessID != "urn:www.cenbii.eu:profile:bii04:ver1.0" {
		t.Errorf("ProcessID = %s, want urn:www.cenbii.eu:profile:bii04:ver1.0", process.ProcessID)
	}

	if len(process.Endpoints) != 1 {
		t.Fatalf("Endpoints count = %d, want 1", len(process.Endpoints))
	}

	endpoint := process.Endpoints[0]
	if endpoint.TransportProfile != TransportAS4V2 {
		t.Errorf("TransportProfile = %s, want %s", endpoint.TransportProfile, TransportAS4V2)
	}
	if endpoint.EndpointURL != "https://ap.example.com/as4" {
		t.Errorf("EndpointURL = %s, want https://ap.example.com/as4", endpoint.EndpointURL)
	}
	if endpoint.ServiceActivationDate == nil {
		t.Error("ServiceActivationDate should not be nil")
	}
	if endpoint.ServiceExpirationDate == nil {
		t.Error("ServiceExpirationDate should not be nil")
	}
}

func TestSMPClientHTTPRequest(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify headers
		if r.Header.Get("Accept") != "application/xml" {
			t.Errorf("Accept header = %s, want application/xml", r.Header.Get("Accept"))
		}
		if r.Header.Get("User-Agent") != "go-as4-smp-client/1.0" {
			t.Errorf("User-Agent header = %s, want go-as4-smp-client/1.0", r.Header.Get("User-Agent"))
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<?xml version="1.0"?><ServiceGroup><ParticipantIdentifier>test</ParticipantIdentifier><ServiceMetadataReferenceCollection></ServiceMetadataReferenceCollection></ServiceGroup>`))
	}))
	defer server.Close()

	client := NewSMPClient()
	sg, err := client.GetServiceGroup(context.Background(), server.URL, "test-participant")
	if err != nil {
		t.Fatalf("GetServiceGroup() error = %v", err)
	}
	if sg == nil {
		t.Error("ServiceGroup should not be nil")
	}
}

func TestSMPClientNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewSMPClient()
	_, err := client.GetServiceGroup(context.Background(), server.URL, "unknown-participant")
	if err != ErrParticipantNotFound {
		t.Errorf("expected ErrParticipantNotFound, got %v", err)
	}
}

func TestFilterEndpointsByTransport(t *testing.T) {
	endpoints := []Endpoint{
		{TransportProfile: TransportAS4V2, EndpointURL: "https://ap1.example.com/as4"},
		{TransportProfile: TransportAS4V1, EndpointURL: "https://ap2.example.com/as4"},
		{TransportProfile: TransportAS4V2, EndpointURL: "https://ap3.example.com/as4"},
		{TransportProfile: TransportPeppolAS4, EndpointURL: "https://ap4.example.com/as4"},
	}

	filtered := FilterEndpointsByTransport(endpoints, TransportAS4V2)
	if len(filtered) != 2 {
		t.Errorf("filtered count = %d, want 2", len(filtered))
	}

	for _, ep := range filtered {
		if ep.TransportProfile != TransportAS4V2 {
			t.Errorf("endpoint transport = %s, want %s", ep.TransportProfile, TransportAS4V2)
		}
	}
}

func TestGetActiveEndpoints(t *testing.T) {
	now := time.Now()
	past := now.Add(-24 * time.Hour)
	future := now.Add(24 * time.Hour)
	farFuture := now.Add(365 * 24 * time.Hour)

	endpoints := []Endpoint{
		{EndpointURL: "https://active.example.com", ServiceActivationDate: &past, ServiceExpirationDate: &farFuture},
		{EndpointURL: "https://expired.example.com", ServiceActivationDate: &past, ServiceExpirationDate: &past},
		{EndpointURL: "https://not-yet-active.example.com", ServiceActivationDate: &future, ServiceExpirationDate: &farFuture},
		{EndpointURL: "https://no-dates.example.com"},
	}

	active := GetActiveEndpoints(endpoints)
	if len(active) != 2 {
		t.Errorf("active count = %d, want 2", len(active))
	}

	// Should have the active endpoint and the one with no dates
	urls := make(map[string]bool)
	for _, ep := range active {
		urls[ep.EndpointURL] = true
	}

	if !urls["https://active.example.com"] {
		t.Error("active endpoint should be included")
	}
	if !urls["https://no-dates.example.com"] {
		t.Error("endpoint with no dates should be included")
	}
	if urls["https://expired.example.com"] {
		t.Error("expired endpoint should not be included")
	}
	if urls["https://not-yet-active.example.com"] {
		t.Error("not-yet-active endpoint should not be included")
	}
}

func TestSMPClientWithCustomConfig(t *testing.T) {
	customClient := NewSMPClientWithConfig(SMPClientConfig{
		Version:      SMPV2,
		UserAgent:    "custom-client/2.0",
		AcceptHeader: "application/json",
	})

	if customClient.config.Version != SMPV2 {
		t.Errorf("Version = %d, want %d", customClient.config.Version, SMPV2)
	}
	if customClient.config.UserAgent != "custom-client/2.0" {
		t.Errorf("UserAgent = %s, want custom-client/2.0", customClient.config.UserAgent)
	}
	if customClient.config.AcceptHeader != "application/json" {
		t.Errorf("AcceptHeader = %s, want application/json", customClient.config.AcceptHeader)
	}
}
