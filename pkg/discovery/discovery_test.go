package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoveryClientConstruction(t *testing.T) {
	// Test simple construction
	client := NewDiscoveryClient("bdxl.example.com")
	if client.bdxl == nil {
		t.Error("BDXL client should not be nil")
	}
	if client.smp == nil {
		t.Error("SMP client should not be nil")
	}

	// Test with config
	config := DiscoveryConfig{
		BDXLConfig: BDXLClientConfig{
			ServiceProviderDomain: "custom.bdxl.com",
			Environment:           EnvTest,
		},
		SMPConfig: SMPClientConfig{
			Version:   SMPV2,
			UserAgent: "test-client",
		},
	}
	customClient := NewDiscoveryClientWithConfig(config)
	if customClient.bdxl.config.ServiceProviderDomain != "custom.bdxl.com" {
		t.Error("BDXL config not applied")
	}
	if customClient.smp.config.Version != SMPV2 {
		t.Error("SMP config not applied")
	}
}

func TestDiscoveryClientAccessors(t *testing.T) {
	client := NewDiscoveryClient("bdxl.example.com")

	bdxl := client.BDXLClient()
	if bdxl == nil {
		t.Error("BDXLClient() should not return nil")
	}

	smp := client.SMPClient()
	if smp == nil {
		t.Error("SMPClient() should not return nil")
	}
}

func TestDiscoverEndpointWithSMP(t *testing.T) {
	// Create a mock SMP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xml := `<?xml version="1.0" encoding="UTF-8"?>
<SignedServiceMetadata xmlns="http://busdox.org/serviceMetadata/publishing/1.0/">
  <ServiceMetadata>
    <ServiceInformation>
      <ParticipantIdentifier scheme="iso6523-actorid-upis">0088:7315458756324</ParticipantIdentifier>
      <DocumentIdentifier scheme="busdox-docid-qns">urn:test:document</DocumentIdentifier>
      <ProcessList>
        <Process>
          <ProcessIdentifier scheme="cenbii-procid-ubl">urn:test:process</ProcessIdentifier>
          <ServiceEndpointList>
            <Endpoint transportProfile="bdxr-transport-ebms3-as4-v2p0">
              <EndpointURI>https://ap.example.com/as4</EndpointURI>
              <Certificate>BASE64CERT</Certificate>
            </Endpoint>
          </ServiceEndpointList>
        </Process>
      </ProcessList>
    </ServiceInformation>
  </ServiceMetadata>
</SignedServiceMetadata>`
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(xml))
	}))
	defer server.Close()

	client := NewDiscoveryClient("bdxl.example.com")
	endpoint, err := client.DiscoverEndpointWithSMP(
		context.Background(),
		server.URL,
		"0088:7315458756324",
		"urn:test:document",
		"urn:test:process",
	)
	if err != nil {
		t.Fatalf("DiscoverEndpointWithSMP() error = %v", err)
	}

	if endpoint == nil {
		t.Fatal("endpoint should not be nil")
	}
	if endpoint.EndpointURL != "https://ap.example.com/as4" {
		t.Errorf("EndpointURL = %s, want https://ap.example.com/as4", endpoint.EndpointURL)
	}
	if endpoint.TransportProfile != TransportAS4V2 {
		t.Errorf("TransportProfile = %s, want %s", endpoint.TransportProfile, TransportAS4V2)
	}
}

func TestDiscoverEndpointWithSMP_AnyProcess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xml := `<?xml version="1.0" encoding="UTF-8"?>
<SignedServiceMetadata xmlns="http://busdox.org/serviceMetadata/publishing/1.0/">
  <ServiceMetadata>
    <ServiceInformation>
      <ParticipantIdentifier>test</ParticipantIdentifier>
      <DocumentIdentifier>doc</DocumentIdentifier>
      <ProcessList>
        <Process>
          <ProcessIdentifier>process1</ProcessIdentifier>
          <ServiceEndpointList>
            <Endpoint transportProfile="as4">
              <EndpointURI>https://endpoint1.example.com</EndpointURI>
            </Endpoint>
          </ServiceEndpointList>
        </Process>
      </ProcessList>
    </ServiceInformation>
  </ServiceMetadata>
</SignedServiceMetadata>`
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(xml))
	}))
	defer server.Close()

	client := NewDiscoveryClient("bdxl.example.com")
	// Test with empty processID to get any process
	endpoint, err := client.DiscoverEndpointWithSMP(
		context.Background(),
		server.URL,
		"test",
		"doc",
		"", // any process
	)
	if err != nil {
		t.Fatalf("DiscoverEndpointWithSMP() error = %v", err)
	}

	if endpoint.EndpointURL != "https://endpoint1.example.com" {
		t.Errorf("EndpointURL = %s, want https://endpoint1.example.com", endpoint.EndpointURL)
	}
}

func TestDiscoverEndpointWithSMP_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewDiscoveryClient("bdxl.example.com")
	_, err := client.DiscoverEndpointWithSMP(
		context.Background(),
		server.URL,
		"unknown",
		"doc",
		"process",
	)
	if err == nil {
		t.Error("expected error for not found")
	}
}

func TestListDocumentTypesWithSMP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xml := `<?xml version="1.0"?>
<ServiceGroup>
  <ParticipantIdentifier>test</ParticipantIdentifier>
  <ServiceMetadataReferenceCollection>
    <ServiceMetadataReference href="https://smp.example.com/services/doc1"/>
    <ServiceMetadataReference href="https://smp.example.com/services/doc2"/>
    <ServiceMetadataReference href="https://smp.example.com/services/doc3"/>
  </ServiceMetadataReferenceCollection>
</ServiceGroup>`
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(xml))
	}))
	defer server.Close()

	// We can't test ListDocumentTypes directly without BDXL, but we can test the SMP part
	client := NewSMPClient()
	sg, err := client.GetServiceGroup(context.Background(), server.URL, "test")
	if err != nil {
		t.Fatalf("GetServiceGroup() error = %v", err)
	}

	if len(sg.ServiceReferences) != 3 {
		t.Errorf("ServiceReferences count = %d, want 3", len(sg.ServiceReferences))
	}
}
