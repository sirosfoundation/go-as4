package discovery

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SMP errors
var (
	// ErrParticipantNotFound is returned when the participant is not found in the SMP
	ErrParticipantNotFound = errors.New("participant not found in SMP")
	// ErrDocumentTypeNotFound is returned when the document type is not found
	ErrDocumentTypeNotFound = errors.New("document type not found")
	// ErrServiceGroupNotFound is returned when the service group is not found
	ErrServiceGroupNotFound = errors.New("service group not found")
	// ErrProcessNotFound is returned when the process is not found
	ErrProcessNotFound = errors.New("process not found")
)

// SMPVersion represents the SMP specification version
type SMPVersion int

const (
	// SMPV1 is OASIS SMP 1.0
	SMPV1 SMPVersion = 1
	// SMPV2 is OASIS SMP 2.0
	SMPV2 SMPVersion = 2
)

// SMPClientConfig contains configuration for the SMP client
type SMPClientConfig struct {
	// HTTPClient is the HTTP client to use (optional)
	// If nil, a default client with 30s timeout is used
	HTTPClient *http.Client

	// Version specifies the SMP version to use
	// Defaults to SMPV1
	Version SMPVersion

	// UserAgent is the User-Agent header to send
	UserAgent string

	// AcceptHeader specifies the Accept header
	// Defaults to "application/xml"
	AcceptHeader string
}

// SMPClient provides SMP (Service Metadata Publishing) functionality
type SMPClient struct {
	config     SMPClientConfig
	httpClient *http.Client
}

// NewSMPClient creates a new SMP client
func NewSMPClient() *SMPClient {
	return &SMPClient{
		config: SMPClientConfig{
			Version:      SMPV1,
			UserAgent:    "go-as4-smp-client/1.0",
			AcceptHeader: "application/xml",
		},
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// NewSMPClientWithConfig creates a new SMP client with custom configuration
func NewSMPClientWithConfig(config SMPClientConfig) *SMPClient {
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if config.Version == 0 {
		config.Version = SMPV1
	}
	if config.UserAgent == "" {
		config.UserAgent = "go-as4-smp-client/1.0"
	}
	if config.AcceptHeader == "" {
		config.AcceptHeader = "application/xml"
	}
	return &SMPClient{
		config:     config,
		httpClient: client,
	}
}

// ServiceGroup represents an SMP ServiceGroup
type ServiceGroup struct {
	ParticipantID     string
	ServiceReferences []string
}

// ServiceMetadata represents SMP ServiceMetadata
type ServiceMetadata struct {
	ParticipantID string
	DocumentType  string
	Processes     []ProcessMetadata
}

// ProcessMetadata represents a process within ServiceMetadata
type ProcessMetadata struct {
	ProcessID string
	Endpoints []Endpoint
}

// Endpoint represents a service endpoint
type Endpoint struct {
	// TransportProfile is the transport protocol (e.g., "bdxr-transport-ebms3-as4-v2p0")
	TransportProfile string
	// EndpointURL is the URL of the AS4 endpoint
	EndpointURL string
	// Certificate is the endpoint certificate in Base64 encoding
	Certificate string
	// ServiceActivationDate is when the service becomes active
	ServiceActivationDate *time.Time
	// ServiceExpirationDate is when the service expires
	ServiceExpirationDate *time.Time
	// TechnicalContactURL is the URL for technical contact
	TechnicalContactURL string
	// Description is a human-readable description
	Description string
}

// GetServiceGroup retrieves the ServiceGroup for a participant from an SMP.
func (c *SMPClient) GetServiceGroup(ctx context.Context, smpURL, participantID string) (*ServiceGroup, error) {
	// Construct URL: <smpURL>/<participantID>
	reqURL := c.formatServiceGroupURL(smpURL, participantID)

	body, err := c.doRequest(ctx, reqURL)
	if err != nil {
		return nil, err
	}

	return c.parseServiceGroup(body, participantID)
}

// GetServiceMetadata retrieves ServiceMetadata for a participant and document type.
func (c *SMPClient) GetServiceMetadata(ctx context.Context, smpURL, participantID, documentTypeID string) (*ServiceMetadata, error) {
	// Construct URL: <smpURL>/<participantID>/services/<documentTypeID>
	reqURL := c.formatServiceMetadataURL(smpURL, participantID, documentTypeID)

	body, err := c.doRequest(ctx, reqURL)
	if err != nil {
		return nil, err
	}

	return c.parseServiceMetadata(body)
}

// GetEndpoint retrieves the endpoint for a specific participant, document type, and process.
func (c *SMPClient) GetEndpoint(ctx context.Context, smpURL, participantID, documentTypeID, processID string) (*Endpoint, error) {
	metadata, err := c.GetServiceMetadata(ctx, smpURL, participantID, documentTypeID)
	if err != nil {
		return nil, err
	}

	for _, process := range metadata.Processes {
		if process.ProcessID == processID || processID == "" {
			if len(process.Endpoints) > 0 {
				return &process.Endpoints[0], nil
			}
		}
	}

	return nil, fmt.Errorf("%w: %s", ErrProcessNotFound, processID)
}

// formatServiceGroupURL constructs the URL for ServiceGroup lookup.
func (c *SMPClient) formatServiceGroupURL(smpURL, participantID string) string {
	base := strings.TrimRight(smpURL, "/")
	encoded := url.PathEscape(participantID)
	return fmt.Sprintf("%s/%s", base, encoded)
}

// formatServiceMetadataURL constructs the URL for ServiceMetadata lookup.
func (c *SMPClient) formatServiceMetadataURL(smpURL, participantID, documentTypeID string) string {
	base := strings.TrimRight(smpURL, "/")
	encodedParticipant := url.PathEscape(participantID)
	encodedDocType := url.PathEscape(documentTypeID)
	return fmt.Sprintf("%s/%s/services/%s", base, encodedParticipant, encodedDocType)
}

// doRequest performs an HTTP request and returns the response body.
func (c *SMPClient) doRequest(ctx context.Context, reqURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", c.config.AcceptHeader)
	req.Header.Set("User-Agent", c.config.UserAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("SMP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrParticipantNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SMP returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return body, nil
}

// SMP 1.0 XML structures
type smp10ServiceGroup struct {
	XMLName               xml.Name `xml:"ServiceGroup"`
	ParticipantIdentifier struct {
		Value  string `xml:",chardata"`
		Scheme string `xml:"scheme,attr"`
	} `xml:"ParticipantIdentifier"`
	ServiceMetadataReferenceCollection struct {
		ServiceMetadataReferences []struct {
			Href string `xml:"href,attr"`
		} `xml:"ServiceMetadataReference"`
	} `xml:"ServiceMetadataReferenceCollection"`
}

type smp10SignedServiceMetadata struct {
	XMLName         xml.Name `xml:"SignedServiceMetadata"`
	ServiceMetadata struct {
		ServiceInformation struct {
			ParticipantIdentifier struct {
				Value  string `xml:",chardata"`
				Scheme string `xml:"scheme,attr"`
			} `xml:"ParticipantIdentifier"`
			DocumentIdentifier struct {
				Value  string `xml:",chardata"`
				Scheme string `xml:"scheme,attr"`
			} `xml:"DocumentIdentifier"`
			ProcessList struct {
				Processes []struct {
					ProcessIdentifier struct {
						Value  string `xml:",chardata"`
						Scheme string `xml:"scheme,attr"`
					} `xml:"ProcessIdentifier"`
					ServiceEndpointList struct {
						Endpoints []struct {
							TransportProfile       string `xml:"transportProfile,attr"`
							EndpointURI            string `xml:"EndpointURI"`
							Certificate            string `xml:"Certificate"`
							ServiceActivationDate  string `xml:"ServiceActivationDate"`
							ServiceExpirationDate  string `xml:"ServiceExpirationDate"`
							TechnicalContactUrl    string `xml:"TechnicalContactUrl"`
							ServiceDescription     string `xml:"ServiceDescription"`
							RequireBusinessLevelSig string `xml:"RequireBusinessLevelSignature"`
						} `xml:"Endpoint"`
					} `xml:"ServiceEndpointList"`
				} `xml:"Process"`
			} `xml:"ProcessList"`
		} `xml:"ServiceInformation"`
	} `xml:"ServiceMetadata"`
}

// parseServiceGroup parses an SMP ServiceGroup response.
func (c *SMPClient) parseServiceGroup(data []byte, participantID string) (*ServiceGroup, error) {
	var sg smp10ServiceGroup
	if err := xml.Unmarshal(data, &sg); err != nil {
		return nil, fmt.Errorf("failed to parse ServiceGroup: %w", err)
	}

	result := &ServiceGroup{
		ParticipantID: participantID,
	}

	for _, ref := range sg.ServiceMetadataReferenceCollection.ServiceMetadataReferences {
		result.ServiceReferences = append(result.ServiceReferences, ref.Href)
	}

	return result, nil
}

// parseServiceMetadata parses an SMP ServiceMetadata response.
func (c *SMPClient) parseServiceMetadata(data []byte) (*ServiceMetadata, error) {
	var ssm smp10SignedServiceMetadata
	if err := xml.Unmarshal(data, &ssm); err != nil {
		return nil, fmt.Errorf("failed to parse ServiceMetadata: %w", err)
	}

	si := ssm.ServiceMetadata.ServiceInformation
	result := &ServiceMetadata{
		ParticipantID: si.ParticipantIdentifier.Value,
		DocumentType:  si.DocumentIdentifier.Value,
	}

	for _, p := range si.ProcessList.Processes {
		pm := ProcessMetadata{
			ProcessID: p.ProcessIdentifier.Value,
		}
		for _, ep := range p.ServiceEndpointList.Endpoints {
			endpoint := Endpoint{
				TransportProfile:    ep.TransportProfile,
				EndpointURL:         ep.EndpointURI,
				Certificate:         ep.Certificate,
				TechnicalContactURL: ep.TechnicalContactUrl,
				Description:         ep.ServiceDescription,
			}
			// Parse activation date
			if ep.ServiceActivationDate != "" {
				if t, err := time.Parse(time.RFC3339, ep.ServiceActivationDate); err == nil {
					endpoint.ServiceActivationDate = &t
				}
			}
			// Parse expiration date
			if ep.ServiceExpirationDate != "" {
				if t, err := time.Parse(time.RFC3339, ep.ServiceExpirationDate); err == nil {
					endpoint.ServiceExpirationDate = &t
				}
			}
			pm.Endpoints = append(pm.Endpoints, endpoint)
		}
		result.Processes = append(result.Processes, pm)
	}

	return result, nil
}

// Transport profile constants
const (
	// TransportAS4V2 is the eDelivery AS4 2.0 transport profile
	TransportAS4V2 = "bdxr-transport-ebms3-as4-v2p0"
	// TransportAS4V1 is the legacy AS4 transport profile
	TransportAS4V1 = "busdox-transport-ebms3-as4-v1p0"
	// TransportPeppolAS4 is the PEPPOL AS4 transport profile
	TransportPeppolAS4 = "peppol-transport-as4-v2_0"
)

// FilterEndpointsByTransport filters endpoints by transport profile.
func FilterEndpointsByTransport(endpoints []Endpoint, transportProfile string) []Endpoint {
	var result []Endpoint
	for _, ep := range endpoints {
		if ep.TransportProfile == transportProfile {
			result = append(result, ep)
		}
	}
	return result
}

// GetActiveEndpoints filters endpoints to only include currently active ones.
func GetActiveEndpoints(endpoints []Endpoint) []Endpoint {
	now := time.Now()
	var result []Endpoint
	for _, ep := range endpoints {
		// Check activation date
		if ep.ServiceActivationDate != nil && ep.ServiceActivationDate.After(now) {
			continue
		}
		// Check expiration date
		if ep.ServiceExpirationDate != nil && ep.ServiceExpirationDate.Before(now) {
			continue
		}
		result = append(result, ep)
	}
	return result
}
