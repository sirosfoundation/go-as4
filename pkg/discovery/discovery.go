package discovery

import (
	"context"
	"fmt"
)

// DiscoveryClient combines BDXL and SMP discovery into a unified interface.
// It provides high-level discovery operations that automatically:
// 1. Discover the SMP URL via BDXL DNS lookup
// 2. Query the SMP for service metadata
// 3. Find the appropriate endpoint
type DiscoveryClient struct {
	bdxl *BDXLClient
	smp  *SMPClient
}

// DiscoveryConfig contains configuration for the discovery client
type DiscoveryConfig struct {
	// BDXLConfig is the configuration for BDXL discovery
	BDXLConfig BDXLClientConfig

	// SMPConfig is the configuration for SMP queries
	SMPConfig SMPClientConfig
}

// NewDiscoveryClient creates a new discovery client with the given service provider domain.
func NewDiscoveryClient(serviceProviderDomain string) *DiscoveryClient {
	return &DiscoveryClient{
		bdxl: NewBDXLClient(serviceProviderDomain),
		smp:  NewSMPClient(),
	}
}

// NewDiscoveryClientWithConfig creates a new discovery client with custom configuration.
func NewDiscoveryClientWithConfig(config DiscoveryConfig) *DiscoveryClient {
	return &DiscoveryClient{
		bdxl: NewBDXLClientWithConfig(config.BDXLConfig),
		smp:  NewSMPClientWithConfig(config.SMPConfig),
	}
}

// DiscoverEndpoint performs full dynamic discovery to find an AS4 endpoint.
// Steps:
//  1. Use BDXL to find the SMP URL for the party
//  2. Query the SMP for service metadata for the document type
//  3. Find the endpoint for the specified process
//
// Parameters:
//   - partyID: The party identifier (ebCore or PEPPOL format)
//   - documentTypeID: The document type identifier
//   - processID: The process identifier (use "" for any process)
//
// Returns the discovered endpoint or an error.
func (c *DiscoveryClient) DiscoverEndpoint(ctx context.Context, partyID, documentTypeID, processID string) (*Endpoint, error) {
	// Step 1: Discover SMP URL via BDXL
	smpURL, err := c.bdxl.DiscoverSMP(ctx, partyID)
	if err != nil {
		return nil, fmt.Errorf("BDXL discovery failed: %w", err)
	}

	// Step 2 & 3: Get endpoint from SMP
	endpoint, err := c.smp.GetEndpoint(ctx, smpURL, partyID, documentTypeID, processID)
	if err != nil {
		return nil, fmt.Errorf("SMP lookup failed: %w", err)
	}

	return endpoint, nil
}

// DiscoverEndpointWithSMP performs discovery when the SMP URL is already known.
// This skips the BDXL lookup and queries the SMP directly.
func (c *DiscoveryClient) DiscoverEndpointWithSMP(ctx context.Context, smpURL, partyID, documentTypeID, processID string) (*Endpoint, error) {
	return c.smp.GetEndpoint(ctx, smpURL, partyID, documentTypeID, processID)
}

// DiscoverAllEndpoints discovers all endpoints for a party and document type.
// Returns all endpoints for all processes.
func (c *DiscoveryClient) DiscoverAllEndpoints(ctx context.Context, partyID, documentTypeID string) ([]Endpoint, error) {
	// Step 1: Discover SMP URL via BDXL
	smpURL, err := c.bdxl.DiscoverSMP(ctx, partyID)
	if err != nil {
		return nil, fmt.Errorf("BDXL discovery failed: %w", err)
	}

	// Step 2: Get service metadata from SMP
	metadata, err := c.smp.GetServiceMetadata(ctx, smpURL, partyID, documentTypeID)
	if err != nil {
		return nil, fmt.Errorf("SMP lookup failed: %w", err)
	}

	// Step 3: Collect all endpoints
	var endpoints []Endpoint
	for _, process := range metadata.Processes {
		endpoints = append(endpoints, process.Endpoints...)
	}

	return endpoints, nil
}

// DiscoverAS4Endpoint discovers an AS4 endpoint, preferring AS4 2.0 transport.
// It filters the available endpoints by transport profile.
func (c *DiscoveryClient) DiscoverAS4Endpoint(ctx context.Context, partyID, documentTypeID, processID string) (*Endpoint, error) {
	endpoints, err := c.discoverEndpointsForProcess(ctx, partyID, documentTypeID, processID)
	if err != nil {
		return nil, err
	}

	// Filter and prioritize by transport profile
	// Preference: AS4 v2.0 > PEPPOL AS4 > AS4 v1.0
	profiles := []string{TransportAS4V2, TransportPeppolAS4, TransportAS4V1}

	for _, profile := range profiles {
		filtered := FilterEndpointsByTransport(endpoints, profile)
		active := GetActiveEndpoints(filtered)
		if len(active) > 0 {
			return &active[0], nil
		}
	}

	// If no AS4 endpoint found, return first active endpoint
	active := GetActiveEndpoints(endpoints)
	if len(active) > 0 {
		return &active[0], nil
	}

	return nil, ErrServiceNotFound
}

// discoverEndpointsForProcess is a helper that discovers endpoints for a specific process.
func (c *DiscoveryClient) discoverEndpointsForProcess(ctx context.Context, partyID, documentTypeID, processID string) ([]Endpoint, error) {
	// Step 1: Discover SMP URL via BDXL
	smpURL, err := c.bdxl.DiscoverSMP(ctx, partyID)
	if err != nil {
		return nil, fmt.Errorf("BDXL discovery failed: %w", err)
	}

	// Step 2: Get service metadata from SMP
	metadata, err := c.smp.GetServiceMetadata(ctx, smpURL, partyID, documentTypeID)
	if err != nil {
		return nil, fmt.Errorf("SMP lookup failed: %w", err)
	}

	// Step 3: Find endpoints for the process
	var endpoints []Endpoint
	for _, process := range metadata.Processes {
		if processID == "" || process.ProcessID == processID {
			endpoints = append(endpoints, process.Endpoints...)
		}
	}

	if len(endpoints) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrProcessNotFound, processID)
	}

	return endpoints, nil
}

// ListDocumentTypes lists all document types registered for a party.
func (c *DiscoveryClient) ListDocumentTypes(ctx context.Context, partyID string) ([]string, error) {
	// Step 1: Discover SMP URL via BDXL
	smpURL, err := c.bdxl.DiscoverSMP(ctx, partyID)
	if err != nil {
		return nil, fmt.Errorf("BDXL discovery failed: %w", err)
	}

	// Step 2: Get service group from SMP
	serviceGroup, err := c.smp.GetServiceGroup(ctx, smpURL, partyID)
	if err != nil {
		return nil, fmt.Errorf("SMP lookup failed: %w", err)
	}

	return serviceGroup.ServiceReferences, nil
}

// BDXLClient returns the underlying BDXL client for advanced usage.
func (c *DiscoveryClient) BDXLClient() *BDXLClient {
	return c.bdxl
}

// SMPClient returns the underlying SMP client for advanced usage.
func (c *DiscoveryClient) SMPClient() *SMPClient {
	return c.smp
}
