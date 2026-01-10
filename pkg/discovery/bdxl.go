package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/miekg/dns"
)

// Common errors
var (
	// ErrNoRecordsFound is returned when no U-NAPTR records are found for the party
	ErrNoRecordsFound = errors.New("no BDXL records found for party identifier")
	// ErrInvalidPartyID is returned when the party identifier format is invalid
	ErrInvalidPartyID = errors.New("invalid party identifier format")
	// ErrServiceNotFound is returned when no matching service is found
	ErrServiceNotFound = errors.New("no matching service found in BDXL records")
	// ErrInvalidNAPTRRecord is returned when a NAPTR record has invalid format
	ErrInvalidNAPTRRecord = errors.New("invalid NAPTR record format")
)

// ServiceType represents the type of metadata service
type ServiceType string

const (
	// ServiceTypeSMP1 is the service type for OASIS SMP 1.0 (Meta:SMP)
	ServiceTypeSMP1 ServiceType = "Meta:SMP"
	// ServiceTypeSMP2 is the service type for OASIS SMP 2.0 (oasis-bdxr-smp-2)
	ServiceTypeSMP2 ServiceType = "oasis-bdxr-smp-2"
)

// IdentifierScheme represents the identifier scheme used
type IdentifierScheme string

const (
	// SchemeEbCore is the ebCore Party Identifier scheme
	SchemeEbCore IdentifierScheme = "ebcore"
	// SchemePEPPOL is the PEPPOL identifier scheme
	SchemePEPPOL IdentifierScheme = "peppol"
)

// Environment represents the BDXL environment
type Environment string

const (
	// EnvProduction is the production environment
	EnvProduction Environment = "production"
	// EnvAcceptance is the acceptance/test environment
	EnvAcceptance Environment = "acceptance"
	// EnvTest is the test environment
	EnvTest Environment = "test"
)

// BDXLClientConfig contains configuration for BDXL client
type BDXLClientConfig struct {
	// ServiceProviderDomain is the base domain of the BDXL service provider
	// Example: "bdxl.example.com"
	ServiceProviderDomain string

	// Environment specifies the environment (production, acceptance, test)
	// For non-production environments, a label is added to the DNS query
	Environment Environment

	// PreferredService specifies the preferred SMP service type
	// Defaults to ServiceTypeSMP2 if not specified
	PreferredService ServiceType

	// DNSServer is the DNS server to use for lookups (optional)
	// Format: "ip:port" (e.g., "8.8.8.8:53")
	// If empty, the system default resolver is used
	DNSServer string

	// IdentifierScheme specifies the identifier scheme to use for formatting
	// Defaults to SchemeEbCore if not specified
	IdentifierScheme IdentifierScheme

	// CustomDomainFormat allows custom domain formatting
	// If set, this function is called instead of the default format
	// Parameters: (hashedID, environment, domain) -> queryDomain
	CustomDomainFormat func(string, Environment, string) string
}

// BDXLClient provides BDXL discovery functionality
type BDXLClient struct {
	config    BDXLClientConfig
	dnsClient *dns.Client
}

// NewBDXLClient creates a new BDXL client with the given service provider domain
func NewBDXLClient(serviceProviderDomain string) *BDXLClient {
	return &BDXLClient{
		config: BDXLClientConfig{
			ServiceProviderDomain: serviceProviderDomain,
			Environment:           EnvProduction,
			PreferredService:      ServiceTypeSMP2,
			IdentifierScheme:      SchemeEbCore,
		},
		dnsClient: new(dns.Client),
	}
}

// NewBDXLClientWithConfig creates a new BDXL client with custom configuration
func NewBDXLClientWithConfig(config BDXLClientConfig) *BDXLClient {
	if config.PreferredService == "" {
		config.PreferredService = ServiceTypeSMP2
	}
	if config.IdentifierScheme == "" {
		config.IdentifierScheme = SchemeEbCore
	}
	return &BDXLClient{
		config:    config,
		dnsClient: new(dns.Client),
	}
}

// DiscoverSMP discovers the SMP service URL for a party identifier.
// The partyID should be in canonical form (e.g., ebCore Party ID or PEPPOL format).
func (c *BDXLClient) DiscoverSMP(ctx context.Context, partyID string) (string, error) {
	// Hash and encode the party identifier
	hashedID, err := c.hashPartyID(partyID)
	if err != nil {
		return "", err
	}

	// Construct DNS query domain
	queryDomain := c.formatQueryDomain(hashedID)

	// Perform DNS U-NAPTR lookup
	smpURL, err := c.lookupNAPTR(ctx, queryDomain)
	if err != nil {
		return "", err
	}

	return smpURL, nil
}

// DiscoverSMPForEbCore discovers the SMP for an ebCore party identifier.
// Parameters:
//   - catalog: The catalog identifier (e.g., "iso6523")
//   - scheme: The scheme within the catalog (e.g., "0088" for GLN)
//   - identifier: The party-specific identifier
func (c *BDXLClient) DiscoverSMPForEbCore(ctx context.Context, catalog, scheme, identifier string) (string, error) {
	partyID := FormatEbCorePartyID(catalog, scheme, identifier)
	return c.DiscoverSMP(ctx, partyID)
}

// DiscoverSMPForPEPPOL discovers the SMP for a PEPPOL identifier.
// Parameters:
//   - scheme: The ISO 6523 scheme code (e.g., "0088")
//   - identifier: The party-specific identifier
func (c *BDXLClient) DiscoverSMPForPEPPOL(ctx context.Context, scheme, identifier string) (string, error) {
	partyID := FormatPEPPOLPartyID(scheme, identifier)
	return c.DiscoverSMP(ctx, partyID)
}

// hashPartyID hashes and encodes the party identifier according to BDXL spec.
// Returns a BASE32-encoded SHA256 hash with padding removed.
func (c *BDXLClient) hashPartyID(partyID string) (string, error) {
	if partyID == "" {
		return "", ErrInvalidPartyID
	}

	// SHA256 hash
	hash := sha256.Sum256([]byte(partyID))

	// BASE32 encode
	encoded := base32.StdEncoding.EncodeToString(hash[:])

	// Remove trailing '=' padding
	encoded = strings.TrimRight(encoded, "=")

	return encoded, nil
}

// formatQueryDomain constructs the DNS query domain from the hashed party ID.
func (c *BDXLClient) formatQueryDomain(hashedID string) string {
	// Use custom format if provided
	if c.config.CustomDomainFormat != nil {
		return c.config.CustomDomainFormat(hashedID, c.config.Environment, c.config.ServiceProviderDomain)
	}

	// Default format: <hashedID>.[<env>.]<domain>
	if c.config.Environment == EnvProduction {
		return fmt.Sprintf("%s.%s", hashedID, c.config.ServiceProviderDomain)
	}

	// Non-production environment
	envLabel := string(c.config.Environment)
	return fmt.Sprintf("%s.%s.%s", hashedID, envLabel, c.config.ServiceProviderDomain)
}

// lookupNAPTR performs the DNS U-NAPTR lookup and extracts the SMP URL.
func (c *BDXLClient) lookupNAPTR(ctx context.Context, queryDomain string) (string, error) {
	// Determine DNS server
	dnsServer := c.config.DNSServer
	if dnsServer == "" {
		// Use system default - get from resolv.conf
		config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return "", fmt.Errorf("failed to read DNS config: %w", err)
		}
		if len(config.Servers) == 0 {
			return "", errors.New("no DNS servers configured")
		}
		dnsServer = config.Servers[0] + ":" + config.Port
	}

	// Create DNS message
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(queryDomain), dns.TypeNAPTR)
	msg.RecursionDesired = true

	// Perform query
	resp, _, err := c.dnsClient.ExchangeContext(ctx, msg, dnsServer)
	if err != nil {
		return "", fmt.Errorf("DNS lookup failed for %s: %w", queryDomain, err)
	}

	if resp.Rcode == dns.RcodeNameError {
		return "", fmt.Errorf("%w: %s", ErrNoRecordsFound, queryDomain)
	}

	if resp.Rcode != dns.RcodeSuccess {
		return "", fmt.Errorf("DNS lookup failed for %s: rcode=%d", queryDomain, resp.Rcode)
	}

	// Extract NAPTR records
	var records []*dns.NAPTR
	for _, rr := range resp.Answer {
		if naptr, ok := rr.(*dns.NAPTR); ok {
			records = append(records, naptr)
		}
	}

	if len(records) == 0 {
		return "", fmt.Errorf("%w: %s", ErrNoRecordsFound, queryDomain)
	}

	// Find matching service record
	return c.selectBestRecord(records)
}

// selectBestRecord selects the best U-NAPTR record based on service type preference.
func (c *BDXLClient) selectBestRecord(records []*dns.NAPTR) (string, error) {
	var bestRecord *dns.NAPTR
	var bestPriority int = 0xFFFF

	preferredService := strings.ToLower(string(c.config.PreferredService))

	for _, record := range records {
		// U-NAPTR records have flag "U"
		if strings.ToUpper(record.Flags) != "U" {
			continue
		}

		// Check if service matches our preference
		service := strings.ToLower(record.Service)
		matches := service == preferredService ||
			service == strings.ToLower(string(ServiceTypeSMP1)) ||
			service == strings.ToLower(string(ServiceTypeSMP2))

		if !matches {
			continue
		}

		// Select by order and preference (lower is better)
		priority := int(record.Order)*1000 + int(record.Preference)
		if bestRecord == nil || priority < bestPriority {
			bestRecord = record
			bestPriority = priority
		}

		// If we found exact match for preferred service, prefer it
		if service == preferredService && (bestRecord == nil || strings.ToLower(bestRecord.Service) != preferredService) {
			bestRecord = record
			bestPriority = priority
		}
	}

	if bestRecord == nil {
		return "", ErrServiceNotFound
	}

	// Extract URL from regexp field
	return c.extractURLFromRegexp(bestRecord.Regexp)
}

// extractURLFromRegexp extracts the URL from a NAPTR regexp field.
// NAPTR regexp format: "!<pattern>!<replacement>!"
func (c *BDXLClient) extractURLFromRegexp(regexpField string) (string, error) {
	if regexpField == "" {
		return "", ErrInvalidNAPTRRecord
	}

	// Parse the NAPTR regexp field
	// Format: !<pattern>!<replacement>!
	// Common format: "!.*!https://smp.example.com/!"
	parts := strings.Split(regexpField, "!")
	if len(parts) < 3 {
		return "", fmt.Errorf("%w: invalid regexp format: %s", ErrInvalidNAPTRRecord, regexpField)
	}

	// The replacement URL is in parts[2]
	replacement := parts[2]
	if replacement == "" {
		return "", fmt.Errorf("%w: empty URL in regexp: %s", ErrInvalidNAPTRRecord, regexpField)
	}

	// Validate URL
	parsedURL, err := url.Parse(replacement)
	if err != nil {
		return "", fmt.Errorf("invalid URL in NAPTR record: %w", err)
	}

	// Ensure HTTPS is used
	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
		return "", fmt.Errorf("invalid URL scheme in NAPTR record: %s", parsedURL.Scheme)
	}

	return replacement, nil
}

// FormatEbCorePartyID formats an ebCore Party Identifier.
// Returns: urn:oasis:names:tc:ebcore:partyid-type:<catalog>:<scheme>:<identifier>
func FormatEbCorePartyID(catalog, scheme, identifier string) string {
	return fmt.Sprintf("urn:oasis:names:tc:ebcore:partyid-type:%s:%s:%s",
		catalog, scheme, identifier)
}

// FormatPEPPOLPartyID formats a PEPPOL party identifier.
// Returns: iso6523-actorid-upis::<scheme>:<identifier>
func FormatPEPPOLPartyID(scheme, identifier string) string {
	return fmt.Sprintf("%s:%s", scheme, identifier)
}

// ParseEbCorePartyID parses an ebCore Party Identifier.
// Returns catalog, scheme, identifier, and error.
func ParseEbCorePartyID(partyID string) (catalog, scheme, identifier string, err error) {
	// Pattern: urn:oasis:names:tc:ebcore:partyid-type:<catalog>:<scheme>:<identifier>
	pattern := regexp.MustCompile(`^urn:oasis:names:tc:ebcore:partyid-type:([^:]+):([^:]+):(.+)$`)
	matches := pattern.FindStringSubmatch(partyID)
	if matches == nil {
		return "", "", "", fmt.Errorf("%w: %s", ErrInvalidPartyID, partyID)
	}
	return matches[1], matches[2], matches[3], nil
}

// ParsePEPPOLPartyID parses a PEPPOL party identifier.
// Returns scheme, identifier, and error.
func ParsePEPPOLPartyID(partyID string) (scheme, identifier string, err error) {
	// Pattern: <scheme>:<identifier>
	parts := strings.SplitN(partyID, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("%w: %s", ErrInvalidPartyID, partyID)
	}
	return parts[0], parts[1], nil
}
