// Package discovery implements eDelivery BDXL (Business Document Exchange Location)
// dynamic metadata discovery for AS4 messaging.
//
// This package provides functionality to discover AS4 Access Point endpoints
// using the eDelivery BDXL specification, which uses DNS U-NAPTR records to
// locate Service Metadata Publisher (SMP) services for a given party identifier.
//
// # Specifications
//
// This implementation supports:
//   - eDelivery BDXL 2.0 (December 2024)
//   - eDelivery BDXL 1.6 (May 2018) - for backward compatibility
//
// The BDXL specification is based on:
//   - OASIS Business Document Metadata Service Location Version 1.0
//   - RFC 4848 (U-NAPTR DNS records)
//
// # Discovery Process
//
// The discovery process works as follows:
//
//  1. Party Identifier Encoding: The party identifier is encoded in a canonical form
//     (e.g., ebCore Party ID or PEPPOL identifier format).
//
//  2. DNS Query Construction: The canonical identifier is hashed with SHA-256,
//     BASE32 encoded, and combined with the service provider domain to form
//     the DNS query name.
//
//  3. U-NAPTR Lookup: A DNS query for U-NAPTR records is performed to retrieve
//     the SMP service URL.
//
//  4. SMP Query: The SMP service is queried using the OASIS SMP HTTP binding
//     to retrieve endpoint metadata including the AS4 Access Point URL.
//
// # Usage
//
// Basic discovery flow:
//
//	// Create a BDXL client for a specific service provider domain
//	client := discovery.NewBDXLClient("bdxl.example.com")
//
//	// Discover SMP URL for a party
//	smpURL, err := client.DiscoverSMP(ctx, "urn:oasis:names:tc:ebcore:partyid-type:iso6523:0088:4035811991021")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Create SMP client and query for endpoint metadata
//	smpClient := discovery.NewSMPClient()
//	endpoint, err := smpClient.GetEndpoint(ctx, smpURL, partyID, documentType, processID)
//
// # Service Types
//
// The package supports both SMP 1.0 and SMP 2.0 service types in U-NAPTR records:
//   - "Meta:SMP" - OASIS SMP 1.0
//   - "oasis-bdxr-smp-2" - OASIS SMP 2.0
//
// # ebCore Party Identifiers
//
// ebCore Party Identifiers follow the format:
//
//	urn:oasis:names:tc:ebcore:partyid-type:<catalog>:<scheme>:<identifier>
//
// Example using ISO 6523 catalog with GLN scheme (0088):
//
//	urn:oasis:names:tc:ebcore:partyid-type:iso6523:0088:4035811991021
//
// # PEPPOL Identifiers
//
// PEPPOL identifiers use the ISO 6523 catalog with a different format:
//
//	iso6523-actorid-upis::<scheme>:<identifier>
//
// Example:
//
//	iso6523-actorid-upis::0088:4035811991021
//
// # References
//
//   - eDelivery BDXL 2.0: https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/843612547/eDelivery+BDXL+-+2.0
//   - eDelivery SMP: https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/467117987/eDelivery+SMP
//   - OASIS BDX-Location 1.0: http://docs.oasis-open.org/bdxr/BDX-Location/v1.0/
//   - OASIS SMP 2.0: https://docs.oasis-open.org/bdxr/bdx-smp/v2.0/
//   - RFC 4848: https://www.rfc-editor.org/rfc/rfc4848.html
package discovery
