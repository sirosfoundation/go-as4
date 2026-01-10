# go-as4

A Go library implementing the eDelivery AS4 2.0 specification for secure, reliable B2B messaging.

## Overview

go-as4 implements the European Commission's eDelivery AS4 profile, which is based on the OASIS ebXML Messaging Services v3.0 (ebMS3) and AS4 specifications. This library provides a complete implementation of the AS4 protocol for secure, reliable business message exchange.

## Features

### Core AS4 Features
- **Message Structure**: Full SOAP 1.2 with ebMS3 headers support
- **Security**:
  - Transport Layer Security: TLS 1.2/1.3 with recommended cipher suites
  - Message Layer Security: WS-Security 1.1.1
  - RSA-SHA256 digital signatures (interoperable with phase4, Domibus)
  - Ed25519 digital signatures (AS4 2.0)
  - AES-128-GCM encryption
- **Reliability**: Reception awareness with retry and duplicate detection
- **Compression**: GZIP payload compression
- **MEPs**: One-Way/Push message exchange pattern

### Interoperability
- Tested against [phase4](https://github.com/phax/phase4) reference implementation
- Compatible with eDelivery ecosystem (Domibus, Holodeck B2B)
- Full WS-Security 1.1.1 compliance with multiple token reference methods

## Installation

```bash
go get github.com/sirosfoundation/go-as4
```

## Quick Start

```go
package main

import (
    "github.com/sirosfoundation/go-as4/pkg/message"
    "github.com/sirosfoundation/go-as4/pkg/security"
    "github.com/sirosfoundation/go-as4/pkg/transport"
)

func main() {
    // Create a new AS4 message
    msg := message.NewUserMessage(
        message.WithFrom("sender-party-id", "urn:oasis:names:tc:ebcore:partyid-type:unregistered"),
        message.WithTo("receiver-party-id", "urn:oasis:names:tc:ebcore:partyid-type:unregistered"),
        message.WithService("http://example.com/services/order"),
        message.WithAction("processOrder"),
    )
    
    // Add payload
    msg.AddPayload([]byte("your payload data"), "application/xml")
    
    // Configure security
    sec := security.NewSecurityConfig(
        security.WithSigningKey(signingKey),
        security.WithEncryptionCert(encryptionCert),
    )
    
    // Send message
    client := transport.NewHTTPSClient(sec)
    receipt, err := client.Send(msg, "https://receiver.example.com/as4")
    if err != nil {
        // Handle error
    }
}
```

## Architecture

```
go-as4/
├── pkg/
│   ├── as4/          # Main AS4 client/server API
│   ├── message/      # AS4 message structure and ebMS3 headers
│   ├── security/     # WS-Security, signing, and encryption
│   ├── transport/    # HTTPS transport with TLS
│   ├── reliability/  # Reception awareness, retry, duplicate detection
│   ├── compression/  # GZIP compression
│   ├── pmode/        # Processing Mode configuration
│   ├── mep/          # Message Exchange Patterns
│   ├── msh/          # Message Service Handler
│   └── mime/         # MIME multipart handling
├── docs/             # Documentation
│   └── adr/          # Architecture Decision Records
├── tests/
│   └── interop/      # Interoperability tests (phase4)
└── examples/         # Usage examples
```

## Documentation

- [Architecture Decision Records](docs/adr/README.md) - Key design decisions
- [Implementation Details](docs/IMPLEMENTATION.md) - Technical implementation
- [Security](SECURITY.md) - Security features and hardening
- [AuthZEN Trust Framework](docs/AUTHZEN.md) - Modern trust validation
- [Token References](docs/TOKEN_REFERENCES.md) - WS-Security token methods
- [Namespace Compliance](docs/NAMESPACE_COMPLIANCE.md) - ebMS3 compliance

## Compliance

This library implements:
- eDelivery AS4 2.0 specification
- OASIS AS4 Profile of ebMS 3.0 Version 1.0
- OASIS ebXML Messaging Services Version 3.0 Part 1
- WS-Security 1.1.1

## Security Algorithms

### Signing (Interoperable)
- **Digest**: SHA-256
- **Signature**: RSA-SHA256 (http://www.w3.org/2001/04/xmldsig-more#rsa-sha256)
- **Canonicalization**: Exclusive C14N with InclusiveNamespaces

### Signing (AS4 2.0)
- **Digest**: SHA-256
- **Signature**: Ed25519 (http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519)

### Encryption
- **Data Encryption**: AES-128-GCM
- **Key Wrap**: AES-128 Key Wrap

### Transport
- **TLS**: 1.2 (minimum), 1.3 (recommended)

## Development

```bash
# Run tests
make test

# Run interoperability self-test (go-as4 ↔ go-as4)
make interop-self-test

# Run full interoperability test against phase4
make interop-test

# Check coverage
make coverage
```

## License

BSD 2-Clause License - see [LICENSE](LICENSE) file.

## References

- [eDelivery AS4 2.0 Specification](https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/845480153/eDelivery+AS4+-+2.0)
- [OASIS AS4 Profile](https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/)
- [ebMS3 Core](https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/core/os/)
- [phase4 Reference Implementation](https://github.com/phax/phase4)
