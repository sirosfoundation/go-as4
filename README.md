# go-as4

<div align="center">

[![Go Reference](https://pkg.go.dev/badge/github.com/sirosfoundation/go-as4.svg)](https://pkg.go.dev/github.com/sirosfoundation/go-as4)
[![CI](https://github.com/sirosfoundation/go-as4/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/go-as4/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/sirosfoundation/go-as4)](https://goreportcard.com/report/github.com/sirosfoundation/go-as4)
[![codecov](https://codecov.io/gh/sirosfoundation/go-as4/branch/main/graph/badge.svg)](https://codecov.io/gh/sirosfoundation/go-as4)
[![Coverage](https://raw.githubusercontent.com/sirosfoundation/go-as4/badges/.badges/main/coverage.svg)](https://github.com/sirosfoundation/go-as4/actions/workflows/ci.yml)
[![Go Version](https://raw.githubusercontent.com/sirosfoundation/go-as4/badges/.badges/main/golang.svg)](https://go.dev/)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)

[![CodeQL](https://github.com/sirosfoundation/go-as4/actions/workflows/codeql.yml/badge.svg)](https://github.com/sirosfoundation/go-as4/actions/workflows/codeql.yml)
[![Latest Release](https://img.shields.io/github/v/release/sirosfoundation/go-as4?include_prereleases)](https://github.com/sirosfoundation/go-as4/releases)
[![Issues](https://img.shields.io/github/issues/sirosfoundation/go-as4)](https://github.com/sirosfoundation/go-as4/issues)
[![Last Commit](https://img.shields.io/github/last-commit/sirosfoundation/go-as4)](https://github.com/sirosfoundation/go-as4/commits/main)

</div>

A Go library implementing the eDelivery AS4 2.0 specification for secure, reliable B2B messaging.

## Overview

go-as4 implements the European Commission's eDelivery AS4 profile, which is based on the OASIS ebXML Messaging Services v3.0 (ebMS3) and AS4 specifications. This library provides a complete implementation of the AS4 protocol for secure, reliable business message exchange.

The project includes both a **library** for embedding AS4 functionality into your applications and a **production-ready multi-tenant server** with JMAP-based mailbox access.

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

### Server Features
- **Multi-tenant architecture**: Single server instance serves multiple organizations
- **JMAP API**: RFC 8620-compliant API for mailbox access and message management
- **REST API**: Traditional REST endpoints for tenant and message management
- **Background Sender**: Automatic retry with exponential backoff
- **Flexible Key Management**:
  - File-based keys (development)
  - FIDO2/PRF-based key encryption (production)
  - PKCS#11 HSM support (high-security)
- **OAuth2/OIDC Authentication**: JWT-based API authentication
- **MongoDB Storage**: Messages and payloads stored with GridFS
- **Observability**: Prometheus metrics and distributed tracing

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

## AS4 Server

The `as4-server` is a production-ready, multi-tenant AS4 message handler with JMAP-based mailbox access.

### Running the Server

```bash
# Build the server
make build

# Run with configuration file
./bin/as4-server -config config.yaml

# Or use Docker Compose for development
make dev-setup  # One-time setup
make dev-up     # Start MongoDB + server
```

### Server API Endpoints

The server exposes multiple API surfaces:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/tenant/{id}/as4` | POST | Receive inbound AS4 messages |
| `/tenant/{id}/jmap/session` | GET | JMAP session/capability discovery |
| `/tenant/{id}/jmap` | POST | JMAP method invocations |
| `/tenant/{id}/jmap/download/{blobID}/{name}` | GET | Download message payloads |
| `/tenant/{id}/api/participants` | GET/POST | Manage trading partners |
| `/tenant/{id}/api/messages` | GET/POST | List/send messages |
| `/health` | GET | Liveness probe |
| `/metrics` | GET | Prometheus metrics |

### Configuration

```yaml
# config.yaml
server:
  port: 8080
  basePath: "/tenant"

storage:
  mongodb:
    uri: "mongodb://localhost:27017"
    database: "as4"

# Key management: file, prf, or pkcs11
signing:
  mode: "file"
  file:
    keyDir: "./keys"

# OAuth2/OIDC for API authentication
oauth2:
  issuer: "https://auth.example.com"
  audience: "as4-api"
  jwksUrl: "https://auth.example.com/.well-known/jwks.json"
```

See [config.example.yaml](cmd/as4-server/config.example.yaml) for all options.

### JMAP API

The server implements an exmperimental [JMAP extension for AS4](docs/draft-johansson-jmap-as4.md) (draft-johansson-jmap-as4), providing:

- **AS4Message** data type for representing AS4 messages
- **Mailbox** support for organizing inbound/outbound/sent messages
- **Push notifications** via Server-Sent Events (SSE)
- **Blob downloads** for message payloads

Example JMAP request:

```json
{
  "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:as4"],
  "methodCalls": [
    ["AS4Message/query", {
      "accountId": "tenant-123",
      "filter": { "inMailbox": "inbox" }
    }, "0"],
    ["AS4Message/get", {
      "accountId": "tenant-123",
      "#ids": { "resultOf": "0", "name": "AS4Message/query", "path": "/ids" }
    }, "1"]
  ]
}
```

## Architecture

```
go-as4/
├── cmd/
│   └── as4-server/   # Multi-tenant AS4 server
├── internal/
│   ├── as4/          # AS4 message handling
│   ├── auth/         # OAuth2/JWT authentication
│   ├── config/       # Configuration loading
│   ├── jmap/         # JMAP protocol handler
│   ├── keystore/     # Key management (file/PRF/PKCS#11)
│   ├── sender/       # Background message sender
│   ├── server/       # HTTP server and routing
│   ├── storage/      # MongoDB storage layer
│   └── tenant/       # Multi-tenant management
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

- [JMAP-AS4 Specification](docs/draft-johansson-jmap-as4.md) - Experimental JMAP extension for AS4
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
# Install git hooks (recommended)
./scripts/install-hooks.sh

# Or use pre-commit framework
pip install pre-commit
pre-commit install
pre-commit install --hook-type pre-push

# Run tests
make test

# Run interoperability self-test (go-as4 ↔ go-as4)
make interop-self-test

# Run full interoperability test against phase4
make interop-test

# Check coverage
make coverage

# Run linting
go vet ./...
golangci-lint run
```

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

Before submitting a PR:
1. Install git hooks: `./scripts/install-hooks.sh`
2. Ensure tests pass: `go test -race ./pkg/...`
3. Check formatting: `gofmt -s -l .`
4. Run linting: `go vet ./...`

## License

BSD 2-Clause License - see [LICENSE](LICENSE) file.

## References

- [eDelivery AS4 2.0 Specification](https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/845480153/eDelivery+AS4+-+2.0)
- [OASIS AS4 Profile](https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/)
- [ebMS3 Core](https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/core/os/)
- [phase4 Reference Implementation](https://github.com/phax/phase4)
