# Examples

This directory contains examples demonstrating how to use the go-as4 library.

## Basic Example

The `basic/` directory contains a simple example showing:
- Creating an AS4 UserMessage
- Configuring security (Ed25519 signing)
- Compressing payloads with GZIP
- Setting up Processing Modes
- Message tracking and reliability
- HTTPS transport configuration

To run the basic example:

```bash
cd examples/basic
go run main.go
```

## Features Demonstrated

### Message Creation
- Party identification
- Service and action configuration
- Payload handling
- Message properties

### Security
- Ed25519 digital signatures
- SHA-256 digest
- X25519 key agreement (configured)
- TLS 1.2/1.3 transport

### Reliability
- Reception awareness
- Retry mechanism with exponential backoff
- Duplicate detection
- Message tracking

### Compression
- GZIP payload compression
- Automatic compression for suitable content types

## Next Steps

For production use:
1. Use proper PKI certificates instead of self-signed
2. Configure encryption with recipient certificates
3. Implement proper error handling and logging
4. Set up monitoring and alerting
5. Configure appropriate retry policies
6. Implement business payload processing logic
