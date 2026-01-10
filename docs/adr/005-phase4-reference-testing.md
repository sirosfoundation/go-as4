# ADR-005: Phase4 Reference Testing

## Status

Accepted

## Context

AS4 interoperability requires testing against other implementations. Previously, we attempted to use Domibus as a reference, but encountered complexity issues:
- Heavy infrastructure requirements (MySQL, complex P-Mode configuration)
- Slow startup times
- Difficult to debug

We needed a simpler, more lightweight reference implementation for testing.

## Decision

Use [phase4](https://github.com/phax/phase4) by Philip Helger as the primary reference implementation for interoperability testing.

Phase4 is:
- A lightweight Java AS4 library (not a full gateway)
- Well-documented with clear test cases
- Uses the same crypto stack (WSS4J/Apache CXF) as other major implementations
- Can run as a simple embedded server (Jetty)
- Actively maintained

## Rationale

Phase4 provides the right balance of:
- **Completeness**: Full AS4 profile support including signing, encryption, MIME attachments
- **Simplicity**: Can be embedded in tests without complex infrastructure
- **Compatibility**: WSS4J-based crypto matches Domibus, Holodeck, and other implementations
- **Debuggability**: Clear logging and message inspection capabilities

## Consequences

- Interoperability tests run against a Dockerized phase4 server
- Test cases cover: unsigned messages, signed messages, attachments, receipt validation
- `make interop-test` builds and runs the full test suite
- `make interop-self-test` provides quick go-as4 ↔ go-as4 validation
- Domibus testing infrastructure has been removed
