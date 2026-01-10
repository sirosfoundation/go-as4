# ADR-002: Test Coverage

## Status

Accepted

## Context

AS4 is a critical messaging protocol used in business-to-business and government-to-government communications. Correctness is essential for:
- Interoperability with other AS4 implementations
- Security of signed and encrypted messages
- Reliability of message delivery

## Decision

This project will aim for >70% test coverage overall, with higher coverage (>80%) for critical packages:
- `pkg/security/` - Cryptographic operations
- `pkg/message/` - Message parsing and construction
- `pkg/msh/` - Message Service Handler

## Rationale

A high degree of test coverage leads to more robust code and, given our use of AI-assisted programming, helps to reduce the effect of hallucination.

Testing is particularly important for:
- XML signature generation and verification
- Canonical form computation (C14N)
- ebMS3 message structure compliance
- Interoperability with reference implementations

## Consequences

- All new features must include corresponding tests
- Pull requests should maintain or improve coverage
- CI pipeline enforces coverage thresholds
- Interoperability tests against phase4 validate real-world compatibility
