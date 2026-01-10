# ADR-008: AuthZEN Trust Framework

## Status

Accepted

## Context

Traditional X.509 PKI requires pre-configured CA trust stores. In federated environments, trust relationships are dynamic and may be established through:
- ETSI Trust Status Lists
- OpenID Federation
- Distributed ledgers
- Other trust registries

The AS4 specification doesn't mandate a specific trust model, allowing flexibility.

## Decision

Implement pluggable certificate validation with support for the AuthZEN Trust Framework ([draft-johansson-authzen-trust](https://datatracker.ietf.org/doc/draft-johansson-authzen-trust/)).

Two validator implementations:
1. **DefaultCertificateValidator** - Traditional X.509 PKI with CA trust store
2. **AuthZENTrustValidator** - REST-based trust decisions via Policy Decision Point

## Rationale

AuthZEN provides:
- **Abstraction**: Applications query trust without knowing backend registries
- **Flexibility**: PDP can consult multiple trust sources
- **Decentralization**: No single CA authority required
- **Standards-based**: Based on AuthZEN authorization protocol

This aligns with eDelivery's federated trust model where participants may be registered in different trust registries across EU member states.

## Consequences

- Certificate validation is pluggable via `CertificateValidator` interface
- AuthZEN validator requires external PDP service
- Default PKI validation works without external dependencies
- Trust decisions include purpose context (signing, TLS, encryption)
- See [AUTHZEN.md](../AUTHZEN.md) for protocol details
