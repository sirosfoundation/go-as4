# ADR-007: WS-Security Compliance

## Status

Accepted

## Context

AS4 mandates WS-Security 1.1.1 for message-level security. This includes:
- BinarySecurityToken for X.509 certificates
- SecurityTokenReference for key identification
- Timestamp elements for replay protection
- Digital signatures covering specific message parts

Different AS4 implementations support different token reference methods, requiring flexibility.

## Decision

Implement full WS-Security 1.1.1 compliance with support for multiple token reference methods:

1. **BinarySecurityToken** (default) - Certificate embedded in message
2. **KeyIdentifier** - Subject Key Identifier reference
3. **IssuerSerial** - Issuer name + serial number reference

Signed elements follow AS4 requirements:
- `wsu:Timestamp` - Replay protection
- `S12:Body` - SOAP body integrity  
- `eb:Messaging` - ebMS3 header integrity

## Rationale

WS-Security compliance ensures interoperability with:
- Domibus (EU reference implementation)
- Phase4 (Philip Helger's library)
- Holodeck B2B
- Commercial AS4 gateways

The AS4 specification mandates:
```xml
<sp:Wss11>
    <sp:MustSupportRefKeyIdentifier/>
    <sp:MustSupportRefIssuerSerial/>
    <sp:MustSupportRefEmbeddedToken/>
</sp:Wss11>
```

## Consequences

- Token reference method configurable via P-Mode
- Security header follows strict element ordering
- wsu:Id attributes use unique identifiers
- Signature covers required elements per AS4 profile
- See [TOKEN_REFERENCES.md](../TOKEN_REFERENCES.md) for implementation details
