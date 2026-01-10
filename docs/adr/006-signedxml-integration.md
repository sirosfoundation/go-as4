# ADR-006: SignedXML Integration

## Status

Accepted

## Context

XML Digital Signatures (XML DSig) require precise implementation of:
- Exclusive Canonicalization (C14N) per RFC 3741
- InclusiveNamespaces handling
- Reference URI resolution
- Digest computation order

Initial attempts at custom C14N implementation failed interoperability testing because the canonical form computed during signing differed from what receivers computed during verification.

## Decision

Integrate the `signedxml` library (forked as `github.com/leifj/signedxml`) for all XML signature operations.

The fork includes critical fixes:
1. **C14N for inline vs transformed references** - Proper handling of elements that are both signed and transformed
2. **RSA-PSS support** - RSASSA-PSS signature algorithm
3. **Namespace propagation** - Correct ancestor namespace handling in canonicalization

## Rationale

The `signedxml` library:
- Properly implements exclusive C14N with InclusiveNamespaces
- Has been battle-tested with SAML and other XML-DSig use cases
- Integrates with `goxmldsig` for low-level C14N operations
- Allows us to focus on AS4-specific logic rather than C14N details

Custom C14N is error-prone:
- Attribute ordering rules
- Namespace axis handling
- Whitespace normalization
- InclusiveNamespaces prefix propagation

## Consequences

- Dependency on forked `signedxml` with replace directive in go.mod
- Must track upstream changes and merge relevant fixes
- Tagged versions (v1.2.3-leifj1 through v1.2.3-leifj4) track our patches
- Signature operations are delegated to the library
