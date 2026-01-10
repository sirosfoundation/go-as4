# ADR-001: Cryptographic Libraries

## Status

Accepted

## Context

The go-as4 library handles sensitive cryptographic operations including:
- XML digital signatures (WS-Security)
- X.509 certificate validation
- Digest computation (SHA-256)
- Optional payload encryption (AES-GCM)

Implementing cryptographic primitives correctly is notoriously difficult, and errors can lead to serious security vulnerabilities.

## Decision

This project avoids implementing cryptographic primitives, favouring the reuse of existing, well-tested libraries:

- **XML Signatures**: `github.com/leifj/signedxml` (fork with critical C14N fixes)
- **XML DSig Core**: `github.com/russellhaering/goxmldsig` for canonicalization
- **Standard Crypto**: Go's `crypto/` standard library for RSA, SHA-256, AES
- **X.509 Handling**: Go's `crypto/x509` for certificate parsing and validation
- **TLS**: Go's `crypto/tls` for transport security

## Rationale

Cryptography is hard to get right. Making a mistake when implementing a cryptographic primitive will have serious implications for the security of protocols that build upon those primitives.

Using well-tested, widely-adopted libraries:
- Reduces the risk of security vulnerabilities
- Benefits from community review and auditing
- Provides better compatibility with standards (XML C14N, WS-Security)
- Simplifies maintenance

The `signedxml` fork contains critical fixes for:
- Exclusive C14N handling for both inline and transformed references
- RSA-PSS signature algorithm support
- Proper namespace handling in canonicalization

## Consequences

- Dependencies on external libraries must be kept up-to-date
- Library choices should be evaluated for security and maintenance status
- Custom crypto code is prohibited without explicit security review
- When upstream libraries have bugs, we fork and maintain patches
