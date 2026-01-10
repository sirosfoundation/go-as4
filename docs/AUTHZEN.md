# AuthZEN Trust Framework Implementation

This document describes the implementation of certificate validation based on the [AuthZEN Trust Framework](https://datatracker.ietf.org/doc/draft-johansson-authzen-trust/) (draft-johansson-authzen-trust-00).

## Overview

The AuthZEN Trust Framework provides a standardized protocol for validating name-to-key bindings across different trust registries. It acts as an abstraction layer, similar to DNS stub resolvers, allowing applications to query trust decisions without knowing the underlying trust registry implementation (ETSI trust status lists, OpenID Federation, ledgers, etc.).

## Architecture

### Components

1. **Policy Enforcement Point (PEP)** - The application code that needs to validate certificates
2. **Policy Decision Point (PDP)** - A service that makes trust decisions by consulting trust registries
3. **Trust Registries** - Backend systems that maintain trust relationships (hidden from PEP)

```
┌─────────────┐         ┌─────────────┐         ┌───────────────────┐
│     PEP     │ AuthZEN │     PDP     │         │ Trust Registries  │
│ (go-as4)    ├────────►│   Server    ├────────►│ (ETSI, OID Fed,   │
│             │         │             │         │  Ledgers, etc.)   │
└─────────────┘         └─────────────┘         └───────────────────┘
```

### Protocol Flow

1. **Certificate Received**: Application receives an X.509 certificate
2. **Extract Information**: Extract subject name and public key
3. **Build Request**: Construct AuthZEN request with name and key
4. **Query PDP**: POST request to `/evaluation` endpoint
5. **Receive Decision**: PDP returns `{"decision": true/false}`
6. **Enforce Decision**: Accept or reject the certificate

## AuthZEN Request Format

Per Section 4 of draft-johansson-authzen-trust-00:

```json
{
  "type": "authzen",
  "request": {
    "subject": {
      "type": "key",
      "id": "www.example.com"
    },
    "resource": {
      "type": "x5c",
      "id": "www.example.com",
      "key": ["<base64-cert>", "<base64-intermediate>", "..."]
    },
    "action": {
      "name": "tls-server"
    }
  }
}
```

### Request Fields

#### Subject (Section 4.1)
Represents the **name** part of the name-to-key binding.

- `type`: MUST be the constant string `"key"`
- `id`: MUST be the name bound to the public key (CN, DNS name, email, URI, DID, etc.)

#### Resource (Section 4.2)
Represents the **public key** part of the name-to-key binding.

- `type`: MUST be `"jwk"` or `"x5c"`
  - `"jwk"`: JSON Web Key format (RFC 7517)
  - `"x5c"`: X.509 certificate chain (RFC 7517 Section 4.7)
- `id`: MUST match `subject.id`
- `key`: 
  - For `"jwk"`: JWK object
  - For `"x5c"`: Array of base64-encoded DER certificates (leaf first, then intermediates)

#### Action (Section 4.3) - Optional
Constrains authorization to a specific role or purpose.

- `name`: String representing the role/purpose
  - Examples: `"tls-server"`, `"tls-client"`, `"signing"`, `"encryption"`
  - Can be OID, URI, or custom identifier depending on deployment

#### Context (Section 4.4) - Optional
MAY be present but MUST NOT contain information critical for the decision.

## AuthZEN Response Format

Per Section 5 of draft-johansson-authzen-trust-00:

### Success Response
```json
{
  "decision": true
}
```

### Failure Response with Context
```json
{
  "decision": false,
  "context": {
    "reason": {
      "403": "Unknown service - contact helpdesk@registry.example.com for support using identifier: #ID4711"
    }
  }
}
```

### Response Fields

- `decision`: Boolean indicating whether the name-to-key binding is authorized
- `context`: Optional object with additional information (error messages, diagnostics, etc.)

## Implementation

### AuthZENTrustValidator

The `AuthZENTrustValidator` type implements the `CertificateValidator` interface using the AuthZEN protocol.

```go
// Create validator pointing to PDP endpoint
// Default action is "signing" for AS4 XML signature validation
validator := security.NewAuthZENTrustValidator("https://trust-pdp.example.com/evaluation")

// Change default action for other use cases
validator.WithDefaultAction("tls-server")

// Use in XML signature verification
signer.WithCertificateValidator(validator)

// Validate manually with explicit purpose
err := validator.ValidateCertificate(cert, intermediates, "signing")
if err != nil {
    log.Error("Certificate validation failed", "error", err)
    return err
}

// Validate using default action (falls back to "signing")
err = validator.ValidateCertificate(cert, intermediates, "")
```

### Configurable Actions

The validator supports configurable actions/purposes via `WithDefaultAction()`:

```go
// For AS4 message signing (default)
validator := security.NewAuthZENTrustValidator(pdpURL).
    WithDefaultAction("signing")

// For TLS server certificates
validator := security.NewAuthZENTrustValidator(pdpURL).
    WithDefaultAction("tls-server")

// For TLS client certificates
validator := security.NewAuthZENTrustValidator(pdpURL).
    WithDefaultAction("tls-client")

// For encryption certificates
validator := security.NewAuthZENTrustValidator(pdpURL).
    WithDefaultAction("encryption")

// Custom action per trust registry
validator := security.NewAuthZENTrustValidator(pdpURL).
    WithDefaultAction("http://ec.europa.eu/NS/wallet-provider")
```

The `purpose` parameter in `ValidateCertificate()` overrides the default action if provided.

### Certificate to x5c Conversion

Per RFC 7517 Section 4.7, certificates are encoded as base64 (NOT base64url) DER values:

```go
x5c := make([]string, 0)
x5c = append(x5c, base64.StdEncoding.EncodeToString(cert.Raw))
for _, intermediate := range chain {
    x5c = append(x5c, base64.StdEncoding.EncodeToString(intermediate.Raw))
}
```

### Subject Name Extraction

The implementation tries multiple sources in order:
1. CommonName from certificate Subject
2. First DNS name from SubjectAltName
3. First email address from SubjectAltName
4. First URI from SubjectAltName

For modern certificates (post-2015), DNS names are typically in SubjectAltName, not CommonName.

### HTTP Client Configuration

Custom HTTP clients can be configured for proxy support, custom TLS, timeouts, etc:

```go
customClient := &http.Client{
    Timeout: 30 * time.Second,
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            // Custom TLS configuration
        },
    },
}

validator := security.NewAuthZENTrustValidator(pdpEndpoint).
    WithHTTPClient(customClient)
```

## Endpoints

Per Section 3 of the specification:

- `/evaluation` - MUST be provided (used by this implementation)
- `/evaluations` - SHOULD be provided (batch evaluations)
- `/discovery` - SHOULD be provided (service discovery)
- `/search` - MAY be provided (not guaranteed to exist)

This implementation uses only the `/evaluation` endpoint.

## Use Cases

### 1. TLS Server Certificate Validation

```json
{
  "type": "authzen",
  "request": {
    "subject": {"type": "key", "id": "www.example.com"},
    "resource": {"type": "x5c", "id": "www.example.com", "key": ["..."]},
    "action": {"name": "tls-server"}
  }
}
```

### 2. Code Signing Certificate

```json
{
  "type": "authzen",
  "request": {
    "subject": {"type": "key", "id": "publisher@example.com"},
    "resource": {"type": "x5c", "id": "publisher@example.com", "key": ["..."]},
    "action": {"name": "code-signing"}
  }
}
```

### 3. Digital Credential Issuer (EUDI Wallet)

```json
{
  "type": "authzen",
  "request": {
    "subject": {"type": "key", "id": "did:example:123"},
    "resource": {"type": "x5c", "id": "did:example:123", "key": ["..."]},
    "action": {"name": "http://ec.europa.eu/NS/wallet-provider"}
  }
}
```

### 4. AS4 Message Signing

```json
{
  "type": "authzen",
  "request": {
    "subject": {"type": "key", "id": "party@example.com"},
    "resource": {"type": "x5c", "id": "party@example.com", "key": ["..."]},
    "action": {"name": "signing"}
  }
}
```

## Security Considerations

Per Section 7 of the specification:

1. **Shared Security Domain**: The protocol is designed for use within a common security domain
2. **localhost Deployments**: May be deployed without authentication on localhost
3. **Authentication**: 
   - MAY implement OAuth 2.0 (RFC 6749) for client-to-server authentication
   - SHOULD provide PDP-to-client authentication
4. **Transport Security**: Use HTTPS in production deployments
5. **Input Validation**: PDP must validate all inputs to prevent injection attacks

## Comparison with Traditional PKI

| Aspect | Traditional PKI | AuthZEN Trust Framework |
|--------|----------------|------------------------|
| Trust Model | CA hierarchy | Pluggable trust registries |
| Revocation | OCSP/CRL | Registry-specific |
| Name Types | DNS, Email, URI | Any identifier (DNS, DID, custom) |
| Purpose Checking | Extended Key Usage | Action field |
| Deployment | Certificate stores | REST API endpoint |
| Flexibility | Fixed CA chains | Multiple trust sources |
| Federation | X.509 bridge CAs | Trust registry federation |

## Example PDP Implementation

A minimal PDP server would:

1. Listen on `/evaluation` endpoint
2. Parse AuthZEN request JSON
3. Extract certificate from `resource.key` (x5c)
4. Extract name from `subject.id`
5. Extract purpose from `action.name`
6. Query appropriate trust registry
7. Return decision

```go
func evaluationHandler(w http.ResponseWriter, r *http.Request) {
    var req AuthZENRequest
    json.NewDecoder(r.Body).Decode(&req)
    
    // Query trust registry
    decision := trustRegistry.Check(
        req.Request.Subject.ID,
        req.Request.Resource.Key,
        req.Request.Action.Name,
    )
    
    resp := AuthZENResponse{Decision: decision}
    json.NewEncoder(w).Encode(resp)
}
```

## Integration with go-as4

The AuthZEN validator integrates seamlessly with go-as4 XML signature verification:

```go
// Setup validator with appropriate action for AS4 signing
pdpEndpoint := "https://trust.example.com/evaluation"
validator := security.NewAuthZENTrustValidator(pdpEndpoint)
// Default action is already "signing" - appropriate for AS4

// For other use cases, configure the action:
// validator.WithDefaultAction("tls-server")  // For TLS
// validator.WithDefaultAction("encryption")   // For encryption

// Configure signer
signer, _ := security.NewXMLSigner(privateKey, cert)
signer.WithCertificateValidator(validator)

// Automatic validation during signature verification
// The validator will use action "signing" in the AuthZEN request
valid, err := signer.VerifyEnvelope(signedSOAPMessage)
```

When `VerifyEnvelope` is called:
1. Extracts certificate from SOAP `<BinarySecurityToken>`
2. Calls `validator.ValidateCertificate(cert, chain, "signing")`
3. Validator builds AuthZEN request with `action.name = "signing"`
4. Queries PDP with the request
5. PDP returns decision
6. Signature verification continues only if decision is true

## Benefits

1. **Abstraction**: Application code doesn't need to know about trust registry details
2. **Federation**: Single PDP can query multiple trust registries
3. **Flexibility**: Change trust policies without modifying application code
4. **Standardization**: Common protocol across different identity systems
5. **Decentralization**: Supports modern decentralized identity systems (DIDs, ledgers)

## References

- [draft-johansson-authzen-trust-00](https://datatracker.ietf.org/doc/draft-johansson-authzen-trust/)
- [AuthZEN Authorization API](https://openid.github.io/authzen/)
- [RFC 7517 - JSON Web Key (JWK)](https://www.rfc-editor.org/rfc/rfc7517)
- [RFC 5280 - X.509 PKI](https://www.rfc-editor.org/rfc/rfc5280)
- [RFC 6749 - OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749)
