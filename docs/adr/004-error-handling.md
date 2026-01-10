# ADR-004: Error Handling

## Status

Accepted

## Context

Consistent error handling is essential for debugging, logging, and providing meaningful feedback in AS4 message processing where failures can occur at multiple levels (transport, security, parsing).

## Decision

1. **Sentinel errors** for common AS4 error cases:

   ```go
   var (
       ErrSignatureInvalid    = errors.New("signature verification failed")
       ErrCertificateExpired  = errors.New("certificate expired")
       ErrMessageMalformed    = errors.New("malformed AS4 message")
       ErrDuplicateMessage    = errors.New("duplicate message detected")
   )
   ```

2. **Error wrapping** for context:

   ```go
   return fmt.Errorf("failed to verify signature: %w", err)
   ```

3. **Error checking** with `errors.Is`:

   ```go
   if errors.Is(err, ErrSignatureInvalid) {
       // Handle signature failure
   }
   ```

4. **ebMS3 error codes** for AS4 protocol errors:

   ```go
   // Map internal errors to ebMS3 error codes
   // EBMS:0001 - ValueNotRecognized
   // EBMS:0301 - MissingReceipt
   // EBMS:0303 - DecompressionFailure
   ```

## Rationale

- Consistent error handling improves debugging
- Error wrapping preserves the error chain
- Sentinel errors enable type-safe error checking
- ebMS3 error codes ensure protocol compliance

## Consequences

- All errors should be wrapped with context
- AS4 protocol errors map to ebMS3 error codes
- Logs include full error chains
- Tests verify error conditions
