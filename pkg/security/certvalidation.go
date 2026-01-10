// Package security implements certificate validation including AuthZEN Trust Framework
package security

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/authzenclient"
)

var (
	// ErrCertificateExpired is returned when a certificate has expired
	ErrCertificateExpired = errors.New("certificate has expired")
	// ErrCertificateNotYetValid is returned when a certificate is not yet valid
	ErrCertificateNotYetValid = errors.New("certificate is not yet valid")
	// ErrCertificateUntrusted is returned when a certificate is not trusted
	ErrCertificateUntrusted = errors.New("certificate is not trusted")
	// ErrCertificateRevoked is returned when a certificate has been revoked
	ErrCertificateRevoked = errors.New("certificate has been revoked")
	// ErrInvalidCertificate is returned for other certificate validation failures
	ErrInvalidCertificate = errors.New("certificate validation failed")
)

// CertificateValidator defines the interface for certificate validation
// Implementations can enforce different trust models including:
// - Traditional PKI with CA trust chains
// - AuthZEN Trust Framework (draft-johansson-authzen-trust-00)
// - Certificate pinning
// - Custom trust policies
type CertificateValidator interface {
	// ValidateCertificate validates a certificate and returns an error if invalid
	// The cert parameter is the certificate to validate
	// The intermediates parameter contains any intermediate certificates in the chain
	// The purpose parameter indicates the intended usage (e.g., "signing", "encryption", "tls-server")
	ValidateCertificate(cert *x509.Certificate, intermediates []*x509.Certificate, purpose string) error

	// ValidateCertificateChain validates a complete certificate chain
	ValidateCertificateChain(chain []*x509.Certificate, purpose string) error
}

// DefaultCertificateValidator implements traditional PKI validation
type DefaultCertificateValidator struct {
	roots *x509.CertPool
}

// NewDefaultCertificateValidator creates a validator using traditional PKI
func NewDefaultCertificateValidator(roots *x509.CertPool) *DefaultCertificateValidator {
	return &DefaultCertificateValidator{
		roots: roots,
	}
}

// ValidateCertificate validates a single certificate against the trust store
func (v *DefaultCertificateValidator) ValidateCertificate(cert *x509.Certificate, chain []*x509.Certificate, purpose string) error {
	// Check expiration
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return ErrCertificateNotYetValid
	}
	if now.After(cert.NotAfter) {
		return ErrCertificateExpired
	}

	// Build verification options
	opts := x509.VerifyOptions{
		Roots:         v.roots,
		CurrentTime:   now,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	// Add intermediate certificates to pool
	if chain != nil {
		for _, intermediate := range chain {
			opts.Intermediates.AddCert(intermediate)
		}
	}

	// Map purpose to key usage if provided
	if purpose != "" {
		switch purpose {
		case "signing", "digital-signature":
			opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection}
		case "tls-server":
			opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		case "tls-client":
			opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		case "encryption":
			opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
		}
	}

	// Verify the certificate chain
	_, err := cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCertificateUntrusted, err)
	}

	return nil
}

// ValidateCertificateChain validates a certificate chain
func (v *DefaultCertificateValidator) ValidateCertificateChain(chain []*x509.Certificate, purpose string) error {
	if len(chain) == 0 {
		return fmt.Errorf("%w: empty chain", ErrInvalidCertificate)
	}
	return v.ValidateCertificate(chain[0], chain[1:], purpose)
}

// AuthZENTrustValidator implements validation using AuthZEN Trust Framework
// Based on draft-johansson-authzen-trust-00
//
// This validator uses the AuthZEN protocol to query a Policy Decision Point (PDP)
// for trust decisions. The PDP acts as an abstraction layer over one or more
// trust registries (ETSI trust status lists, OpenID Federation, ledgers, etc.).
//
// The protocol validates name-to-key bindings by asking: "Is this public key
// (represented by an X.509 certificate) bound to this name, and is it authorized
// for this purpose?"
type AuthZENTrustValidator struct {
	client        *authzenclient.Client
	defaultAction string // Default action/purpose if not specified in ValidateCertificate
}

// NewAuthZENTrustValidator creates a validator using AuthZEN Trust Framework
// The pdpEndpoint should be the full URL to the /evaluation endpoint or base URL of the PDP
// Example: "https://trust-pdp.example.com" or "https://trust-pdp.example.com/evaluation"
//
// The default action is set to "signing" which is appropriate for AS4 message signing.
// Use WithDefaultAction() to change it for other use cases.
func NewAuthZENTrustValidator(pdpEndpoint string) *AuthZENTrustValidator {
	return &AuthZENTrustValidator{
		client:        authzenclient.New(pdpEndpoint),
		defaultAction: "signing", // Default for AS4 XML signature validation
	}
}

// NewAuthZENTrustValidatorWithClient creates a validator using a pre-configured authzenclient
// This is useful for testing with testserver or custom client configurations
func NewAuthZENTrustValidatorWithClient(client *authzenclient.Client) *AuthZENTrustValidator {
	return &AuthZENTrustValidator{
		client:        client,
		defaultAction: "signing",
	}
}

// WithDefaultAction sets the default action/purpose for certificate validation
// Common actions:
//   - "signing" or "digital-signature" - For AS4 message signing, code signing
//   - "tls-server" - For TLS server certificates
//   - "tls-client" - For TLS client certificates
//   - "encryption" - For encryption certificates
//   - Custom URIs/OIDs per your trust registry configuration
func (v *AuthZENTrustValidator) WithDefaultAction(action string) *AuthZENTrustValidator {
	v.defaultAction = action
	return v
}

// ValidateCertificate validates a certificate using AuthZEN Trust Framework
//
// This method:
// 1. Constructs an x5c array from the certificate and chain (per RFC 7517 Section 4.7)
// 2. Builds an AuthZEN request asking if the cert's subject name is bound to the public key
// 3. Sends the request to the PDP's /evaluation endpoint
// 4. Returns an error if the decision is false or if the request fails
func (v *AuthZENTrustValidator) ValidateCertificate(cert *x509.Certificate, chain []*x509.Certificate, purpose string) error {
	if cert == nil {
		return fmt.Errorf("%w: nil certificate", ErrInvalidCertificate)
	}

	// Build x5c array (base64-encoded DER certificates)
	// Per RFC 7517 Section 4.7: "Each string in the array is a base64-encoded
	// (Section 4 of [RFC4648] -- not base64url-encoded) DER [ITU.X690.2008]
	// PKIX certificate value"
	x5c := make([]interface{}, 0, 1+len(chain))
	x5c = append(x5c, base64.StdEncoding.EncodeToString(cert.Raw))

	for _, intermediate := range chain {
		x5c = append(x5c, base64.StdEncoding.EncodeToString(intermediate.Raw))
	}

	// Extract subject name from certificate
	// Try CommonName first, then DNS names, then fail
	subjectName := cert.Subject.CommonName
	if subjectName == "" && len(cert.DNSNames) > 0 {
		subjectName = cert.DNSNames[0]
	}
	if subjectName == "" && len(cert.EmailAddresses) > 0 {
		subjectName = cert.EmailAddresses[0]
	}
	if subjectName == "" && len(cert.URIs) > 0 {
		subjectName = cert.URIs[0].String()
	}
	if subjectName == "" {
		return fmt.Errorf("%w: certificate has no identifiable subject name", ErrInvalidCertificate)
	}

	// Determine action/purpose
	actionName := purpose
	if actionName == "" {
		actionName = v.defaultAction
	}

	// Build AuthZEN request per draft-johansson-authzen-trust-00
	request := &authzen.EvaluationRequest{
		// Section 4.1: Subject represents the name
		Subject: authzen.Subject{
			Type: "key", // Constant per spec
			ID:   subjectName,
		},
		// Section 4.2: Resource represents the public key
		Resource: authzen.Resource{
			Type: "x5c",       // Using X.509 certificate format
			ID:   subjectName, // Must match subject.ID
			Key:  x5c,         // Certificate chain
		},
	}

	// Section 4.3: Add action if purpose is specified
	if actionName != "" {
		request.Action = &authzen.Action{
			Name: actionName,
		}
	}

	// Send request to PDP
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	response, err := v.client.Evaluate(ctx, request)
	if err != nil {
		return fmt.Errorf("AuthZEN evaluation failed: %w", err)
	}

	// Section 5: Process response
	if !response.Decision {
		// Extract error message from context if available
		if response.Context != nil && response.Context.Reason != nil {
			return fmt.Errorf("%w: %v", ErrCertificateUntrusted, response.Context.Reason)
		}
		return ErrCertificateUntrusted
	}

	return nil
}

// ValidateCertificateChain validates a certificate chain using AuthZEN
func (v *AuthZENTrustValidator) ValidateCertificateChain(chain []*x509.Certificate, purpose string) error {
	if len(chain) == 0 {
		return fmt.Errorf("%w: empty chain", ErrInvalidCertificate)
	}
	return v.ValidateCertificate(chain[0], chain[1:], purpose)
}
