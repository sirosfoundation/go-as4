package security

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

// NewVerifierForCert returns a signature verifier whose algorithm matches the
// public key in the given certificate (RSA -> RSA-SHA256, ECDSA -> curve-matched
// ECDSA, Ed25519 -> Ed25519). The concrete signature algorithm of a received
// message is taken from the signed XML itself; the verifier chosen here only
// has to match the certificate's key type.
func NewVerifierForCert(cert *x509.Certificate) (Signer, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is required")
	}

	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return NewRSAVerifier(cert, crypto.SHA256, crypto.SHA256, SignatureModePKCS1v15)
	case *ecdsa.PublicKey:
		return NewECDSAVerifier(cert)
	case ed25519.PublicKey:
		return NewEd25519Verifier(cert)
	default:
		return nil, fmt.Errorf("unsupported public key type for verification: %T", cert.PublicKey)
	}
}
