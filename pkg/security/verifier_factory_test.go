package security

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVerifierForCert_DispatchesOnKeyType(t *testing.T) {
	t.Run("RSA", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		cert := generateRSATestCert(t, &key.PublicKey, key)

		v, err := NewVerifierForCert(cert)
		require.NoError(t, err)
		require.NotNil(t, v)

		rsaSigner, err := NewRSASigner(key, cert, 0)
		require.NoError(t, err)
		signed, err := rsaSigner.SignEnvelope([]byte(ecdsaTestEnvelope))
		require.NoError(t, err)
		assert.NoError(t, v.VerifyEnvelope(signed))
	})

	t.Run("ECDSA-P256", func(t *testing.T) {
		key, cert := generateECDSATestCert(t, elliptic.P256())

		v, err := NewVerifierForCert(cert)
		require.NoError(t, err)
		require.NotNil(t, v)

		ecSigner, err := NewECDSASigner(key, cert)
		require.NoError(t, err)
		signed, err := ecSigner.SignEnvelope([]byte(ecdsaTestEnvelope))
		require.NoError(t, err)
		assert.NoError(t, v.VerifyEnvelope(signed))
	})

	t.Run("Ed25519", func(t *testing.T) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		template := &x509.Certificate{
			SerialNumber:          big.NewInt(7),
			Subject:               pkix.Name{CommonName: "ed25519.example.com"},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(certDER)
		require.NoError(t, err)

		v, err := NewVerifierForCert(cert)
		require.NoError(t, err)
		require.NotNil(t, v)

		signer, err := NewEd25519Signer(priv, cert)
		require.NoError(t, err)
		signed, err := signer.SignEnvelope([]byte(ecdsaTestEnvelope))
		require.NoError(t, err)
		assert.NoError(t, v.VerifyEnvelope(signed))
	})

	t.Run("nil cert", func(t *testing.T) {
		_, err := NewVerifierForCert(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "certificate is required")
	})
}
