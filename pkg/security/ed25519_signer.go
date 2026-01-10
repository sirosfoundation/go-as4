// Package security implements WS-Security signing
package security

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/beevik/etree"
	"github.com/leifj/signedxml"
	"github.com/sirosfoundation/go-as4/pkg/pmode"
)

// Ed25519Signer implements WS-Security XML signatures using Ed25519.
// Ed25519 support in XML signatures uses the algorithm URI:
// http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519 (RFC 9231)
//
// This is required by the eDelivery AS4 2.0 Common Usage Profile.
type Ed25519Signer struct {
	privateKey     ed25519.PrivateKey
	publicKey      ed25519.PublicKey
	cert           *x509.Certificate
	certPEM        []byte
	tokenReference pmode.TokenReferenceMethod
	certValidator  CertificateValidator
}

// Ed25519SignatureAlgorithmURI is the XML Signature algorithm URI for Ed25519
const Ed25519SignatureAlgorithmURI = "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519"

// NewEd25519Signer creates a new Ed25519-based XML signer.
func NewEd25519Signer(privateKey ed25519.PrivateKey, cert *x509.Certificate) (*Ed25519Signer, error) {
	return NewEd25519SignerWithTokenRef(privateKey, cert, pmode.TokenRefBinarySecurityToken)
}

// NewEd25519SignerWithTokenRef creates a new Ed25519-based XML signer with specific token reference method.
func NewEd25519SignerWithTokenRef(privateKey ed25519.PrivateKey, cert *x509.Certificate, tokenRef pmode.TokenReferenceMethod) (*Ed25519Signer, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}
	if cert == nil {
		return nil, fmt.Errorf("certificate is required")
	}

	publicKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate does not contain Ed25519 public key")
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// Default to BinarySecurityToken if not specified
	if tokenRef == "" {
		tokenRef = pmode.TokenRefBinarySecurityToken
	}

	return &Ed25519Signer{
		privateKey:     privateKey,
		publicKey:      publicKey,
		cert:           cert,
		certPEM:        certPEM,
		tokenReference: tokenRef,
		certValidator:  nil,
	}, nil
}

// NewEd25519Verifier creates a new Ed25519-based XML signature verifier (no private key required).
func NewEd25519Verifier(cert *x509.Certificate) (*Ed25519Signer, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is required")
	}

	publicKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate does not contain Ed25519 public key")
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	return &Ed25519Signer{
		privateKey:     nil, // No private key for verification
		publicKey:      publicKey,
		cert:           cert,
		certPEM:        certPEM,
		tokenReference: pmode.TokenRefBinarySecurityToken,
	}, nil
}

// WithCertificateValidator sets the certificate validator.
func (s *Ed25519Signer) WithCertificateValidator(validator CertificateValidator) *Ed25519Signer {
	s.certValidator = validator
	return s
}

// SignEnvelope signs an XML SOAP envelope with Ed25519 using signedxml.
func (s *Ed25519Signer) SignEnvelope(envelopeXML []byte) ([]byte, error) {
	return s.SignEnvelopeWithAttachments(envelopeXML, nil)
}

// SignEnvelopeWithAttachments signs an XML SOAP envelope along with MIME attachments.
func (s *Ed25519Signer) SignEnvelopeWithAttachments(envelopeXML []byte, attachments []Attachment) ([]byte, error) {
	if s.privateKey == nil {
		return nil, fmt.Errorf("private key is required for signing")
	}

	// Parse XML document
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(envelopeXML); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}

	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("no root element found")
	}

	// Ensure namespaces are declared on root
	s.ensureNamespaces(root)

	// Find SOAP Header
	header := root.FindElement("./Header")
	if header == nil {
		header = root.FindElement("./*[local-name()='Header']")
	}
	if header == nil {
		return nil, fmt.Errorf("SOAP Header not found")
	}

	// Create or find Security element
	security := header.FindElement("./Security")
	if security == nil {
		security = header.FindElement("./*[local-name()='Security']")
	}
	if security == nil {
		security = header.CreateElement("wsse:Security")
		security.CreateAttr("env:mustUnderstand", "true")
	}

	// Add BinarySecurityToken if using that token reference method
	bstID := "X509-" + generateID()
	if s.tokenReference == pmode.TokenRefBinarySecurityToken {
		bst := security.CreateElement("wsse:BinarySecurityToken")
		bst.CreateAttr("wsu:Id", bstID)
		bst.CreateAttr("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary")
		bst.CreateAttr("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")
		bst.SetText(base64.StdEncoding.EncodeToString(s.cert.Raw))
	}

	// Add Timestamp element
	timestampID := "TS-" + generateID()
	timestamp := security.CreateElement("wsu:Timestamp")
	timestamp.CreateAttr("wsu:Id", timestampID)
	now := time.Now().UTC()
	expires := now.Add(5 * time.Minute)
	created := timestamp.CreateElement("wsu:Created")
	created.SetText(now.Format("2006-01-02T15:04:05.000Z"))
	expiresElem := timestamp.CreateElement("wsu:Expires")
	expiresElem.SetText(expires.Format("2006-01-02T15:04:05.000Z"))

	// Find SOAP Body and ensure it has an ID
	body := root.FindElement("./Body")
	if body == nil {
		body = root.FindElement("./*[local-name()='Body']")
	}
	if body == nil {
		return nil, fmt.Errorf("SOAP Body not found")
	}

	bodyID := s.getOrCreateID(body, "id-")

	// Find Messaging header (if present)
	messaging := header.FindElement("./Messaging")
	if messaging == nil {
		messaging = header.FindElement("./*[local-name()='Messaging']")
	}
	var messagingID string
	if messaging != nil {
		if messaging.SelectAttrValue("env:mustUnderstand", "") == "" {
			messaging.CreateAttr("env:mustUnderstand", "true")
		}
		messagingID = s.getOrCreateID(messaging, "id-")
	}

	// Build the Signature element with SignedInfo template
	sig := security.CreateElement("ds:Signature")
	sig.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")

	signedInfo := sig.CreateElement("ds:SignedInfo")

	// Canonicalization method
	c14nMethod := signedInfo.CreateElement("ds:CanonicalizationMethod")
	c14nMethod.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
	c14nInclNS := c14nMethod.CreateElement("ec:InclusiveNamespaces")
	c14nInclNS.CreateAttr("xmlns:ec", "http://www.w3.org/2001/10/xml-exc-c14n#")
	c14nInclNS.CreateAttr("PrefixList", "env")

	// Signature method - Ed25519
	sigMethod := signedInfo.CreateElement("ds:SignatureMethod")
	sigMethod.CreateAttr("Algorithm", Ed25519SignatureAlgorithmURI)

	// Add References - Timestamp first, then Body, then Messaging
	s.addReference(signedInfo, timestampID, timestamp, "")
	s.addReference(signedInfo, bodyID, body, "")
	if messaging != nil {
		s.addReference(signedInfo, messagingID, messaging, "env")
	}

	// Add attachment references
	for _, att := range attachments {
		s.addAttachmentReference(signedInfo, att)
	}

	// Add SignatureValue placeholder
	sigValue := sig.CreateElement("ds:SignatureValue")
	sigValue.SetText("placeholder")

	// Add KeyInfo with SecurityTokenReference
	keyInfo := sig.CreateElement("ds:KeyInfo")
	if err := s.buildSecurityTokenReference(keyInfo, bstID); err != nil {
		return nil, fmt.Errorf("failed to build security token reference: %w", err)
	}

	// Convert to string for signedxml
	xmlStr, err := doc.WriteToString()
	if err != nil {
		return nil, fmt.Errorf("failed to write XML: %w", err)
	}

	// Use signedxml to sign the document
	signer, err := signedxml.NewSigner(xmlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	// Set the reference ID attribute to wsu:Id
	signer.SetReferenceIDAttribute("wsu:Id")

	// Sign with Ed25519 private key
	signedXML, err := signer.Sign(s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return []byte(signedXML), nil
}

// VerifyEnvelope verifies an Ed25519 XML signature.
func (s *Ed25519Signer) VerifyEnvelope(envelopeXML []byte) error {
	return s.VerifyEnvelopeWithAttachments(envelopeXML, nil)
}

// VerifyEnvelopeWithAttachments verifies an Ed25519 XML signature with attachments.
func (s *Ed25519Signer) VerifyEnvelopeWithAttachments(envelopeXML []byte, attachments []Attachment) error {
	validator, err := signedxml.NewValidator(string(envelopeXML))
	if err != nil {
		return fmt.Errorf("failed to create validator: %w", err)
	}

	// Add our certificate for validation
	validator.Certificates = append(validator.Certificates, *s.cert)

	// Set the reference ID attribute to wsu:Id
	validator.SetReferenceIDAttribute("wsu:Id")

	// Validate the signature
	_, err = validator.ValidateReferences()
	if err != nil {
		return fmt.Errorf("signature validation failed: %w", err)
	}

	// TODO: Verify attachment digests if attachments are provided

	return nil
}

// Helper methods

func (s *Ed25519Signer) ensureNamespaces(root *etree.Element) {
	if root.SelectAttr("xmlns:env") == nil {
		root.CreateAttr("xmlns:env", "http://www.w3.org/2003/05/soap-envelope")
	}
	if root.SelectAttr("xmlns:wsu") == nil {
		root.CreateAttr("xmlns:wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
	}
	if root.SelectAttr("xmlns:wsse") == nil {
		root.CreateAttr("xmlns:wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
	}
}

func (s *Ed25519Signer) getOrCreateID(elem *etree.Element, prefix string) string {
	// Check for existing wsu:Id
	id := elem.SelectAttrValue("wsu:Id", "")
	if id == "" {
		id = elem.SelectAttrValue("{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Id", "")
	}
	if id == "" {
		for _, attr := range elem.Attr {
			if attr.Key == "wsu:Id" || attr.FullKey() == "{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Id" {
				id = attr.Value
				break
			}
		}
	}
	if id == "" {
		id = prefix + generateID()
		elem.CreateAttr("wsu:Id", id)
	}
	return id
}

func (s *Ed25519Signer) addReference(signedInfo *etree.Element, id string, elem *etree.Element, prefixList string) {
	// Don't pre-compute digest - signedxml will compute it during Sign()
	ref := signedInfo.CreateElement("ds:Reference")
	ref.CreateAttr("URI", "#"+id)

	transforms := ref.CreateElement("ds:Transforms")
	transform := transforms.CreateElement("ds:Transform")
	transform.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
	if prefixList != "" {
		inclNs := transform.CreateElement("ec:InclusiveNamespaces")
		inclNs.CreateAttr("xmlns:ec", "http://www.w3.org/2001/10/xml-exc-c14n#")
		inclNs.CreateAttr("PrefixList", prefixList)
	}

	digestMethod := ref.CreateElement("ds:DigestMethod")
	digestMethod.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")

	// Placeholder - signedxml will fill this in
	digestValueElem := ref.CreateElement("ds:DigestValue")
	digestValueElem.SetText("placeholder")
}

func (s *Ed25519Signer) addAttachmentReference(signedInfo *etree.Element, att Attachment) {
	// Compute digest of attachment content
	hash := sha256.Sum256(att.Data)
	digestValue := base64.StdEncoding.EncodeToString(hash[:])

	ref := signedInfo.CreateElement("ds:Reference")
	ref.CreateAttr("URI", "cid:"+att.ContentID)

	transforms := ref.CreateElement("ds:Transforms")
	transform := transforms.CreateElement("ds:Transform")
	transform.CreateAttr("Algorithm", "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform")

	digestMethod := ref.CreateElement("ds:DigestMethod")
	digestMethod.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")

	digestValueElem := ref.CreateElement("ds:DigestValue")
	digestValueElem.SetText(digestValue)
}

func (s *Ed25519Signer) buildSecurityTokenReference(parent *etree.Element, bstID string) error {
	secTokenRef := parent.CreateElement("wsse:SecurityTokenReference")

	switch s.tokenReference {
	case pmode.TokenRefBinarySecurityToken:
		reference := secTokenRef.CreateElement("wsse:Reference")
		reference.CreateAttr("URI", "#"+bstID)
		reference.CreateAttr("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")

	case pmode.TokenRefKeyIdentifier:
		keyID := secTokenRef.CreateElement("wsse:KeyIdentifier")
		keyID.CreateAttr("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier")
		keyID.CreateAttr("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary")

		// Extract Subject Key Identifier from certificate extensions
		var skiBytes []byte
		for _, ext := range s.cert.Extensions {
			if ext.Id.Equal([]int{2, 5, 29, 14}) {
				if len(ext.Value) > 2 {
					skiBytes = ext.Value[2:]
				}
				break
			}
		}
		if len(skiBytes) == 0 {
			// Fallback: compute SHA-256 hash of public key
			hash := sha256.Sum256(s.publicKey)
			skiBytes = hash[:20]
		}
		keyID.SetText(base64.StdEncoding.EncodeToString(skiBytes))

	case pmode.TokenRefIssuerSerial:
		x509Data := secTokenRef.CreateElement("ds:X509Data")
		x509Data.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
		issuerSerial := x509Data.CreateElement("ds:X509IssuerSerial")
		issuerName := issuerSerial.CreateElement("ds:X509IssuerName")
		issuerName.SetText(s.cert.Issuer.String())
		serialNumber := issuerSerial.CreateElement("ds:X509SerialNumber")
		serialNumber.SetText(s.cert.SerialNumber.String())

	case pmode.TokenRefThumbprint:
		keyID := secTokenRef.CreateElement("wsse:KeyIdentifier")
		keyID.CreateAttr("ValueType", "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1")
		thumbprint := sha256.Sum256(s.cert.Raw)
		keyID.SetText(base64.StdEncoding.EncodeToString(thumbprint[:]))

	default:
		return fmt.Errorf("unsupported token reference method: %s", s.tokenReference)
	}

	return nil
}

// Legacy alias for backward compatibility
var NewXMLSigner = NewEd25519Signer
