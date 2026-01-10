// Package security implements RSA-based XML digital signatures for AS4
package security

import (
	"crypto"
	"crypto/rsa"
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

// SignatureMode defines the RSA signature padding scheme
type SignatureMode int

const (
	// SignatureModePKCS1v15 uses PKCS#1 v1.5 padding (required for most XML signatures)
	SignatureModePKCS1v15 SignatureMode = iota
	// SignatureModePSS uses RSA-PSS padding (more secure but less common in XML)
	SignatureModePSS
)

// RSASigner handles XML digital signatures using RSA keys.
// Uses signedxml library for all signature operations.
type RSASigner struct {
	privateKey     *rsa.PrivateKey
	publicKey      *rsa.PublicKey
	cert           *x509.Certificate
	certPEM        []byte
	hashAlgo       crypto.Hash // Hash algorithm for signature
	digestHashAlgo crypto.Hash // Hash algorithm for digest (can be different from signature)
	tokenReference pmode.TokenReferenceMethod
	certValidator  CertificateValidator
	signatureMode  SignatureMode // PKCS#1 v1.5 or PSS
}

// NewRSASigner creates a new RSA-based XML signer with PKCS#1 v1.5 mode
func NewRSASigner(privateKey *rsa.PrivateKey, cert *x509.Certificate, hashAlgo crypto.Hash) (*RSASigner, error) {
	return NewRSASignerWithTokenRef(privateKey, cert, hashAlgo, hashAlgo, pmode.TokenRefBinarySecurityToken)
}

// NewRSASignerWithTokenRef creates a new RSA-based XML signer with specific token reference method
func NewRSASignerWithTokenRef(privateKey *rsa.PrivateKey, cert *x509.Certificate, hashAlgo crypto.Hash, digestHashAlgo crypto.Hash, tokenRef pmode.TokenReferenceMethod) (*RSASigner, error) {
	return NewRSASignerWithMode(privateKey, cert, hashAlgo, digestHashAlgo, tokenRef, SignatureModePKCS1v15)
}

// NewRSAVerifier creates a new RSA-based XML signature verifier (no private key required)
func NewRSAVerifier(cert *x509.Certificate, hashAlgo crypto.Hash, digestHashAlgo crypto.Hash, mode SignatureMode) (*RSASigner, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is required")
	}

	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate does not contain RSA public key")
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// Default to SHA-256 if not specified
	if hashAlgo == 0 {
		hashAlgo = crypto.SHA256
	}
	if digestHashAlgo == 0 {
		digestHashAlgo = crypto.SHA256
	}

	return &RSASigner{
		privateKey:     nil, // No private key for verification
		publicKey:      publicKey,
		cert:           cert,
		certPEM:        certPEM,
		hashAlgo:       hashAlgo,
		digestHashAlgo: digestHashAlgo,
		tokenReference: pmode.TokenRefBinarySecurityToken,
		signatureMode:  mode,
	}, nil
}

// NewRSASignerWithMode creates a new RSA-based XML signer with specific signature mode
func NewRSASignerWithMode(privateKey *rsa.PrivateKey, cert *x509.Certificate, hashAlgo crypto.Hash, digestHashAlgo crypto.Hash, tokenRef pmode.TokenReferenceMethod, mode SignatureMode) (*RSASigner, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}
	if cert == nil {
		return nil, fmt.Errorf("certificate is required")
	}

	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate does not contain RSA public key")
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// Default to SHA-256 if not specified
	if hashAlgo == 0 {
		hashAlgo = crypto.SHA256
	}
	if digestHashAlgo == 0 {
		digestHashAlgo = crypto.SHA256
	}

	// Default to BinarySecurityToken if not specified
	if tokenRef == "" {
		tokenRef = pmode.TokenRefBinarySecurityToken
	}

	return &RSASigner{
		privateKey:     privateKey,
		publicKey:      publicKey,
		cert:           cert,
		certPEM:        certPEM,
		hashAlgo:       hashAlgo,
		digestHashAlgo: digestHashAlgo,
		tokenReference: tokenRef,
		certValidator:  nil,
		signatureMode:  mode,
	}, nil
}

// WithCertificateValidator sets the certificate validator
func (s *RSASigner) WithCertificateValidator(validator CertificateValidator) *RSASigner {
	s.certValidator = validator
	return s
}

// SignEnvelope signs an XML SOAP envelope with RSA using signedxml.
func (s *RSASigner) SignEnvelope(envelopeXML []byte) ([]byte, error) {
	return s.SignEnvelopeWithAttachments(envelopeXML, nil)
}

// SignEnvelopeWithAttachments signs an XML SOAP envelope along with MIME attachments.
func (s *RSASigner) SignEnvelopeWithAttachments(envelopeXML []byte, attachments []Attachment) ([]byte, error) {
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

	// Signature method - RSA with configured hash
	sigMethod := signedInfo.CreateElement("ds:SignatureMethod")
	sigMethod.CreateAttr("Algorithm", s.getSignatureAlgorithmURI())

	// Add References - Timestamp first, then Body, then Messaging
	s.addReference(signedInfo, timestampID, "")
	s.addReference(signedInfo, bodyID, "")
	if messaging != nil {
		s.addReference(signedInfo, messagingID, "env")
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

	// Sign with RSA private key
	signedXML, err := signer.Sign(s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return []byte(signedXML), nil
}

// VerifyEnvelope verifies an RSA XML signature.
func (s *RSASigner) VerifyEnvelope(envelopeXML []byte) error {
	return s.VerifyEnvelopeWithAttachments(envelopeXML, nil)
}

// VerifyEnvelopeWithAttachments verifies an RSA XML signature with attachments.
func (s *RSASigner) VerifyEnvelopeWithAttachments(envelopeXML []byte, attachments []Attachment) error {
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

func (s *RSASigner) ensureNamespaces(root *etree.Element) {
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

func (s *RSASigner) getOrCreateID(elem *etree.Element, prefix string) string {
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

func (s *RSASigner) addReference(signedInfo *etree.Element, id string, prefixList string) {
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
	digestMethod.CreateAttr("Algorithm", s.getDigestAlgorithmURI())

	// Placeholder - signedxml will fill this in
	digestValueElem := ref.CreateElement("ds:DigestValue")
	digestValueElem.SetText("placeholder")
}

func (s *RSASigner) addAttachmentReference(signedInfo *etree.Element, att Attachment) {
	// Compute digest of attachment content
	hash := sha256.Sum256(att.Data)
	digestValue := base64.StdEncoding.EncodeToString(hash[:])

	// Content-ID URI format: cid:payload-1@as4.siros.org (without angle brackets)
	contentID := att.ContentID
	if len(contentID) > 0 && contentID[0] == '<' {
		contentID = contentID[1 : len(contentID)-1] // Remove < and >
	}

	ref := signedInfo.CreateElement("ds:Reference")
	ref.CreateAttr("URI", "cid:"+contentID)

	transforms := ref.CreateElement("ds:Transforms")
	transform := transforms.CreateElement("ds:Transform")
	transform.CreateAttr("Algorithm", "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform")

	digestMethod := ref.CreateElement("ds:DigestMethod")
	digestMethod.CreateAttr("Algorithm", s.getDigestAlgorithmURI())

	digestValueElem := ref.CreateElement("ds:DigestValue")
	digestValueElem.SetText(digestValue)
}

func (s *RSASigner) buildSecurityTokenReference(parent *etree.Element, bstID string) error {
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
			pubKeyBytes, err := x509.MarshalPKIXPublicKey(s.publicKey)
			if err != nil {
				return fmt.Errorf("failed to marshal public key: %w", err)
			}
			hash := sha256.Sum256(pubKeyBytes)
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

// getSignatureAlgorithmURI returns the XML signature algorithm URI
func (s *RSASigner) getSignatureAlgorithmURI() string {
	switch s.hashAlgo {
	case crypto.SHA1:
		return "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	case crypto.SHA256:
		return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	case crypto.SHA384:
		return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	case crypto.SHA512:
		return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	default:
		return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	}
}

// getDigestAlgorithmURI returns the XML digest algorithm URI
func (s *RSASigner) getDigestAlgorithmURI() string {
	switch s.digestHashAlgo {
	case crypto.SHA1:
		return "http://www.w3.org/2000/09/xmldsig#sha1"
	case crypto.SHA256:
		return AlgorithmSHA256
	case crypto.SHA384:
		return "http://www.w3.org/2001/04/xmldsig-more#sha384"
	case crypto.SHA512:
		return "http://www.w3.org/2001/04/xmlenc#sha512"
	default:
		return AlgorithmSHA256
	}
}
