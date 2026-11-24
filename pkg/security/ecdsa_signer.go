// Package security implements ECDSA-based XML digital signatures for AS4
package security

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/leifj/signedxml"
	"github.com/sirosfoundation/go-as4/pkg/pmode"
)

// ECDSASigner handles XML digital signatures using ECDSA keys
// (e.g. ES256: ecdsa-sha256 with a P-256 key, exclusive c14n).
//
// Signing is implemented locally because the underlying signedxml
// library validates ECDSA signatures but does not produce them;
// canonicalization and digest computation reuse the exported
// signedxml exclusive-canonicalization algorithms so that a
// signature produced here validates with any conformant
// xmldsig implementation (including signedxml itself).
type ECDSASigner struct {
	privateKey     *ecdsa.PrivateKey
	publicKey      *ecdsa.PublicKey
	cert           *x509.Certificate
	certPEM        []byte
	hashAlgo       crypto.Hash // Hash algorithm for signature (fixed by curve)
	digestHashAlgo crypto.Hash // Hash algorithm for digests
	tokenReference pmode.TokenReferenceMethod
	certValidator  CertificateValidator
}

// NewECDSASigner creates a new ECDSA-based XML signer.
// The signature hash is derived from the key's curve
// (P-256 -> SHA-256, P-384 -> SHA-384, P-521 -> SHA-512).
func NewECDSASigner(privateKey *ecdsa.PrivateKey, cert *x509.Certificate) (*ECDSASigner, error) {
	return NewECDSASignerWithTokenRef(privateKey, cert, pmode.TokenRefBinarySecurityToken)
}

// NewECDSASignerWithTokenRef creates a new ECDSA-based XML signer with a
// specific token reference method.
func NewECDSASignerWithTokenRef(privateKey *ecdsa.PrivateKey, cert *x509.Certificate, tokenRef pmode.TokenReferenceMethod) (*ECDSASigner, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}
	if cert == nil {
		return nil, fmt.Errorf("certificate is required")
	}

	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate does not contain an ECDSA public key")
	}

	hashAlgo, err := curveHash(privateKey.Curve)
	if err != nil {
		return nil, err
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

	return &ECDSASigner{
		privateKey:     privateKey,
		publicKey:      publicKey,
		cert:           cert,
		certPEM:        certPEM,
		hashAlgo:       hashAlgo,
		digestHashAlgo: hashAlgo,
		tokenReference: tokenRef,
		certValidator:  nil,
	}, nil
}

// NewECDSAVerifier creates a new ECDSA-based XML signature verifier
// (no private key required). Verification itself derives the
// algorithm from the signed XML, so the default hash is only a
// fallback for signers that report one.
func NewECDSAVerifier(cert *x509.Certificate) (*ECDSASigner, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is required")
	}

	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate does not contain an ECDSA public key")
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	return &ECDSASigner{
		privateKey:     nil, // No private key for verification
		publicKey:      publicKey,
		cert:           cert,
		certPEM:        certPEM,
		hashAlgo:       crypto.SHA256,
		digestHashAlgo: crypto.SHA256,
		tokenReference: pmode.TokenRefBinarySecurityToken,
	}, nil
}

// WithCertificateValidator sets the certificate validator
func (s *ECDSASigner) WithCertificateValidator(validator CertificateValidator) *ECDSASigner {
	s.certValidator = validator
	return s
}

// SignEnvelope signs an XML SOAP envelope with ECDSA.
func (s *ECDSASigner) SignEnvelope(envelopeXML []byte) ([]byte, error) {
	return s.SignEnvelopeWithAttachments(envelopeXML, nil)
}

// SignEnvelopeWithAttachments signs an XML SOAP envelope along with MIME attachments.
func (s *ECDSASigner) SignEnvelopeWithAttachments(envelopeXML []byte, attachments []Attachment) ([]byte, error) {
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
	s.addTimestamp(timestamp)

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

	// Signature method - ECDSA with curve-matched hash
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

	// Compute the digest value of every internal reference.
	// (Attachment/cid: references carry pre-computed digests.)
	if err := s.computeReferenceDigests(doc, signedInfo); err != nil {
		return nil, fmt.Errorf("failed to compute reference digests: %w", err)
	}

	// Canonicalize SignedInfo and sign it with ECDSA
	signatureB64, err := s.signSignedInfo(signedInfo, c14nMethod)
	if err != nil {
		return nil, fmt.Errorf("failed to sign SignedInfo: %w", err)
	}
	sigValue.SetText(signatureB64)

	return doc.WriteToBytes()
}

// VerifyEnvelope verifies an ECDSA XML signature.
func (s *ECDSASigner) VerifyEnvelope(envelopeXML []byte) error {
	return s.VerifyEnvelopeWithAttachments(envelopeXML, nil)
}

// VerifyEnvelopeWithAttachments verifies an ECDSA XML signature with attachments.
func (s *ECDSASigner) VerifyEnvelopeWithAttachments(envelopeXML []byte, attachments []Attachment) error {
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

// addTimestamp adds the wsu:Timestamp element children
func (s *ECDSASigner) addTimestamp(timestamp *etree.Element) {
	now := time.Now().UTC()
	expires := now.Add(5 * time.Minute)
	created := timestamp.CreateElement("wsu:Created")
	created.SetText(now.Format("2006-01-02T15:04:05.000Z"))
	expiresElem := timestamp.CreateElement("wsu:Expires")
	expiresElem.SetText(expires.Format("2006-01-02T15:04:05.000Z"))
}

func (s *ECDSASigner) ensureNamespaces(root *etree.Element) {
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

func (s *ECDSASigner) getOrCreateID(elem *etree.Element, prefix string) string {
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

func (s *ECDSASigner) addReference(signedInfo *etree.Element, id string, prefixList string) {
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

	// Placeholder - filled in by computeReferenceDigests
	digestValueElem := ref.CreateElement("ds:DigestValue")
	digestValueElem.SetText("placeholder")
}

func (s *ECDSASigner) addAttachmentReference(signedInfo *etree.Element, att Attachment) {
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

func (s *ECDSASigner) buildSecurityTokenReference(parent *etree.Element, bstID string) error {
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

// computeReferenceDigests fills in the DigestValue of every internal
// (non-cid:) Reference in SignedInfo. It mirrors the digest logic of
// signedxml's Signer.setDigest: each referenced element is canonicalized
// in its original document context (so inherited namespace declarations
// are handled correctly) using the exclusive c14n algorithm named by the
// Reference's Transform, then hashed.
func (s *ECDSASigner) computeReferenceDigests(doc *etree.Document, signedInfo *etree.Element) error {
	canon := signedxml.ExclusiveCanonicalization{}

	for _, ref := range signedInfo.FindElements("./Reference") {
		uri := ref.SelectAttrValue("URI", "")
		if strings.HasPrefix(uri, "cid:") {
			continue // attachment digests are pre-computed
		}
		if !strings.HasPrefix(uri, "#") {
			return fmt.Errorf("unsupported reference URI: %s", uri)
		}
		id := strings.TrimPrefix(uri, "#")
		if id == "" {
			return fmt.Errorf("reference without URI is not supported")
		}

		// Find the referenced element in its original context
		refElement := doc.FindElement(fmt.Sprintf(".//[@wsu:Id='%s']", id))
		if refElement == nil {
			return fmt.Errorf("unable to find referenced element for URI %s", uri)
		}

		// Build the transform content (the serialized Transform element,
		// e.g. containing ec:InclusiveNamespaces) exactly as signedxml does
		transformContent := ""
		if transforms := ref.SelectElement("Transforms"); transforms != nil {
			for _, transform := range transforms.SelectElements("Transform") {
				if len(transform.ChildElements()) > 0 {
					tDoc := etree.NewDocument()
					tDoc.SetRoot(transform.Copy())
					content, err := tDoc.WriteToString()
					if err != nil {
						return fmt.Errorf("failed to serialize transform: %w", err)
					}
					transformContent = content
				}
			}
		}

		canonicalXML, err := canon.ProcessElement(refElement, transformContent)
		if err != nil {
			return fmt.Errorf("failed to canonicalize element for URI %s: %w", uri, err)
		}

		hasher := s.digestHashAlgo.New()
		hasher.Write([]byte(canonicalXML))
		digest := base64.StdEncoding.EncodeToString(hasher.Sum(nil))

		digestValueElement := ref.SelectElement("DigestValue")
		if digestValueElement == nil {
			return fmt.Errorf("DigestValue not found for URI %s", uri)
		}
		digestValueElement.SetText(digest)
	}

	return nil
}

// signSignedInfo canonicalizes SignedInfo (with the c14n parameters from
// the Signature's CanonicalizationMethod), hashes it and produces the
// base64-encoded ECDSA signature in the raw r||s form required by
// XML-DSig (RFC 4050 style: each component zero-padded to the curve size).
func (s *ECDSASigner) signSignedInfo(signedInfo *etree.Element, c14nMethod *etree.Element) (string, error) {
	// Serialize the CanonicalizationMethod element (including its
	// ec:InclusiveNamespaces child, if any) as the transform content,
	// exactly like signedxml's parseCanonAlgorithm does.
	transformContent := ""
	if len(c14nMethod.ChildElements()) > 0 {
		tDoc := etree.NewDocument()
		tDoc.SetRoot(c14nMethod.Copy())
		content, err := tDoc.WriteToString()
		if err != nil {
			return "", fmt.Errorf("failed to serialize canonicalization method: %w", err)
		}
		transformContent = content
	}

	canon := signedxml.ExclusiveCanonicalization{}
	canonSignedInfo, err := canon.ProcessElement(signedInfo, transformContent)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize SignedInfo: %w", err)
	}

	hasher := s.hashAlgo.New()
	hasher.Write([]byte(canonSignedInfo))
	hashed := hasher.Sum(nil)

	r, sigS, err := ecdsa.Sign(rand.Reader, s.privateKey, hashed)
	if err != nil {
		return "", fmt.Errorf("failed to compute ECDSA signature: %w", err)
	}

	// XML-DSig encodes ECDSA signatures as the raw concatenation r||s,
	// each component zero-padded to the curve's component size
	// (32 bytes for P-256). This is the inverse of the raw-to-ASN.1
	// conversion performed by the signedxml validator.
	componentSize := (s.privateKey.Curve.Params().N.BitLen() + 7) / 8
	rawSig := append(leftPad(r.Bytes(), componentSize), leftPad(sigS.Bytes(), componentSize)...)

	return base64.StdEncoding.EncodeToString(rawSig), nil
}

// leftPad zero-pads b to exactly n bytes
func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	padded := make([]byte, n)
	copy(padded[n-len(b):], b)
	return padded
}

// getSignatureAlgorithmURI returns the XML signature algorithm URI
func (s *ECDSASigner) getSignatureAlgorithmURI() string {
	switch s.hashAlgo {
	case crypto.SHA256:
		return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	case crypto.SHA384:
		return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	case crypto.SHA512:
		return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
	default:
		return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	}
}

// getDigestAlgorithmURI returns the XML digest algorithm URI
func (s *ECDSASigner) getDigestAlgorithmURI() string {
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

// curveHash returns the hash matching an ECDSA curve
func curveHash(curve elliptic.Curve) (crypto.Hash, error) {
	switch curve {
	case elliptic.P256():
		return crypto.SHA256, nil
	case elliptic.P384():
		return crypto.SHA384, nil
	case elliptic.P521():
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported ECDSA curve %s: use P-256 (secp256r1) for ecdsa-sha256/ES256, P-384 for ecdsa-sha384 or P-521 for ecdsa-sha512",
			curveName(curve))
	}
}

// curveName returns a printable name for a curve
func curveName(curve elliptic.Curve) string {
	if params := curve.Params(); params != nil {
		return params.Name
	}
	return "unknown"
}
