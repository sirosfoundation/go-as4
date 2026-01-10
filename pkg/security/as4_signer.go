// Package security implements AS4 message signing using goxmldsig
package security

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/beevik/etree"
	"github.com/leifj/signedxml"
	"github.com/sirosfoundation/go-as4/pkg/pmode"
)

// AS4Signer handles WS-Security signing for AS4 messages using signedxml
type AS4Signer struct {
	privateKey     *rsa.PrivateKey
	cert           *x509.Certificate
	hashAlgo       crypto.Hash
	tokenReference pmode.TokenReferenceMethod
}

// NewAS4Signer creates a new AS4 signer using goxmldsig for proper C14N
func NewAS4Signer(privateKey *rsa.PrivateKey, cert *x509.Certificate, hashAlgo crypto.Hash, tokenRef pmode.TokenReferenceMethod) (*AS4Signer, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}
	if cert == nil {
		return nil, fmt.Errorf("certificate is required")
	}

	return &AS4Signer{
		privateKey:     privateKey,
		cert:           cert,
		hashAlgo:       hashAlgo,
		tokenReference: tokenRef,
	}, nil
}

// SignEnvelope signs a SOAP envelope with WS-Security for AS4
func (s *AS4Signer) SignEnvelope(envelopeXML []byte) ([]byte, error) {
	// Parse the envelope
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(envelopeXML); err != nil {
		return nil, fmt.Errorf("failed to parse envelope: %w", err)
	}

	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("no root element found")
	}

	// Add WS-Security namespace declarations to root if not present
	if root.SelectAttr("xmlns:env") == nil {
		root.CreateAttr("xmlns:env", "http://www.w3.org/2003/05/soap-envelope")
	}
	if root.SelectAttr("xmlns:wsu") == nil {
		root.CreateAttr("xmlns:wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
	}
	if root.SelectAttr("xmlns:wsse") == nil {
		root.CreateAttr("xmlns:wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
	}

	// Find SOAP Header
	header := root.FindElement("./Header")
	if header == nil {
		header = root.FindElement("./*[local-name()='Header']")
	}
	if header == nil {
		return nil, fmt.Errorf("SOAP Header not found")
	}

	// Find or create Security element
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

	// Find Body and ensure it has wsu:Id
	body := root.FindElement("./Body")
	if body == nil {
		body = root.FindElement("./*[local-name()='Body']")
	}
	if body == nil {
		return nil, fmt.Errorf("SOAP Body not found")
	}

	bodyID := ensureWSUId(body)

	// Find Messaging header and ensure it has wsu:Id
	messaging := header.FindElement("./Messaging")
	if messaging == nil {
		messaging = header.FindElement("./*[local-name()='Messaging']")
	}
	var messagingID string
	if messaging != nil {
		messagingID = ensureWSUId(messaging)
	}

	// Create signature referencing Body and Messaging
	// Per AS4 conformance samples: Body reference comes first
	// Note: we need the IDs for logging/debugging but goxmldsig finds elements by their IDs
	_ = bodyID      // Used by goxmldsig internally
	_ = messagingID // Used by goxmldsig internally

	elementsToSign := []*etree.Element{body}
	if messaging != nil {
		elementsToSign = append(elementsToSign, messaging)
	}

	// Use goxmldsig to create the signature
	sig, err := s.createAS4Signature(elementsToSign)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature: %w", err)
	}

	// Add KeyInfo with SecurityTokenReference
	keyInfo := sig.FindElement(".//KeyInfo")
	if keyInfo == nil {
		keyInfo = sig.CreateElement("ds:KeyInfo")
	}

	secTokenRef := keyInfo.CreateElement("wsse:SecurityTokenReference")

	switch s.tokenReference {
	case pmode.TokenRefBinarySecurityToken:
		ref := secTokenRef.CreateElement("wsse:Reference")
		ref.CreateAttr("URI", "#"+bstID)
		ref.CreateAttr("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")

	case pmode.TokenRefKeyIdentifier:
		// Use Subject Key Identifier
		keyID := secTokenRef.CreateElement("wsse:KeyIdentifier")
		keyID.CreateAttr("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier")
		keyID.CreateAttr("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary")

		// Extract SKI from certificate
		var skiBytes []byte
		for _, ext := range s.cert.Extensions {
			if ext.Id.Equal([]int{2, 5, 29, 14}) {
				if len(ext.Value) > 2 {
					skiBytes = ext.Value[2:]
				}
				break
			}
		}
		if len(skiBytes) > 0 {
			keyID.SetText(base64.StdEncoding.EncodeToString(skiBytes))
		}
	}

	// Add signature to Security element
	security.AddChild(sig)

	// Serialize back to XML WITHOUT indentation
	// Important: Indentation adds whitespace text nodes which affect canonicalization
	// We need to send compact XML so that when Domibus parses and canonicalizes it,
	// it gets the same canonical form we used for signing
	signedXML, err := doc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize signed document: %w", err)
	}

	return signedXML, nil
}

// createAS4Signature creates an XML-DSig signature for the given elements
func (s *AS4Signer) createAS4Signature(elements []*etree.Element) (*etree.Element, error) {
	// Create Signature element with ds namespace declaration
	sig := etree.NewElement("ds:Signature")
	sig.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")

	// Create SignedInfo (need to explicitly declare namespaces for canonicalization)
	signedInfo := sig.CreateElement("ds:SignedInfo")
	// Exclusive C14N requires namespace declarations to be present on the element
	// even if they're declared on parent elements
	signedInfo.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	signedInfo.CreateAttr("xmlns:env", "http://www.w3.org/2003/05/soap-envelope")

	// CanonicalizationMethod with InclusiveNamespaces
	c14nMethod := signedInfo.CreateElement("ds:CanonicalizationMethod")
	c14nMethod.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
	c14nInclNS := c14nMethod.CreateElement("ec:InclusiveNamespaces")
	c14nInclNS.CreateAttr("xmlns:ec", "http://www.w3.org/2001/10/xml-exc-c14n#")
	c14nInclNS.CreateAttr("PrefixList", "env") // Include SOAP envelope namespace

	// SignatureMethod - hardcode RSA-SHA256 for now
	sigMethod := signedInfo.CreateElement("ds:SignatureMethod")
	sigMethod.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")

	// Create canonicalizer for elements (without prefix list)
	elemCanonicalizer := signedxml.ExclusiveCanonicalization{WithComments: false}

	// Add Reference for each element
	for _, elem := range elements {
		elemID := elem.SelectAttrValue("wsu:Id", "")
		if elemID == "" {
			elemID = elem.SelectAttrValue("{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Id", "")
		}
		if elemID == "" {
			return nil, fmt.Errorf("element must have wsu:Id attribute")
		}

		// Canonicalize the element using Exclusive C14N WITHOUT prefix list
		// signedxml handles namespace declarations correctly
		canonical, err := elemCanonicalizer.ProcessElement(elem, "")
		if err != nil {
			return nil, fmt.Errorf("failed to canonicalize element: %w", err)
		}

		// Compute digest
		hash := sha256.New()
		hash.Write([]byte(canonical))
		digest := hash.Sum(nil)

		// Create Reference
		ref := signedInfo.CreateElement("ds:Reference")
		ref.CreateAttr("URI", "#"+elemID)

		// Transforms - use Exclusive C14N WITHOUT InclusiveNamespaces child
		// (AS4 samples show Transform has no children)
		transforms := ref.CreateElement("ds:Transforms")
		transform := transforms.CreateElement("ds:Transform")
		transform.CreateAttr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")

		// DigestMethod
		digestMethod := ref.CreateElement("ds:DigestMethod")
		digestMethod.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")

		// DigestValue
		digestValue := ref.CreateElement("ds:DigestValue")
		digestValue.SetText(base64.StdEncoding.EncodeToString(digest))
	}

	// Canonicalize SignedInfo with "env" prefix list (for SOAP envelope namespace)
	// Use signedxml's ExclusiveCanonicalization with InclusiveNamespaces transform XML
	signedInfoCanonicalizer := signedxml.ExclusiveCanonicalization{WithComments: false}
	transformXML := `<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="env"/>`
	canonicalSignedInfo, err := signedInfoCanonicalizer.ProcessElement(signedInfo, transformXML)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize SignedInfo: %w", err)
	}

	// Hash the canonical SignedInfo
	hash := sha256.New()
	hash.Write([]byte(canonicalSignedInfo))
	digest := hash.Sum(nil)

	// Sign the digest using RSA
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// Add SignatureValue
	sigValue := sig.CreateElement("ds:SignatureValue")
	sigValue.SetText(base64.StdEncoding.EncodeToString(signature))

	return sig, nil
}

// ensureWSUId ensures an element has a wsu:Id attribute and returns it.
// Also ensures the wsu namespace is declared on the element for Exclusive C14N.
func ensureWSUId(elem *etree.Element) string {
	// Ensure wsu namespace is declared on this element for Exclusive C14N
	if elem.SelectAttr("xmlns:wsu") == nil {
		elem.CreateAttr("xmlns:wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
	}

	// Check for existing wsu:Id
	id := elem.SelectAttrValue("wsu:Id", "")
	if id == "" {
		id = elem.SelectAttrValue("{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Id", "")
	}
	if id == "" {
		// Check all attributes
		for _, attr := range elem.Attr {
			if attr.Key == "wsu:Id" || attr.FullKey() == "{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Id" {
				id = attr.Value
				break
			}
		}
	}
	if id == "" {
		// Generate new ID - use simple format like AS4 samples
		id = "_" + generateID()
		elem.CreateAttr("wsu:Id", id)
	}
	return id
}

// SignEnvelopeWithAttachments is not yet implemented for goxmldsig version
func (s *AS4Signer) SignEnvelopeWithAttachments(envelopeXML []byte, attachments []Attachment) ([]byte, error) {
	return nil, fmt.Errorf("SignEnvelopeWithAttachments not yet implemented with goxmldsig")
}
