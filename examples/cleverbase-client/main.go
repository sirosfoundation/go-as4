// Command cleverbase-client sends a signed AS4 UserMessage to Cleverbase's
// public TEST access point (WE BUILD QERDS interop, CS-16).
//
// It is the day-1 slice of the AS4 <-> WMP gateway: build the message per the
// evidence collected from Cleverbase's interop pages and SMP metadata, sign it
// with the gateway's test-CA key, MIME-serialize it and POST it, then print the
// exact response (Receipt or ebMS Error).
//
// Usage:
//
//	go run ./examples/cleverbase-client -algo=ecdsa -dry-run   # print the wire message
//	go run ./examples/cleverbase-client -algo=ecdsa -local    # end-to-end against a local go-as4 server
//	go run ./examples/cleverbase-client -algo=ecdsa           # ONE test message to Cleverbase TEST
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/beevik/etree"
	"github.com/google/uuid"
	"github.com/sirosfoundation/go-as4/pkg/message"
	"github.com/sirosfoundation/go-as4/pkg/pmode"
	"github.com/sirosfoundation/go-as4/pkg/security"
	phase4server "github.com/sirosfoundation/go-as4/tests/interop/phase4/server"
)

const (
	iso6523 = "urn:oasis:names:tc:ebcore:partyid-type:iso6523"

	// Cleverbase WE BUILD TEST defaults (from https://demo.cleverbase.io/interop/
	// and their SMP service metadata).
	defaultEndpoint = "https://as4-wb.business-sandbox.cleverbase.io/as4"
	defaultToID     = "67419925"  // Cleverbase ID B.V. (TEST), on erds-wb
	defaultToScheme = "0106"      // KvK-nummer
	defaultFromID   = "5595421925" // SIROS Foundation AB
	defaultFromScheme = "0007"    // Swedish org number
	defaultService  = "urn:webuild:svc:erds:dispatch" // service named in their SMP metadata
	defaultAction   = "Submit"                        // iterated per their error responses
)

var (
	endpoint   = flag.String("endpoint", defaultEndpoint, "AS4 access point URL")
	algo       = flag.String("algo", "ecdsa", "signature algorithm: ecdsa | ed25519 | rsa")
	keyPath    = flag.String("key", "", "signing key PEM (default: per-algo gateway key in /tmp/opencode/gw-pki)")
	certPath   = flag.String("cert", "", "signing cert PEM (default: per-algo gateway cert in /tmp/opencode/gw-pki)")
	fromID     = flag.String("from", defaultFromID, "sender party id")
	fromScheme = flag.String("from-scheme", defaultFromScheme, "sender party id scheme (ICD)")
	toID       = flag.String("to", defaultToID, "recipient party id")
	toScheme   = flag.String("to-scheme", defaultToScheme, "recipient party id scheme (ICD)")
	service    = flag.String("service", defaultService, "ebMS CollaborationInfo Service")
	action     = flag.String("action", defaultAction, "ebMS CollaborationInfo Action")
	tokenRef   = flag.String("token-ref", "binary", "token reference: binary | keyidentifier | issuerserial | thumbprint")
	payload    = flag.String("payload", "", "optional payload file to attach as a MIME part")
	dryRun     = flag.Bool("dry-run", false, "print the wire message and exit without sending")
	localMode  = flag.Bool("local", false, "start a local go-as4 server and send to it instead of the flag endpoint")
	verbose    = flag.Bool("verbose", false, "print the signed UserMessage")
)

// gatewayKey names the default per-algorithm gateway credential minted from the
// SIROS WE BUILD Pilot Test CA (see /tmp/opencode/gw-pki).
func gatewayKeyPaths(algo string) (string, string) {
	var k string
	switch algo {
	case "ecdsa":
		k = "ec256"
	case "ed25519":
		k = "ed25519"
	case "rsa":
		k = "rsa2048"
	default:
		return "", ""
	}
	return "/tmp/opencode/gw-pki/gw-" + k + "-key.pem", "/tmp/opencode/gw-pki/gw-" + k + "-cert.pem"
}

func loadPEM(path string) *pem.Block {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		log.Fatalf("no PEM block in %s", path)
	}
	return block
}

func loadCert(path string) *x509.Certificate {
	cert, err := x509.ParseCertificate(loadPEM(path).Bytes)
	if err != nil {
		log.Fatalf("parse certificate %s: %v", path, err)
	}
	return cert
}

// signCredentials loads the gateway key+cert for the chosen algorithm and
// returns a signer built accordingly.
func makeSigner(algo, keyPath, certPath, tokenRefMethod string) (security.Signer, *x509.Certificate) {
	if keyPath == "" || certPath == "" {
		defKey, defCert := gatewayKeyPaths(algo)
		if keyPath == "" {
			keyPath = defKey
		}
		if certPath == "" {
			certPath = defCert
		}
	}
	cert := loadCert(certPath)
	block := loadPEM(keyPath)

	var key interface{}
	var err error
	switch block.Type {
	case "PRIVATE KEY": // PKCS#8
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			log.Fatalf("parse PKCS#8 key %s: %v", keyPath, err)
		}
	case "RSA PRIVATE KEY": // PKCS#1
		var rsaKey *rsa.PrivateKey
		rsaKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		key = rsaKey
		if err != nil {
			log.Fatalf("parse RSA key %s: %v", keyPath, err)
		}
	case "EC PRIVATE KEY": // SEC1
		var ecKey *ecdsa.PrivateKey
		ecKey, err = x509.ParseECPrivateKey(block.Bytes)
		key = ecKey
		if err != nil {
			log.Fatalf("parse EC key %s: %v", keyPath, err)
		}
	default:
		log.Fatalf("unsupported PEM block type %q in %s", block.Type, keyPath)
	}

	factory := &security.SignerFactory{}
	cfg := &pmode.SignConfig{TokenReference: parseTokenRef(tokenRefMethod)}

	var signer security.Signer
	switch algo {
	case "ecdsa":
		cfg.Algorithm = pmode.AlgoECDSASHA256
		signer, err = factory.NewSigner(cfg, key, cert)
	case "ed25519":
		cfg.Algorithm = pmode.AlgoEd25519
		signer, err = factory.NewSigner(cfg, key, cert)
	case "rsa":
		cfg.Algorithm = pmode.AlgoRSASHA256
		signer, err = factory.NewSigner(cfg, key, cert)
	default:
		log.Fatalf("unknown -algo %q (use ecdsa, ed25519 or rsa)", algo)
	}
	if err != nil {
		log.Fatalf("create %s signer: %v", algo, err)
	}
	return signer, cert
}

func parseTokenRef(s string) pmode.TokenReferenceMethod {
	switch s {
	case "binary", "":
		return pmode.TokenRefBinarySecurityToken
	case "keyidentifier":
		return pmode.TokenRefKeyIdentifier
	case "issuerserial":
		return pmode.TokenRefIssuerSerial
	case "thumbprint":
		return pmode.TokenRefThumbprint
	default:
		log.Fatalf("unknown -token-ref %q", s)
		return ""
	}
}

// partyType returns the PartyId type attribute for the given ICD scheme.
// An empty scheme means the id value is already in full URN form and the
// standard "unregistered" type is used.
func partyType(scheme string) string {
	if scheme == "" {
		return "urn:oasis:names:tc:ebcore:partyid-type:unregistered"
	}
	return iso6523 + ":" + scheme
}

// partyUrn returns the full URN form used in the eDelivery message
// properties (originalSender/finalRecipient).
func partyUrn(scheme, id string) string {
	if scheme == "" {
		return id
	}
	return iso6523 + ":" + scheme + "::" + id
}

// buildUserMessage composes the ebMS UserMessage per the collected evidence:
// iso6523 party ids, the service from Cleverbase's SMP metadata and the
// eDelivery-required originalSender/finalRecipient properties.
func buildUserMessage(payloadData []byte) (*message.Envelope, []message.PayloadPart, error) {
	opts := []message.Option{
		message.WithFrom(*fromID, partyType(*fromScheme)),
		message.WithFromRole("http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/initiator"),
		message.WithTo(*toID, partyType(*toScheme)),
		message.WithToRole("http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/responder"),
		message.WithService(*service),
		message.WithAction(*action),
		message.WithConversationId("conv-" + uuid.New().String()),
		// Required by eDelivery/Peppol P-Modes
		message.WithMessageProperty("originalSender", partyUrn(*fromScheme, *fromID)),
		message.WithMessageProperty("finalRecipient", partyUrn(*toScheme, *toID)),
	}
	builder := message.NewUserMessage(opts...)
	if len(payloadData) > 0 {
		builder.AddPayload(payloadData, "application/xml")
	}
	return builder.BuildEnvelope()
}

// serializeMIME wraps the SIGNED envelope (exact bytes) plus payload parts in a
// multipart/related message. This is done manually because
// mime.Message.Serialize re-marshals the Envelope struct and cannot carry an
// already-signed envelope.
func serializeMIME(signedEnvelope []byte, payloads []message.PayloadPart) (body []byte, contentType string, err error) {
	var buf bytes.Buffer
	boundary := "uuid:" + uuid.New().String()
	startID := "<root.message@as4.siros.org>"

	w := multipart.NewWriter(&buf)
	if err := w.SetBoundary(boundary); err != nil {
		return nil, "", err
	}

	// SOAP part (the signed envelope, verbatim)
	soapHeader := textproto.MIMEHeader{
		"Content-Type":              {`application/soap+xml; charset=UTF-8`},
		"Content-Transfer-Encoding": {"binary"},
		"Content-Id":                {startID},
	}
	soapPart, err := w.CreatePart(soapHeader)
	if err != nil {
		return nil, "", err
	}
	if _, err := soapPart.Write(signedEnvelope); err != nil {
		return nil, "", err
	}

	// Payload parts
	for i, p := range payloads {
		contentID := p.ContentID
		if contentID == "" {
			contentID = fmt.Sprintf("payload-%d@as4.siros.org", i+1)
		}
		contentID = strings.TrimSuffix(strings.TrimPrefix(contentID, "<"), ">")
		ct := p.ContentType
		if ct == "" {
			ct = "application/octet-stream"
		}
		payloadHeader := textproto.MIMEHeader{
			"Content-Type":              {ct},
			"Content-Transfer-Encoding": {"binary"},
			"Content-Id":                {"<" + contentID + ">"},
		}
		part, err := w.CreatePart(payloadHeader)
		if err != nil {
			return nil, "", err
		}
		if _, err := part.Write(p.Data); err != nil {
			return nil, "", err
		}
	}

	if err := w.Close(); err != nil {
		return nil, "", err
	}

	contentType = fmt.Sprintf(`multipart/related; type="application/soap+xml"; boundary=%q; start=%q; start-info="application/soap+xml"`,
		boundary, strings.TrimSuffix(strings.TrimPrefix(startID, "<"), ">"))
	return buf.Bytes(), contentType, nil
}

// responseVerdict parses the HTTP response body and prints the ebMS verdict:
// a Receipt or the Error elements, plus any SOAP Fault.
func responseVerdict(status int, body []byte) string {
	doc := etree.NewDocument()
	var receipt, errors []string
	if err := doc.ReadFromBytes(body); err == nil {
		for _, e := range doc.FindElements(".//*[local-name()='Error']") {
			errCode := e.SelectAttrValue("errorCode", "?")
			severity := e.SelectAttrValue("severity", "?")
			category := e.SelectAttrValue("category", "?")
			short := e.SelectAttrValue("shortDescription", "")
			desc := ""
			if d := e.SelectElement("Description"); d != nil {
				desc = d.Text()
			}
			detail := ""
			if d := e.SelectElement("ErrorDetail"); d != nil {
				detail = d.Text()
			}
			line := fmt.Sprintf("ebms error %s [%s/%s] %s", errCode, category, severity, short)
			if desc != "" {
				line += ": " + desc
			}
			if detail != "" {
				line += " — " + detail
			}
			errors = append(errors, line)
		}
		for _, r := range doc.FindElements(".//*[local-name()='Receipt']") {
			receipt = append(receipt, "Receipt (non-repudiation signal): "+strings.TrimSpace(r.Text()))
		}
		for _, f := range doc.FindElements(".//*[local-name()='Fault']") {
			reason := ""
			if t := f.FindElement(".//*[local-name()='Text']"); t != nil {
				reason = t.Text()
			}
			errors = append(errors, "SOAP Fault: "+reason)
		}
	}

	verdict := fmt.Sprintf("HTTP %d", status)
	if len(receipt) > 0 {
		verdict += " — RECEIPT"
		for _, r := range receipt {
			verdict += "\n  " + r
		}
	}
	if len(errors) > 0 {
		verdict += " — REFUSED/ERROR"
		for _, e := range errors {
			verdict += "\n  " + e
		}
	}
	return verdict
}

// localServer runs an in-process go-as4 interop server that trusts the
// sender's own certificate and records whether the signature verified.
func localServer(addr string, certPEM []byte) (*phase4server.AS4Server, *signatureProbe) {
	probe := &signatureProbe{}
	srv, err := phase4server.NewAS4Server(&phase4server.ServerConfig{
		CertPEM:         nil,
		KeyPEM:          nil,
		TrustedCAs:      [][]byte{certPEM},
		Logger:          log.New(os.Stderr, "[local-as4] ", log.LstdFlags),
		MessageHandler:  probe.handler,
	})
	if err != nil {
		log.Fatalf("local server: %v", err)
	}
	go func() {
		if err := srv.Start(addr); err != nil {
			log.Printf("local server stopped: %v", err)
		}
	}()
	time.Sleep(200 * time.Millisecond)
	return srv, probe
}

type signatureProbe struct {
	mu   sync.Mutex
	seen []*phase4server.ReceivedMessage
}

func (p *signatureProbe) handler(_ context.Context, msg *phase4server.ReceivedMessage) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen = append(p.seen, msg)
	return nil
}

func main() {
	flag.Parse()

	// Load credentials and build the signer for the chosen algorithm
	signer, cert := makeSigner(*algo, *keyPath, *certPath, *tokenRef)
	log.Printf("algorithm=%s token-ref=%s cert-subject=%q", *algo, *tokenRef, cert.Subject.String())

	// Optional payload
	var payloadData []byte
	if *payload != "" {
		var err error
		payloadData, err = os.ReadFile(*payload)
		if err != nil {
			log.Fatalf("read payload: %v", err)
		}
	}

	// Build and sign the UserMessage
	envelope, payloads, err := buildUserMessage(payloadData)
	if err != nil {
		log.Fatalf("build envelope: %v", err)
	}
	envelopeXML, err := xml.Marshal(envelope)
	if err != nil {
		log.Fatalf("marshal envelope: %v", err)
	}

	attachments := make([]security.Attachment, 0, len(payloads))
	for _, p := range payloads {
		attachments = append(attachments, security.Attachment{
			ContentID:   p.ContentID,
			ContentType: p.ContentType,
			Data:        p.Data,
		})
	}
	signedXML, err := signer.SignEnvelopeWithAttachments(envelopeXML, attachments)
	if err != nil {
		log.Fatalf("sign: %v", err)
	}

	// Serialize for the wire
	var body []byte
	var contentType string
	if len(payloads) > 0 {
		body, contentType, err = serializeMIME(signedXML, payloads)
		if err != nil {
			log.Fatalf("serialize MIME: %v", err)
		}
	} else {
		body = signedXML
		contentType = "application/soap+xml; charset=UTF-8"
	}

	if *verbose || *dryRun {
		fmt.Printf("--- Content-Type: %s ---\n%s\n", contentType, string(body))
	}
	if *dryRun {
		// Self-verify what we just produced before it leaves the machine
		if err := signer.VerifyEnvelope(signedXML); err != nil {
			log.Fatalf("DRY-RUN FAILED: produced signature does not verify: %v", err)
		}
		fmt.Println("DRY-RUN OK: signed message verifies locally")
		return
	}

	// Where to send
	target := *endpoint
	var srv *phase4server.AS4Server
	var probe *signatureProbe
	if *localMode {
		addr := "127.0.0.1:9091"
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		srv, probe = localServer(addr, certPEM)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			srv.Stop(ctx)
		}()
		target = "http://" + addr + "/as4"
	}
	log.Printf("POST %s (%d bytes)", target, len(body))

	// Send
	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		log.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("send: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("read response: %v", err)
	}

	fmt.Println("=== RESPONSE ===")
	fmt.Printf("HTTP %s\nContent-Type: %s\n\n", resp.Status, resp.Header.Get("Content-Type"))
	fmt.Println(string(respBody))
	fmt.Println("=== VERDICT ===")
	fmt.Println(responseVerdict(resp.StatusCode, respBody))

	if *localMode {
		probe.mu.Lock()
		defer probe.mu.Unlock()
		if len(probe.seen) == 0 {
			log.Fatal("local test FAILED: server did not record a received message")
		}
		msg := probe.seen[0]
		log.Printf("local server: message-id=%s signed=%v signatureValid=%v attachments=%d",
			msg.MessageID, msg.Signed, msg.SignatureValid, len(msg.Attachments))
		if !msg.SignatureValid {
			log.Fatal("local test FAILED: the ECDSA signature did not verify server-side")
		}
		fmt.Println("LOCAL TEST OK: message parsed, signature VERIFIED server-side, receipt returned")
	}
}
