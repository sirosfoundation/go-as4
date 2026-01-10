// Package server provides an HTTP server for AS4 message handling
// compatible with phase4 and other AS4 implementations.
package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/beevik/etree"
	"github.com/sirosfoundation/go-as4/pkg/pmode"
	"github.com/sirosfoundation/go-as4/pkg/security"
)

// Constants for XML namespaces
const (
	NS_SOAP12   = "http://www.w3.org/2003/05/soap-envelope"
	NS_EBMS3    = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
	NS_WSSEC    = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	NS_WSSEC_UT = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	NS_XMLDSIG  = "http://www.w3.org/2000/09/xmldsig#"
)

// ReceivedMessage represents an AS4 message received by the server
type ReceivedMessage struct {
	MessageID      string
	ConversationID string
	FromPartyID    string
	ToPartyID      string
	Service        string
	Action         string
	Payload        []byte
	Attachments    []Attachment
	RawXML         []byte
	ReceivedAt     time.Time
	Signed         bool
	SignatureValid bool
}

// Attachment represents a message attachment
type Attachment struct {
	ContentID   string
	ContentType string
	Data        []byte
}

// MessageHandler is a callback for processing received messages
type MessageHandler func(ctx context.Context, msg *ReceivedMessage) error

// AS4Server implements an HTTP server for AS4 message handling
type AS4Server struct {
	cert           *x509.Certificate
	key            *rsa.PrivateKey
	trustedCerts   []*x509.Certificate
	pmodeRegistry  map[string]*pmode.ProcessingMode
	messageHandler MessageHandler
	mu             sync.RWMutex
	receivedMsgs   []*ReceivedMessage
	server         *http.Server
	logger         *log.Logger
}

// ServerConfig holds configuration for the AS4 server
type ServerConfig struct {
	CertPEM        []byte
	KeyPEM         []byte
	TrustedCAs     [][]byte
	ListenAddr     string
	Path           string
	PModeRegistry  map[string]*pmode.ProcessingMode
	MessageHandler MessageHandler
	Logger         *log.Logger
}

// NewAS4Server creates a new AS4 server
func NewAS4Server(config *ServerConfig) (*AS4Server, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	logger := config.Logger
	if logger == nil {
		logger = log.New(os.Stdout, "[AS4Server] ", log.LstdFlags)
	}

	server := &AS4Server{
		pmodeRegistry:  config.PModeRegistry,
		messageHandler: config.MessageHandler,
		receivedMsgs:   make([]*ReceivedMessage, 0),
		logger:         logger,
	}

	// Parse certificate if provided
	if len(config.CertPEM) > 0 {
		block, _ := pem.Decode(config.CertPEM)
		if block == nil {
			return nil, fmt.Errorf("failed to decode certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		server.cert = cert
	}

	// Parse private key if provided
	if len(config.KeyPEM) > 0 {
		block, _ := pem.Decode(config.KeyPEM)
		if block == nil {
			return nil, fmt.Errorf("failed to decode key PEM")
		}
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse private key: %w", err)
			}
			var ok bool
			key, ok = keyInterface.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("private key is not RSA")
			}
		}
		server.key = key
	}

	// Parse trusted CAs
	for _, caPEM := range config.TrustedCAs {
		block, _ := pem.Decode(caPEM)
		if block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				server.trustedCerts = append(server.trustedCerts, cert)
			}
		}
	}

	return server, nil
}

// Handler returns an http.Handler for the AS4 server
func (s *AS4Server) Handler() http.Handler {
	return http.HandlerFunc(s.handleAS4Request)
}

// Start starts the HTTP server
func (s *AS4Server) Start(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/as4", s.handleAS4Request)
	mux.HandleFunc("/", s.handleAS4Request)

	s.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	s.logger.Printf("Starting AS4 server on %s", addr)
	return s.server.ListenAndServe()
}

// Stop stops the HTTP server gracefully
func (s *AS4Server) Stop(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

// GetReceivedMessages returns all received messages
func (s *AS4Server) GetReceivedMessages() []*ReceivedMessage {
	s.mu.RLock()
	defer s.mu.RUnlock()

	msgs := make([]*ReceivedMessage, len(s.receivedMsgs))
	copy(msgs, s.receivedMsgs)
	return msgs
}

// ClearReceivedMessages clears the received message store
func (s *AS4Server) ClearReceivedMessages() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receivedMsgs = make([]*ReceivedMessage, 0)
}

// handleAS4Request handles incoming AS4 HTTP requests
func (s *AS4Server) handleAS4Request(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	s.logger.Printf("Received %s request from %s", r.Method, r.RemoteAddr)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.Printf("Failed to read request body: %v", err)
		s.sendSOAPFault(w, "Client", "Failed to read request body")
		return
	}
	defer r.Body.Close()

	s.logger.Printf("Received %d bytes", len(body))

	contentType := r.Header.Get("Content-Type")

	var soapXML []byte
	var attachments []Attachment

	if strings.Contains(contentType, "multipart/related") {
		soapXML, attachments, err = s.parseMIMEMessage(body, contentType)
		if err != nil {
			s.logger.Printf("Failed to parse MIME message: %v", err)
			s.sendSOAPFault(w, "Client", "Failed to parse MIME message")
			return
		}
	} else {
		soapXML = body
	}

	msg, err := s.parseAS4Message(soapXML)
	if err != nil {
		s.logger.Printf("Failed to parse AS4 message: %v", err)
		s.sendSOAPFault(w, "Client", fmt.Sprintf("Failed to parse AS4 message: %v", err))
		return
	}
	msg.Attachments = attachments
	msg.RawXML = soapXML
	msg.ReceivedAt = time.Now()

	if msg.Signed {
		valid, err := s.verifySignature(soapXML)
		if err != nil {
			s.logger.Printf("Signature verification error: %v", err)
			msg.SignatureValid = false
		} else {
			msg.SignatureValid = valid
			s.logger.Printf("Signature valid: %v", valid)
		}
	}

	s.mu.Lock()
	s.receivedMsgs = append(s.receivedMsgs, msg)
	s.mu.Unlock()

	if s.messageHandler != nil {
		if err := s.messageHandler(ctx, msg); err != nil {
			s.logger.Printf("Message handler error: %v", err)
			s.sendSOAPFault(w, "Server", "Message processing error")
			return
		}
	}

	s.logger.Printf("Message processed successfully: %s", msg.MessageID)

	receipt, err := s.generateReceipt(msg)
	if err != nil {
		s.logger.Printf("Failed to generate receipt: %v", err)
		s.sendSOAPFault(w, "Server", "Failed to generate receipt")
		return
	}

	w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(receipt)
}

// parseMIMEMessage parses a MIME multipart/related message
func (s *AS4Server) parseMIMEMessage(body []byte, contentType string) ([]byte, []Attachment, error) {
	var boundary string
	for _, part := range strings.Split(contentType, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "boundary=") {
			boundary = strings.Trim(strings.TrimPrefix(part, "boundary="), "\"")
			break
		}
	}

	if boundary == "" {
		return body, nil, nil
	}

	delimiter := "--" + boundary
	parts := bytes.Split(body, []byte(delimiter))

	var soapXML []byte
	var attachments []Attachment

	for i, part := range parts {
		if len(part) == 0 || bytes.Equal(part, []byte("--\r\n")) || bytes.Equal(part, []byte("--")) {
			continue
		}

		headerEnd := bytes.Index(part, []byte("\r\n\r\n"))
		if headerEnd == -1 {
			headerEnd = bytes.Index(part, []byte("\n\n"))
		}
		if headerEnd == -1 {
			continue
		}

		header := string(part[:headerEnd])
		bodyContent := part[headerEnd+4:]

		isSOAP := strings.Contains(header, "application/soap+xml") ||
			strings.Contains(header, "text/xml") ||
			(i == 1 && soapXML == nil)

		if isSOAP && soapXML == nil {
			soapXML = bytes.TrimSpace(bodyContent)
		} else {
			contentID := ""
			for _, line := range strings.Split(header, "\n") {
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "content-id:") {
					contentID = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "Content-ID:"))
					contentID = strings.Trim(contentID, "<>")
					break
				}
			}

			attachments = append(attachments, Attachment{
				ContentID:   contentID,
				ContentType: extractHeaderValue(header, "Content-Type"),
				Data:        bytes.TrimSpace(bodyContent),
			})
		}
	}

	return soapXML, attachments, nil
}

func extractHeaderValue(header, name string) string {
	for _, line := range strings.Split(header, "\n") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), strings.ToLower(name)+":") {
			return strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}
	return ""
}

// parseAS4Message parses a SOAP envelope to extract AS4 message information
func (s *AS4Server) parseAS4Message(soapXML []byte) (*ReceivedMessage, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(soapXML); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}

	msg := &ReceivedMessage{}

	messaging := doc.FindElement("//Messaging")
	if messaging == nil {
		messaging = doc.FindElement("//eb:Messaging")
	}
	if messaging == nil {
		messaging = doc.FindElement("//*[local-name()='Messaging']")
	}

	if messaging != nil {
		userMsg := messaging.FindElement(".//UserMessage")
		if userMsg == nil {
			userMsg = messaging.FindElement(".//*[local-name()='UserMessage']")
		}

		if userMsg != nil {
			msgInfo := userMsg.FindElement(".//MessageInfo")
			if msgInfo == nil {
				msgInfo = userMsg.FindElement(".//*[local-name()='MessageInfo']")
			}
			if msgInfo != nil {
				if msgID := msgInfo.FindElement(".//MessageId"); msgID != nil {
					msg.MessageID = msgID.Text()
				} else if msgID := msgInfo.FindElement(".//*[local-name()='MessageId']"); msgID != nil {
					msg.MessageID = msgID.Text()
				}
			}

			partyInfo := userMsg.FindElement(".//PartyInfo")
			if partyInfo == nil {
				partyInfo = userMsg.FindElement(".//*[local-name()='PartyInfo']")
			}
			if partyInfo != nil {
				if from := partyInfo.FindElement(".//From//PartyId"); from != nil {
					msg.FromPartyID = from.Text()
				} else if from := partyInfo.FindElement(".//*[local-name()='From']//*[local-name()='PartyId']"); from != nil {
					msg.FromPartyID = from.Text()
				}
				if to := partyInfo.FindElement(".//To//PartyId"); to != nil {
					msg.ToPartyID = to.Text()
				} else if to := partyInfo.FindElement(".//*[local-name()='To']//*[local-name()='PartyId']"); to != nil {
					msg.ToPartyID = to.Text()
				}
			}

			collabInfo := userMsg.FindElement(".//CollaborationInfo")
			if collabInfo == nil {
				collabInfo = userMsg.FindElement(".//*[local-name()='CollaborationInfo']")
			}
			if collabInfo != nil {
				if service := collabInfo.FindElement(".//Service"); service != nil {
					msg.Service = service.Text()
				} else if service := collabInfo.FindElement(".//*[local-name()='Service']"); service != nil {
					msg.Service = service.Text()
				}
				if action := collabInfo.FindElement(".//Action"); action != nil {
					msg.Action = action.Text()
				} else if action := collabInfo.FindElement(".//*[local-name()='Action']"); action != nil {
					msg.Action = action.Text()
				}
				if convID := collabInfo.FindElement(".//ConversationId"); convID != nil {
					msg.ConversationID = convID.Text()
				} else if convID := collabInfo.FindElement(".//*[local-name()='ConversationId']"); convID != nil {
					msg.ConversationID = convID.Text()
				}
			}
		}
	}

	securityElem := doc.FindElement("//Security")
	if securityElem == nil {
		securityElem = doc.FindElement("//wsse:Security")
	}
	if securityElem == nil {
		securityElem = doc.FindElement("//*[local-name()='Security']")
	}
	if securityElem != nil {
		sig := securityElem.FindElement(".//Signature")
		if sig == nil {
			sig = securityElem.FindElement(".//*[local-name()='Signature']")
		}
		msg.Signed = sig != nil
	}

	return msg, nil
}

// verifySignature verifies the XML signature on the message
func (s *AS4Server) verifySignature(soapXML []byte) (bool, error) {
	if len(s.trustedCerts) == 0 {
		s.logger.Println("No trusted certificates configured, skipping verification")
		return true, nil
	}

	verifier, err := security.NewRSAVerifier(s.trustedCerts[0], crypto.SHA256, crypto.SHA256, security.SignatureModePKCS1v15)
	if err != nil {
		return false, fmt.Errorf("failed to create verifier: %w", err)
	}

	if err := verifier.VerifyEnvelope(soapXML); err != nil {
		return false, err
	}
	return true, nil
}

// generateReceipt generates an AS4 Receipt for the received message
func (s *AS4Server) generateReceipt(msg *ReceivedMessage) ([]byte, error) {
	receiptID := fmt.Sprintf("receipt-%s@as4.example.com", generateServerUUID())

	envelope := buildReceiptEnvelope(receiptID, msg.MessageID)

	if s.key != nil && s.cert != nil {
		signer, err := security.NewRSASignerWithMode(s.key, s.cert, crypto.SHA256, crypto.SHA256, pmode.TokenRefBinarySecurityToken, security.SignatureModePKCS1v15)
		if err != nil {
			s.logger.Printf("Failed to create signer: %v", err)
			return xml.Marshal(envelope)
		}

		envelopeXML, err := xml.Marshal(envelope)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal envelope: %w", err)
		}

		return signer.SignEnvelope(envelopeXML)
	}

	return xml.Marshal(envelope)
}

func generateServerUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// buildReceiptEnvelope builds a SOAP envelope containing an AS4 Receipt
func buildReceiptEnvelope(receiptID, refToMessageID string) interface{} {
	timestamp := time.Now().UTC().Format(time.RFC3339)

	return struct {
		XMLName xml.Name `xml:"S12:Envelope"`
		S12     string   `xml:"xmlns:S12,attr"`
		Eb      string   `xml:"xmlns:eb,attr"`
		Header  struct {
			Messaging struct {
				MustUnderstand string `xml:"S12:mustUnderstand,attr"`
				SignalMessage  struct {
					MessageInfo struct {
						Timestamp      string `xml:"eb:Timestamp"`
						MessageId      string `xml:"eb:MessageId"`
						RefToMessageId string `xml:"eb:RefToMessageId,omitempty"`
					} `xml:"eb:MessageInfo"`
					Receipt struct{} `xml:"eb:Receipt"`
				} `xml:"eb:SignalMessage"`
			} `xml:"eb:Messaging"`
		} `xml:"S12:Header"`
		Body struct{} `xml:"S12:Body"`
	}{
		S12: NS_SOAP12,
		Eb:  NS_EBMS3,
		Header: struct {
			Messaging struct {
				MustUnderstand string `xml:"S12:mustUnderstand,attr"`
				SignalMessage  struct {
					MessageInfo struct {
						Timestamp      string `xml:"eb:Timestamp"`
						MessageId      string `xml:"eb:MessageId"`
						RefToMessageId string `xml:"eb:RefToMessageId,omitempty"`
					} `xml:"eb:MessageInfo"`
					Receipt struct{} `xml:"eb:Receipt"`
				} `xml:"eb:SignalMessage"`
			} `xml:"eb:Messaging"`
		}{
			Messaging: struct {
				MustUnderstand string `xml:"S12:mustUnderstand,attr"`
				SignalMessage  struct {
					MessageInfo struct {
						Timestamp      string `xml:"eb:Timestamp"`
						MessageId      string `xml:"eb:MessageId"`
						RefToMessageId string `xml:"eb:RefToMessageId,omitempty"`
					} `xml:"eb:MessageInfo"`
					Receipt struct{} `xml:"eb:Receipt"`
				} `xml:"eb:SignalMessage"`
			}{
				MustUnderstand: "true",
				SignalMessage: struct {
					MessageInfo struct {
						Timestamp      string `xml:"eb:Timestamp"`
						MessageId      string `xml:"eb:MessageId"`
						RefToMessageId string `xml:"eb:RefToMessageId,omitempty"`
					} `xml:"eb:MessageInfo"`
					Receipt struct{} `xml:"eb:Receipt"`
				}{
					MessageInfo: struct {
						Timestamp      string `xml:"eb:Timestamp"`
						MessageId      string `xml:"eb:MessageId"`
						RefToMessageId string `xml:"eb:RefToMessageId,omitempty"`
					}{
						Timestamp:      timestamp,
						MessageId:      receiptID,
						RefToMessageId: refToMessageID,
					},
				},
			},
		},
	}
}

// sendSOAPFault sends a SOAP 1.2 Fault response
func (s *AS4Server) sendSOAPFault(w http.ResponseWriter, code, reason string) {
	fault := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<S12:Envelope xmlns:S12="%s">
  <S12:Body>
    <S12:Fault>
      <S12:Code>
        <S12:Value>S12:%s</S12:Value>
      </S12:Code>
      <S12:Reason>
        <S12:Text xml:lang="en">%s</S12:Text>
      </S12:Reason>
    </S12:Fault>
  </S12:Body>
</S12:Envelope>`, NS_SOAP12, code, reason)

	w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(fault))
}
