// Package sdk provides Swedish SDK (Säker Digital Kommunikation) specific functionality.
// It includes pre-configured P-Modes, message builders, and SDK-specific constants.
package sdk

import (
	"fmt"

	"github.com/sirosfoundation/go-as4/pkg/message"
	"github.com/sirosfoundation/go-as4/pkg/pmode"
)

// SDK Constants
const (
	// PartyType is the party type for SDK accesspoints
	PartyType = "urn:fdc:digg.se:edelivery:transportprofile:as4:partytype:ap"
	// ParticipantPartyType is the party type for SDK participants (originalSender/finalRecipient)
	ParticipantPartyType = "urn:fdc:digg.se:edelivery:transportprofile:as4:partytype:participant"
	// APRole is the role for accesspoints
	APRole = "urn:fdc:digg.se:edelivery:transportprofile:as4:role:ap"
	// ServiceType is the default service type
	ServiceType = "urn:fdc:digg.se:edelivery:process"
	// TransportProfile is the SDK transport profile identifier
	TransportProfile = "digg-transport-as4-v1_2"
	// ParticipantIDScheme is the participant identifier scheme
	ParticipantIDScheme = "iso6523-actorid-upis"

	// SML zones
	SMLZoneProduction = "edelivery.tech.ec.europa.eu"
	SMLZoneQA         = "acc.edelivery.tech.ec.europa.eu"

	// SMP Extension URIs for certificate publishing
	ExtensionCertPub        = "urn:fdc:digg.se:edelivery:certpub"
	ExtensionSigningCert    = "urn:fdc:digg.se:edelivery:certpub:signing-cert"
	ExtensionEncryptionCert = "urn:fdc:digg.se:edelivery:certpub:encryption-cert"
)

// SDKPModeOptions configures SDK P-Mode creation
type SDKPModeOptions struct {
	// PModeID is the unique identifier for this P-Mode
	PModeID string
	// APPartyID is this accesspoint's party identifier
	APPartyID string
	// Service is the business service identifier
	Service string
	// Action is the business action
	Action string
	// EncryptPayloads enables encryption of payloads (default: true)
	EncryptPayloads bool
	// SignAttachments enables signing of MIME attachments (default: true)
	SignAttachments bool
}

// NewSDKPMode creates a P-Mode configured for Swedish SDK federation
func NewSDKPMode(opts SDKPModeOptions) *pmode.ProcessingMode {
	// Set defaults
	if opts.PModeID == "" {
		opts.PModeID = "sdk-default"
	}
	if opts.Action == "" {
		opts.Action = "submit"
	}

	pm := &pmode.ProcessingMode{
		ID:         opts.PModeID,
		MEP:        message.MEPOneWay,
		MEPBinding: message.MEPBindingPush,
		Service:    opts.Service,
		Action:     opts.Action,

		Protocol: &pmode.Protocol{
			SOAPVersion: "1.2",
		},

		Security: &pmode.Security{
			WSSVersion: "1.1",
			X509: &pmode.X509Config{
				Sign: &pmode.SignConfig{
					Algorithm:        pmode.AlgoRSASHA256,
					HashFunction:     pmode.HashSHA256,
					TokenReference:   pmode.TokenRefBinarySecurityToken,
					Canonicalization: pmode.C14NExclusive,
					SignAttachments:  true,
				},
				Encryption: &pmode.EncryptionConfig{
					Algorithm:          pmode.KeyAlgoRSAOAEP256,
					DataEncryption:     pmode.DataAlgoAES128GCM,
					EncryptAttachments: true,
				},
			},
			SendReceipt: &pmode.SendReceipt{
				ReplyPattern:   "callback",
				NonRepudiation: true,
			},
		},

		PayloadService: &pmode.PayloadService{
			CompressionType: "application/gzip",
		},

		SecurityProfile:  pmode.ProfileEDelivery,
		NamespaceVersion: pmode.NamespaceEBMS3,
	}

	// Add leg with SDK-specific business info
	pm.Legs = []pmode.Leg{
		{
			BusinessInfo: &pmode.BusinessInfo{
				Service: &pmode.Service{
					Value: opts.Service,
					Type:  ServiceType,
				},
				Action: opts.Action,
			},
			Security:       pm.Security,
			PayloadService: pm.PayloadService,
		},
	}

	return pm
}

// MessagePropertyBuilder helps build SDK message properties
type MessagePropertyBuilder struct {
	properties []message.Property
}

// NewMessagePropertyBuilder creates a new property builder
func NewMessagePropertyBuilder() *MessagePropertyBuilder {
	return &MessagePropertyBuilder{
		properties: make([]message.Property, 0),
	}
}

// WithOriginalSender sets the originalSender property
func (b *MessagePropertyBuilder) WithOriginalSender(participantID string) *MessagePropertyBuilder {
	b.properties = append(b.properties, message.Property{
		Name:  "originalSender",
		Type:  ParticipantPartyType,
		Value: participantID,
	})
	return b
}

// WithFinalRecipient sets the finalRecipient property
func (b *MessagePropertyBuilder) WithFinalRecipient(participantID string) *MessagePropertyBuilder {
	b.properties = append(b.properties, message.Property{
		Name:  "finalRecipient",
		Type:  ParticipantPartyType,
		Value: participantID,
	})
	return b
}

// WithProperty adds a custom property
func (b *MessagePropertyBuilder) WithProperty(name, propType, value string) *MessagePropertyBuilder {
	b.properties = append(b.properties, message.Property{
		Name:  name,
		Type:  propType,
		Value: value,
	})
	return b
}

// Build returns the message properties
func (b *MessagePropertyBuilder) Build() []message.Property {
	return b.properties
}

// PartyBuilder helps build SDK party information
type PartyBuilder struct {
	partyID string
	role    string
}

// NewAPPartyBuilder creates a builder for an accesspoint party
func NewAPPartyBuilder(apPartyID string) *PartyBuilder {
	return &PartyBuilder{
		partyID: apPartyID,
		role:    APRole,
	}
}

// WithRole overrides the default role
func (b *PartyBuilder) WithRole(role string) *PartyBuilder {
	b.role = role
	return b
}

// Build creates the party information
func (b *PartyBuilder) Build() (partyID string, partyType string, role string) {
	return b.partyID, PartyType, b.role
}

// ValidateParticipantID validates an SDK participant identifier
func ValidateParticipantID(id string) error {
	// SDK participant IDs should follow format: <scheme>:<identifier>
	// e.g., 0203:org-number for Swedish organizations
	if len(id) < 5 { // Minimum: "0203:x"
		return fmt.Errorf("participant ID too short: %s", id)
	}
	return nil
}

// FormatParticipantID formats a participant ID with the standard scheme
func FormatParticipantID(orgNumber string) string {
	return ParticipantIDScheme + ":" + orgNumber
}

// SDK Error codes as per SDK specification
const (
	// ErrorNotServiced indicates the recipient is not served by this accesspoint
	ErrorNotServiced = "EBMS:0004"
	// ErrorValueNotRecognized indicates a malformed message
	ErrorValueNotRecognized = "EBMS:0001"
	// ErrorDecompressionFailure indicates GZIP decompression failed
	ErrorDecompressionFailure = "EBMS:0303"
)

// NewNotServicedError creates an SDK NOT_SERVICED error
func NewNotServicedError(recipientID string) *message.Error {
	return &message.Error{
		ErrorCode:        ErrorNotServiced,
		Severity:         "failure",
		ShortDescription: "NOT_SERVICED",
		Description:      "Recipient " + recipientID + " is not served by this accesspoint",
	}
}
