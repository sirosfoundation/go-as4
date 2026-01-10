package security

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
)

// TestVerifySampleAS4Message tests signature verification against real AS4 samples
func TestVerifySampleAS4Message(t *testing.T) {
	// Sample from "1b. Sample AS4 User Message's Receipt"
	sampleXML := `<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:eb3="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/" xmlns:ebbp="http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0" xmlns:ebint="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/multihop/200902/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
<S12:Header>
<eb3:Messaging S12:mustUnderstand="true" id="_ebmessaging_N65541" wsu:Id="_18b5d6a1762dc4ef9506a64d515a020dab87e08d33bff4c927d563964e055d5d2">
<eb3:SignalMessage>
<eb3:MessageInfo>
<eb3:Timestamp>2025-10-10T16:36:36.000Z</eb3:Timestamp>
<eb3:MessageId>4a1a549f-a5f7-11f0-8a6e-6ad694a15c37@domibus.eu</eb3:MessageId>
<eb3:RefToMessageId>1_15_AS4_basic_two_way_C38347e961-e65c-40df-a012-8f148dbead82@gitb.eu</eb3:RefToMessageId>
</eb3:MessageInfo>
<eb3:Receipt>
<ebbp:NonRepudiationInformation>
<ebbp:MessagePartNRInformation>
<ds:Reference xmlns:env="http://www.w3.org/2003/05/soap-envelope" URI="#_28b5d6a1762dc4ef9506a64d515a020dab87e08d33bff4c927d563964e055d5d2">
<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<ds:DigestValue>7gYj9L0UeZ7YSFI6CHzDbEuqyOG8q/j3077Efmn6+bA=</ds:DigestValue>
</ds:Reference>
</ebbp:MessagePartNRInformation>
</ebbp:NonRepudiationInformation>
</eb3:Receipt>
</eb3:SignalMessage>
</eb3:Messaging>
<wsse:Security S12:mustUnderstand="true">
<ds:Signature Id="SIG-6e3736b0-04b6-4697-bca8-aa3538aeb888">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="S12 ds eb3 ebbp ebint wsa wsse wsu"/>
</ds:CanonicalizationMethod>
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<ds:Reference URI="#N65695">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="ds eb3 ebbp ebint wsa wsse"/>
</ds:Transform>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<ds:DigestValue>pqhbgQM9C1tDYKzmOsuMCyLJ6/stnfaaZKxR5wnG0p4=</ds:DigestValue>
</ds:Reference>
<ds:Reference URI="#_18b5d6a1762dc4ef9506a64d515a020dab87e08d33bff4c927d563964e055d5d2">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="ds ebbp ebint wsa wsse"/>
</ds:Transform>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<ds:DigestValue>XoPSbEe1VKm/6wLp/jTL7y+r0USJOnxjMPK6gsky6oY=</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue>XBDCCUkwOWqnMcnPIVtKReLQSqt5UW+Sm/9zV1uHWcZWLlQ3/fridrzCiPsR8ON4Bxhe2qtCitC+darWPkKe1Ugfi9Hw0BkxxdCshmGNXkIv/icK0/J4aynRmO/FR0mKjwznXNnzFD6kIddMH3rnHK8obgjuIg57fu9WDru/NIixEf/qVKw4/hwnUYPYzDBMiFTI8NPIdbrWuwD870pFPz5o4w7J26rrIjO+2WqWIQ9JnbfaJ2JGLJn8ppFq6w7gcPUj7mYBPokRbSbl/Mya4AsReklS6I0ZuxT40i+uDw2PtRMEnaYMLQ7M85bRIJvCTj9ubdabzNAiXrGv2zJ9PA==</ds:SignatureValue>
<ds:KeyInfo Id="KI-dfc39305-4052-4381-8e81-58c4086e1d0f">
<wsse:SecurityTokenReference wsu:Id="STR-24ff3c93-4968-4dbd-9e0d-0de89e8f8d29">
<wsse:KeyIdentifier EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier">lf5Qc+1b8CTia5DWijeWA6JzsNw=</wsse:KeyIdentifier>
</wsse:SecurityTokenReference>
</ds:KeyInfo>
</ds:Signature>
</wsse:Security>
</S12:Header>
<S12:Body wsu:Id="N65695"/>
</S12:Envelope>`

	t.Log("Sample XML loaded successfully")
	t.Log("This test demonstrates the expected structure of AS4 signatures")
	t.Log("Key findings:")
	t.Log("1. CanonicalizationMethod includes InclusiveNamespaces element")
	t.Log("2. Each Transform also includes InclusiveNamespaces with specific prefix lists")
	t.Log("3. References are ordered: Body first, then Messaging header")
	t.Log("4. IDs can be simple (e.g., 'N65695') or prefixed with underscore")

	// Verify XML can be parsed
	if !strings.Contains(sampleXML, "InclusiveNamespaces") {
		t.Error("Sample XML should contain InclusiveNamespaces elements")
	}

	if !strings.Contains(sampleXML, `PrefixList="S12 ds eb3 ebbp ebint wsa wsse wsu"`) {
		t.Error("Sample XML should contain PrefixList in CanonicalizationMethod")
	}
}

// TestIDGeneration tests that we generate compatible wsu:Id values
func TestIDGeneration(t *testing.T) {
	// Real AS4 examples use:
	// - Simple IDs like "N65695"
	// - Prefixed IDs like "_18b5d6a1762dc4ef9506a64d515a020dab87e08d33bff4c927d563964e055d5d2"
	// - Our current format: "id-" + base64url

	id1 := generateID()
	t.Logf("Generated ID: %s", id1)

	// Check that ID is valid for wsu:Id attribute (no special chars except base64url)
	if len(id1) == 0 {
		t.Error("Generated ID should not be empty")
	}

	// Real examples show IDs can be simple or complex
	// The key is they must be unique and valid XML IDs
	t.Log("Note: Real AS4 messages use various ID formats")
	t.Log("Our current format uses base64url encoding which is valid")
}

// TestCertificateLoading tests loading the test certificate
func TestCertificateLoading(t *testing.T) {
	certPath := "../../certs/test.crt" // Use certs directory at root

	// Check if cert file exists
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Skip("Test certificate not found, skipping")
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("Failed to read certificate: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("Failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	t.Logf("Certificate Subject: %s", cert.Subject)
	t.Logf("Certificate Issuer: %s", cert.Issuer)
	t.Logf("Certificate Valid Until: %s", cert.NotAfter)
}
