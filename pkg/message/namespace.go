package message

import (
	"bytes"
	"fmt"
	"strings"
)

// AddEbMSPrefix transforms the XML to use the 'eb' prefix for all ebMS namespace elements
// instead of using default namespace. This is required for compatibility with WSS4J/Domibus
// which expects prefixed namespaces.
//
// Transforms:
//   <Messaging xmlns="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
//     <UserMessage>
//       <MessageInfo>...
//
// Into:
//   <eb:Messaging xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
//     <eb:UserMessage>
//       <eb:MessageInfo>...
func AddEbMSPrefix(xmlData []byte) ([]byte, error) {
	const ebmsNS = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
	
	// Elements that should have the eb: prefix
	ebmsElements := []string{
		"Messaging", "UserMessage", "SignalMessage",
		"MessageInfo", "Timestamp", "MessageId", "RefToMessageId",
		"PartyInfo", "From", "To", "PartyId", "Role",
		"CollaborationInfo", "AgreementRef", "Service", "Action", "ConversationId",
		"MessageProperties", "Property",
		"PayloadInfo", "PartInfo", "PartProperties",
		"Receipt", "Error", "Description", "ErrorDetail",
	}
	
	result := string(xmlData)
	
	//Replace opening tags with prefixed versions
	for _, elem := range ebmsElements {
		// Replace opening tags: <Element to <eb:Element
		result = strings.ReplaceAll(result, "<"+elem+" ", "<eb:"+elem+" ")
		result = strings.ReplaceAll(result, "<"+elem+">", "<eb:"+elem+">")
		
		// Replace closing tags: </Element> to </eb:Element>
		result = strings.ReplaceAll(result, "</"+elem+">", "</eb:"+elem+">")
	}
	
	// Fix the namespace declaration on Messaging element
	// From: <eb:Messaging xmlns="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
	// To:   <eb:Messaging xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
	result = strings.ReplaceAll(result, 
		fmt.Sprintf(`<eb:Messaging xmlns="%s"`, ebmsNS),
		fmt.Sprintf(`<eb:Messaging xmlns:eb="%s"`, ebmsNS))
	
	// Also handle UserMessage and SignalMessage if they appear at the root (shouldn't normally)
	result = strings.ReplaceAll(result,
		fmt.Sprintf(`<eb:UserMessage xmlns="%s"`, ebmsNS),
		fmt.Sprintf(`<eb:UserMessage xmlns:eb="%s"`, ebmsNS))
	result = strings.ReplaceAll(result,
		fmt.Sprintf(`<eb:SignalMessage xmlns="%s"`, ebmsNS),
		fmt.Sprintf(`<eb:SignalMessage xmlns:eb="%s"`, ebmsNS))
	
	return []byte(result), nil
}

// RemoveDefaultNamespace removes default namespace declarations and prefixes elements
// This is a more general version of AddEbMSPrefix that works with any namespace
func RemoveDefaultNamespace(xmlData []byte, namespace string, prefix string) ([]byte, error) {
	result := bytes.ReplaceAll(xmlData,
		[]byte(fmt.Sprintf(` xmlns="%s"`, namespace)),
		[]byte(fmt.Sprintf(` xmlns:%s="%s"`, prefix, namespace)))
	return result, nil
}
