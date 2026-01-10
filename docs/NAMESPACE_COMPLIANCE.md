# ebMS 3.0 Namespace Compliance

This document describes go-as4's compliance with the ebMS 3.0 namespace specification, ensuring interoperability with Domibus and other ebMS 3.0 / AS4 Profile 1.0 implementations.

## Overview

Domibus 5.1.9 exclusively uses the **ebMS 3.0** namespace with the `200704` version identifier. Our implementation is fully compliant with this requirement.

## Namespace URIs

### Primary ebMS 3.0 Namespace
```
http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/
```

This namespace is used for:
- `Messaging` header element
- `UserMessage` element
- All ebMS 3.0 message structures

### Message Exchange Pattern (MEP) URIs

All MEP and binding URIs use the `200704` namespace:

```go
// MEP Types
MEPOneWay  = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/oneWay"
MEPTwoWay  = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/twoWay"

// MEP Bindings
MEPBindingPush     = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/push"
MEPBindingPushPush = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/pushAndPush"
MEPBindingPull     = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/pull"
```

### Test Service URIs

```go
TestService = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/service"
TestAction  = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/test"
```

### Default Role

```go
DefaultRole = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/defaultRole"
```

## Domibus Compatibility

### Verified Matches

Our implementation has been verified to match Domibus 5.1.9 exactly:

| Constant | go-as4 Value | Domibus Value | Match |
|----------|--------------|---------------|-------|
| MEPOneWay | `.../200704/oneWay` | `Ebms3Constants.ONEWAY_MEP_VALUE` | ✅ |
| MEPTwoWay | `.../200704/twoWay` | `Ebms3Constants.TWOWAY_MEP_VALUE` | ✅ |
| MEPBindingPush | `.../200704/push` | `MessageExchangePattern.ONE_WAY_PUSH` | ✅ |
| MEPBindingPull | `.../200704/pull` | `MessageExchangePattern.ONE_WAY_PULL` | ✅ |
| TestService | `.../200704/service` | `Ebms3Constants.TEST_SERVICE` | ✅ |
| TestAction | `.../200704/test` | `Ebms3Constants.TEST_ACTION` | ✅ |
| DefaultRole | `.../200704/defaultRole` | `Ebms3Constants.DEFAULT_ROLE` | ✅ |

## XML Structure

### Example Message

```xml
<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Header>
    <eb:Messaging xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/">
      <eb:UserMessage>
        <eb:MessageInfo>
          <eb:Timestamp>2025-11-20T12:00:00Z</eb:Timestamp>
          <eb:MessageId>uuid-1234</eb:MessageId>
        </eb:MessageInfo>
        <eb:PartyInfo>
          <eb:From>
            <eb:PartyId>sender</eb:PartyId>
            <eb:Role>http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/defaultRole</eb:Role>
          </eb:From>
          <eb:To>
            <eb:PartyId>receiver</eb:PartyId>
            <eb:Role>http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/defaultRole</eb:Role>
          </eb:To>
        </eb:PartyInfo>
        <eb:CollaborationInfo>
          <eb:Service>http://example.com/service</eb:Service>
          <eb:Action>ProcessOrder</eb:Action>
          <eb:ConversationId>conv-123</eb:ConversationId>
        </eb:CollaborationInfo>
      </eb:UserMessage>
    </eb:Messaging>
  </soap:Header>
  <soap:Body/>
</soap:Envelope>
```

## P-Mode Configuration

The namespace version is configurable via P-Mode:

```go
pmode := &pmode.ProcessingMode{
    NamespaceVersion: pmode.NamespaceEBMS3, // ebMS 3.0 (200704)
    // ... other config
}
```

### Available Namespace Versions

```go
type NamespaceVersion string

const (
    // NamespaceEBMS3 is the ebXML Messaging 3.0 namespace (AS4 Profile 1.0)
    // Used by: Domibus, eDelivery, most AS4 implementations
    NamespaceEBMS3 NamespaceVersion = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
    
    // NamespaceAS4v2 is the AS4 2.0 namespace (future spec)
    // Currently theoretical - no implementations exist
    NamespaceAS4v2 NamespaceVersion = "http://docs.oasis-open.org/ebxml-msg/as4/v2.0/ns/core/202X/"
)
```

### Default Configuration

All profile defaults use ebMS 3.0:

```go
// Domibus/eDelivery Profile
pmode := pmode.GetDefaultPMode(pmode.ProfileDomibus)
// pmode.NamespaceVersion == pmode.NamespaceEBMS3

// AS4 v2 Profile (uses ebMS 3.0 for compatibility)
pmode := pmode.GetDefaultPMode(pmode.ProfileAS4v2)
// pmode.NamespaceVersion == pmode.NamespaceEBMS3
```

## Implementation Details

### Hardcoded vs Configurable

Currently, the namespace is **hardcoded** in the XML struct tags to ensure correctness:

```go
type Messaging struct {
    XMLName     xml.Name     `xml:"http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/ Messaging"`
    UserMessage *UserMessage `xml:"UserMessage,omitempty"`
}
```

**Rationale:**
1. Domibus and all production AS4 implementations use ebMS 3.0
2. AS4 2.0 namespace is theoretical (spec not finalized)
3. Hardcoding ensures Domibus compatibility
4. Prevents accidental misconfiguration

### Future Enhancement

If AS4 2.0 becomes a real specification, we can add dynamic namespace selection:

```go
// Hypothetical future implementation
type Message struct {
    namespace string
}

func (m *Message) MarshalXML(e *xml.Encoder, start xml.Start) error {
    start.Name = xml.Name{
        Space: m.namespace,
        Local: "Messaging",
    }
    // ...
}
```

## Testing

Comprehensive namespace compliance tests verify:

### TestEBMS3NamespaceCompliance
- ✅ Namespace constants use 200704
- ✅ MEP URIs contain 200704
- ✅ Marshaled XML contains 200704
- ✅ No AS4 v2.0 namespace present

### TestDomibusCompatibleConstants
- ✅ MEP constants match Domibus exactly
- ✅ Service/Action constants match Domibus
- ✅ Default role matches Domibus

### TestMessageRoleDefaultValue
- ✅ Party roles use correct default URI

### TestXMLStructNamespaceDeclarations
- ✅ SOAP 1.2 namespace present
- ✅ ebMS 3.0 namespace with 200704
- ✅ No AS4 v2.0 references

### TestNamespaceConsistency
- ✅ All elements use consistent namespace
- ✅ No mixed versions

Run tests:
```bash
go test ./pkg/message -run Namespace -v
go test ./pkg/message -run Domibus -v
```

## Compatibility Matrix

| Implementation | Namespace | Compatible |
|----------------|-----------|------------|
| Domibus 5.1.9 | ebMS 3.0 (200704) | ✅ Yes |
| eDelivery Access Points | ebMS 3.0 (200704) | ✅ Yes |
| Holodeck B2B | ebMS 3.0 (200704) | ✅ Yes |
| AS4.NET | ebMS 3.0 (200704) | ✅ Yes |
| go-as4 | ebMS 3.0 (200704) | ✅ Yes |
| AS4 2.0 (future) | as4/v2.0 (202X) | ⚠️ Not yet specified |

## Specification References

- **ebXML Messaging 3.0**: OASIS ebMS 3.0 Core Specification
- **AS4 Profile**: OASIS AS4 Profile of ebMS 3.0
- **Domibus**: EU eDelivery Domibus 5.1.9
  - Source: `eu.domibus.api.ebms3.Ebms3Constants`
  - Namespace: `@XmlSchema(namespace = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/")`

## Key Findings from Domibus Analysis

From analyzing Domibus 5.1.9 source code:

1. **No AS4 2.0 support** - Only ebMS 3.0 (200704) found
2. **Strict namespace enforcement** - All constants use `/200704/` paths
3. **JAXB annotations** - Package-level `@XmlSchema` declares 200704 namespace
4. **Constants class** - `Ebms3Constants.java` defines all standard URIs
5. **Prefix "eb"** - Uses `eb:` prefix for ebMS elements

## Conclusion

✅ **go-as4 is fully compliant with ebMS 3.0 namespace requirements**

Our implementation:
- Uses the correct 200704 namespace version
- Matches Domibus constants exactly
- Passes comprehensive compliance tests
- Ready for Domibus interoperability

**No changes needed** - existing implementation is already correct for Domibus compatibility.
