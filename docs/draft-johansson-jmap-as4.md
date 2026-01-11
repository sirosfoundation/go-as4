---
title: "JMAP Extension for AS4 Message Exchange"
abbrev: "JMAP-AS4"
docname: draft-johansson-jmap-as4-00
category: std
ipr: trust200902

stand_alone: yes
smart_quotes: no
pi: [toc, sortrefs, symrefs]

author:
  -
    ins: L. Johansson
    name: Leif Johansson
    organization: SIROS Foundation
    email: leifj@sirosfoundation.org

normative:
  RFC8620:
  RFC9110:

informative:
  OASIS-AS4:
    title: "AS4 Profile of ebMS 3.0 Version 1.0"
    author:
      org: OASIS
    date: 2013-01
    target: https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/AS4-profile-v1.0.html
  PEPPOL-AS4:
    title: "Peppol AS4 Profile"
    author:
      org: OpenPeppol
    date: 2023
    target: https://docs.peppol.eu/

--- abstract

This document defines a JMAP (RFC 8620) extension for accessing and
managing AS4 messages. It provides a JSON-based protocol for
synchronizing AS4 mailboxes, enabling efficient polling and push-based
notification of business document exchanges over the AS4 protocol.

--- middle

# Introduction

The OASIS AS4 profile {{OASIS-AS4}} defines a reliable messaging
protocol for business-to-business document exchange. While AS4 handles
the transport layer effectively, applications need a standardized way
to access received messages and submit outbound messages.

This specification defines a JMAP {{RFC8620}} extension that maps AS4
concepts to JMAP data types, enabling:

- Efficient synchronization of AS4 mailboxes
- Delta-based updates via state tracking
- Push notifications for real-time message delivery
- Structured access to AS4 message metadata and payloads

## Notational Conventions

{::boilerplate bcp14-tagged}

The definitions of JSON keys and datatypes in this document follow
the conventions established in {{RFC8620}}.

## Terminology

AS4 Message:
: A business document exchanged via the AS4 protocol, consisting of
  a SOAP envelope with ebMS3 headers and zero or more payload attachments.

Party:
: An AS4 participant identified by a Party ID (type and value).

Mailbox:
: A logical container for AS4 messages associated with a participant.

Conversation:
: A related set of AS4 messages sharing a conversation identifier.

# Data Model

## AS4Message

An **AS4Message** object represents a single AS4 message, either
received from a trading partner or queued for outbound delivery.

### Properties

- **id**: `Id` (immutable; server-set)
  The unique identifier for this message within the account.

- **mailboxId**: `Id` (immutable)
  The identifier of the mailbox containing this message.

- **direction**: `String` (immutable)
  Either "inbound" (received from partner) or "outbound" (sent/queued).

- **status**: `String`
  The delivery status. One of:
  - `pending` - Queued for delivery (outbound only)
  - `sending` - Currently being transmitted (outbound only)
  - `sent` - Successfully delivered (outbound only)
  - `received` - Received from partner (inbound only)
  - `delivered` - Delivered to application (inbound only)
  - `read` - Marked as read
  - `failed` - Delivery failed
  - `rejected` - Rejected by recipient

- **as4MessageId**: `String` (immutable)
  The AS4 Message-ID from the ebMS3 header.

- **conversationId**: `String` (immutable)
  The AS4 Conversation-ID linking related messages.

- **refToMessageId**: `String|null` (immutable)
  Reference to a previous message this is responding to.

- **fromParty**: `Party` (immutable)
  The sending party identification.

- **toParty**: `Party` (immutable)
  The receiving party identification.

- **service**: `String` (immutable)
  The ebMS3 Service value identifying the business process.

- **action**: `String` (immutable)
  The ebMS3 Action value identifying the message type within the service.

- **payloads**: `AS4Payload[]` (immutable)
  Array of payload references attached to this message.

- **receivedAt**: `UTCDate` (immutable; server-set)
  When the message was received by the server.

- **processedAt**: `UTCDate|null` (server-set)
  When the message was processed/validated.

- **deliveredAt**: `UTCDate|null` (server-set)
  When the message was delivered to recipient (outbound) or application (inbound).

- **readAt**: `UTCDate|null`
  When the message was marked as read.

- **signatureValid**: `Boolean` (immutable; server-set)
  Whether the AS4 signature was successfully validated.

- **receiptId**: `String|null` (immutable; server-set)
  The AS4 Message-ID of the receipt for this message.

- **retryCount**: `UnsignedInt` (server-set)
  Number of delivery attempts (outbound only).

- **lastError**: `String|null` (server-set)
  Last error message if delivery failed.

### Party Object

A **Party** object identifies an AS4 participant:

- **type**: `String`
  The Party ID type URI (e.g., "urn:oasis:names:tc:ebcore:partyid-type:unregistered").

- **value**: `String`
  The Party ID value.

### AS4Payload Object

An **AS4Payload** object describes an attachment:

- **id**: `Id`
  Server identifier for this payload.

- **contentId**: `String`
  The Content-ID from the MIME part.

- **mimeType**: `String`
  The MIME type of the payload.

- **size**: `UnsignedInt`
  Size in bytes.

- **compressed**: `Boolean`
  Whether the payload is compressed.

- **checksum**: `String`
  SHA-256 checksum of the payload data.

## AS4Mailbox

An **AS4Mailbox** object represents a message container for a participant.

### Properties

- **id**: `Id` (immutable; server-set)
  The unique identifier for this mailbox.

- **participantId**: `Id` (immutable)
  The participant this mailbox belongs to.

- **name**: `String`
  Display name for the mailbox.

- **totalMessages**: `UnsignedInt` (server-set)
  Total number of messages in the mailbox.

- **unreadCount**: `UnsignedInt` (server-set)
  Number of unread messages.

- **role**: `String`
  Either "inbox" (for received messages) or "outbox" (for sent messages).

## AS4Participant

An **AS4Participant** object represents a trading partner or local identity.

### Properties

- **id**: `Id` (immutable; server-set)
  The unique identifier for this participant.

- **name**: `String`
  Human-readable name.

- **partyId**: `Party`
  The AS4 Party identification.

- **mailboxId**: `Id` (server-set)
  The associated mailbox identifier.

- **status**: `String`
  One of: `active`, `suspended`, `pending`.

- **createdAt**: `UTCDate` (immutable; server-set)
  When the participant was created.

# Methods

## AS4Message/get

Standard JMAP get method {{RFC8620}} Section 5.1.

Returns AS4Message objects for the specified IDs.

### Additional Arguments

- **fetchPayloads**: `Boolean` (default: false)
  If true, include base64-encoded payload data in the response.
  Only recommended for small payloads.

### Example

~~~json
["AS4Message/get", {
  "accountId": "tenant-123",
  "ids": ["msg-456", "msg-789"],
  "properties": ["id", "as4MessageId", "fromParty", "toParty",
                 "service", "action", "status", "payloads"]
}, "call-1"]
~~~

## AS4Message/changes

Standard JMAP changes method {{RFC8620}} Section 5.2.

Returns the IDs of AS4Messages that have changed since the given state.

State strings are opaque to clients and SHOULD be treated as tokens.
Servers MAY implement states as:

- Sequential version numbers
- Timestamps (ISO 8601 or opaque hashes)
- Database change sequence identifiers

If the server cannot calculate changes from the provided state (e.g.,
state is too old or invalid), it MUST return a `cannotCalculateChanges`
error, and the client MUST perform a full resync.

### Example

~~~json
["AS4Message/changes", {
  "accountId": "tenant-123",
  "sinceState": "state-abc123",
  "maxChanges": 100
}, "call-2"]
~~~

Response:

~~~json
["AS4Message/changes", {
  "accountId": "tenant-123",
  "oldState": "state-abc123",
  "newState": "state-def456",
  "hasMoreChanges": false,
  "created": ["msg-901", "msg-902"],
  "updated": ["msg-456"],
  "destroyed": []
}, "call-2"]
~~~

## AS4Message/query

Standard JMAP query method {{RFC8620}} Section 5.5.

Searches for AS4Messages matching specified criteria.

### Filter Conditions

An **AS4MessageFilterCondition** object has these properties:

- **mailboxId**: `Id`
  Messages in this mailbox.

- **direction**: `String`
  Filter by direction ("inbound" or "outbound").

- **status**: `String`
  Filter by status.

- **service**: `String`
  Filter by service identifier.

- **action**: `String`
  Filter by action identifier.

- **fromPartyValue**: `String`
  Filter by sender party value.

- **toPartyValue**: `String`
  Filter by recipient party value.

- **conversationId**: `String`
  Filter by conversation.

- **receivedAfter**: `UTCDate`
  Messages received after this timestamp.

- **receivedBefore**: `UTCDate`
  Messages received before this timestamp.

- **hasUnread**: `Boolean`
  If true, only unread messages; if false, only read messages.

### Sort Properties

- `receivedAt` (default)
- `as4MessageId`
- `service`
- `action`
- `status`

### Example

~~~json
["AS4Message/query", {
  "accountId": "tenant-123",
  "filter": {
    "mailboxId": "inbox-456",
    "direction": "inbound",
    "hasUnread": true
  },
  "sort": [{"property": "receivedAt", "isAscending": false}],
  "limit": 50
}, "call-3"]
~~~

## AS4Message/queryChanges

Standard JMAP queryChanges method {{RFC8620}} Section 5.6.

Returns changes to a previous query result.

## AS4Message/set

Standard JMAP set method {{RFC8620}} Section 5.3.

Creates new outbound messages or updates message properties.

### Creating Messages

When creating a new AS4Message for outbound delivery:

**Required properties:**

- `mailboxId` - Target outbox
- `toParty` - Recipient party
- `service` - Business service
- `action` - Message action
- `payloads` - At least one payload

**Server-set on create:**

- `id`
- `as4MessageId` (generated)
- `conversationId` (generated if not provided)
- `fromParty` (set from participant)
- `direction` (set to "outbound")
- `status` (set to "pending")
- `receivedAt` (set to creation time)
- `signatureValid` (set to true for outbound)

### Updating Messages

Only these properties may be updated:

- `status` - Can transition to "read" for inbound messages

### Payload Upload

Payloads for new messages must be uploaded first using the
standard JMAP upload mechanism {{RFC8620}} Section 6.1, then
referenced by their blobId:

~~~json
["AS4Message/set", {
  "accountId": "tenant-123",
  "create": {
    "draft-1": {
      "mailboxId": "outbox-789",
      "toParty": {
        "type": "urn:oasis:names:tc:ebcore:partyid-type:iso6523:0088",
        "value": "1234567890123"
      },
      "service": "urn:fdc:peppol.eu:2017:poacc:billing:01:1.0",
      "action": "busdox-docid-qns::urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0::2.1",
      "payloads": [{
        "blobId": "blob-upload-xyz",
        "contentId": "invoice.xml",
        "mimeType": "application/xml"
      }]
    }
  }
}, "call-4"]
~~~

### Example Response

~~~json
["AS4Message/set", {
  "accountId": "tenant-123",
  "oldState": "state-111",
  "newState": "state-222",
  "created": {
    "draft-1": {
      "id": "msg-new-333",
      "as4MessageId": "generated-uuid@server.example",
      "conversationId": "conv-new-444",
      "status": "pending"
    }
  },
  "updated": null,
  "destroyed": null,
  "notCreated": null,
  "notUpdated": null,
  "notDestroyed": null
}, "call-4"]
~~~

## AS4Mailbox/get

Standard JMAP get method for mailbox objects.

### Example

~~~json
["AS4Mailbox/get", {
  "accountId": "tenant-123",
  "ids": null
}, "call-5"]
~~~

## AS4Mailbox/changes

Standard JMAP changes method for mailbox state tracking.

## AS4Participant/get

Standard JMAP get method for participant objects.

## AS4Participant/set

Standard JMAP set method for creating/updating participants.

# Payload Download

Message payloads are accessed via the standard JMAP download
mechanism {{RFC8620}} Section 6.2:

~~~
GET /jmap/download/{blobId}/{name}
~~~

Note: The accountId is implicit in the endpoint path for this implementation.
The `blobId` corresponds to the payload `id` from the AS4Message object.
The `name` parameter is optional and used for Content-Disposition header.

# Payload Upload

New payloads for outbound messages must be uploaded via the standard
JMAP upload mechanism {{RFC8620}} Section 6.1:

~~~
POST /jmap/upload
Content-Type: application/xml

<payload data>
~~~

Response:

~~~json
{
  "accountId": "tenant-123",
  "blobId": "uploaded-blob-id",
  "type": "application/xml",
  "size": 12345
}
~~~

The returned `blobId` can then be used when creating messages via
`AS4Message/set`.

# Push Notifications

This extension supports JMAP push notifications {{RFC8620}} Section 7
for real-time updates via Server-Sent Events (EventSource).

## EventSource Connection

Clients establish an EventSource connection to receive real-time state changes:

~~~
GET /jmap/eventsource?types={types}&closeafter={closeafter}&ping={ping}
~~~

### Query Parameters

- **types** (required): Comma-separated list of data types to monitor.
  Supported values: `AS4Message`, `AS4Mailbox`, `Participant`, or `*` for all types.

- **closeafter** (optional): Either `state` to close after first state change,
  or `no` to keep the connection open indefinitely. Default: `no`.

- **ping** (optional): Interval in seconds between keep-alive pings.
  Default: 30. Set to 0 to disable pings.

### Event Format

State change events use the `state` event type:

~~~
event: state
data: {"changed":{"tenant-123":{"AS4Message":"0001921a3b4c5d6e"}}}
~~~

The `changed` object maps account IDs to objects containing the new state
for each changed data type. Clients should compare states and fetch changes
for any data types where the state differs from their cached state.

Keep-alive events use the `ping` event type:

~~~
event: ping
data: {"interval":30}
~~~

## State String Format

State strings are opaque tokens representing the current state of a data type.
Clients MUST NOT parse or interpret state strings; they should only compare
them for equality and pass them back to the server in subsequent requests.

Servers MAY implement states using any of:

- Sequential version numbers
- Encoded timestamps
- Database change sequence identifiers
- Cryptographic hashes of data state

If a client provides an invalid or expired state to a `/changes` method,
the server MUST return a `cannotCalculateChanges` error (type: `"cannotCalculateChanges"`),
and the client MUST perform a full resync using the `/get` method.

## Implementation Considerations

### Real-time vs Polling

Servers SHOULD support real-time push notifications using database
change streams or similar mechanisms where available. When real-time
notification is not possible (e.g., database doesn't support change streams),
servers MAY fall back to periodic polling.

The implementation SHOULD:

1. Use database change streams (MongoDB, PostgreSQL LISTEN/NOTIFY) when available
2. Fall back to polling at reasonable intervals (e.g., 1-5 seconds) otherwise
3. Coalesce rapid changes to avoid overwhelming clients

### State Synchronization Pattern

The recommended client synchronization pattern is:

1. Establish EventSource connection on session initialization
2. Maintain cached state strings for each data type
3. When receiving a state change event, compare with cached state
4. If state differs, call the appropriate `/changes` method
5. If `hasMoreChanges` is true, repeat the `/changes` call
6. Update cached state to `newState` from the response

### Example State Synchronization Flow

~~~
Client                          Server
   |                               |
   |-- GET /eventsource?types=*-->|
   |<-- event: state              |
   |    data: {"changed":         |
   |      {"t1":{"AS4Message":    |
   |        "state-abc"}}}        |
   |                               |
   |-- POST /jmap                 |
   |   AS4Message/changes         |
   |   sinceState: "state-old"   -->|
   |                               |
   |<-- created: [...],           |
   |    updated: [...],           |
   |    newState: "state-abc"     |
   |                               |
   (client updates local cache)    |
~~~

## State Change Types

- **AS4Message** - Message created, status changed, or marked read
- **AS4Mailbox** - Mailbox counts changed (totalMessages, unreadCount)
- **Participant** - Participant created or updated

# Capability

Servers supporting this extension advertise the capability:

~~~
"urn:ietf:params:jmap:as4": {}
~~~

## Account Capability

Each account that supports AS4 includes:

~~~json
{
  "urn:ietf:params:jmap:as4": {
    "maxPayloadSize": 104857600,
    "supportedServices": ["*"],
    "supportedActions": ["*"]
  }
}
~~~

- **maxPayloadSize**: Maximum size in bytes for a single payload upload (default 100MB).
- **supportedServices**: Array of supported service URIs, or `["*"]` for any.
- **supportedActions**: Array of supported action URIs, or `["*"]` for any.

# Endpoint Structure

The JMAP-AS4 API follows a tenant-scoped URL structure:

~~~
Base URL: /tenant/{tenantId}/jmap

Session:     GET  /tenant/{tenantId}/jmap/session
API:         POST /tenant/{tenantId}/jmap
Download:    GET  /tenant/{tenantId}/jmap/download/{blobId}/{name}
Upload:      POST /tenant/{tenantId}/jmap/upload
EventSource: GET  /tenant/{tenantId}/jmap/eventsource
~~~

The tenant ID is included in the URL path rather than requiring separate
authentication per account, as AS4 access points typically operate in a
multi-tenant environment where each tenant represents an organization.

# Security Considerations

## Authentication

JMAP requests MUST be authenticated. This specification does not
mandate a specific authentication mechanism, but recommends:

- OAuth 2.0 Bearer tokens {{RFC6750}}
- Mutual TLS with client certificates

## Authorization

Servers MUST enforce authorization such that:

- Users can only access messages in their authorized mailboxes
- Outbound messages can only be sent as authorized parties
- Administrative operations require elevated privileges

## Payload Confidentiality

Payloads may contain sensitive business documents. Servers SHOULD:

- Encrypt payloads at rest
- Use TLS for all API communications
- Implement appropriate access logging

## AS4 Security Properties

The JMAP layer does not replace AS4 security mechanisms:

- Messages still use AS4 signing for non-repudiation
- The `signatureValid` property indicates AS4 verification status
- Receipt handling follows AS4 reliability semantics

# IANA Considerations

## JMAP Capability Registration

IANA is requested to register the following in the "JMAP Capabilities"
registry:

Capability Name: `urn:ietf:params:jmap:as4`

Specification document: this document

Intended use: common

Change Controller: IETF

## JMAP Data Type Registration

IANA is requested to register the following in the "JMAP Data Types"
registry:

| Type Name      | Can Reference Blobs | Can Use for State Change |
|----------------|---------------------|--------------------------|
| AS4Message     | Yes                 | Yes                      |
| AS4Mailbox     | No                  | Yes                      |
| AS4Participant | No                  | Yes                      |

--- back

# Acknowledgments

This work builds on the JMAP protocol developed by the IETF JMAP
working group and the AS4 profile developed by OASIS.

# Example Session

This appendix shows a complete example session.

## Initial State Sync

Client fetches current mailbox state:

~~~json
["AS4Mailbox/get", {
  "accountId": "acme-corp",
  "ids": null
}, "0"]
~~~

~~~json
[["AS4Mailbox/get", {
  "accountId": "acme-corp",
  "state": "mb-state-1",
  "list": [{
    "id": "inbox-1",
    "name": "Inbox",
    "role": "inbox",
    "totalMessages": 42,
    "unreadCount": 3
  }, {
    "id": "outbox-1",
    "name": "Outbox",
    "role": "outbox",
    "totalMessages": 15,
    "unreadCount": 0
  }],
  "notFound": []
}, "0"]]
~~~

## Fetch Unread Messages

~~~json
["AS4Message/query", {
  "accountId": "acme-corp",
  "filter": {
    "mailboxId": "inbox-1",
    "hasUnread": true
  },
  "sort": [{"property": "receivedAt", "isAscending": false}],
  "limit": 10
}, "1"],
["AS4Message/get", {
  "accountId": "acme-corp",
  "#ids": {
    "resultOf": "1",
    "name": "AS4Message/query",
    "path": "/ids"
  }
}, "2"]
~~~

## Mark Message Read

~~~json
["AS4Message/set", {
  "accountId": "acme-corp",
  "update": {
    "msg-123": {
      "status": "read"
    }
  }
}, "3"]
~~~

## Poll for Changes

~~~json
["AS4Message/changes", {
  "accountId": "acme-corp",
  "sinceState": "msg-state-xyz"
}, "4"]
~~~

# Mapping to Peppol AS4

This appendix describes how JMAP-AS4 maps to Peppol network concepts.

| Peppol Concept        | JMAP-AS4 Mapping                          |
|-----------------------|-------------------------------------------|
| Participant ID        | `AS4Participant.partyId`                  |
| Document Type         | `AS4Message.action`                       |
| Process ID            | `AS4Message.service`                      |
| Business Document     | `AS4Message.payloads[0]`                  |
| SBDH                  | Included in payload (application layer)  |
| Message ID            | `AS4Message.as4MessageId`                 |
| Conversation ID       | `AS4Message.conversationId`               |

