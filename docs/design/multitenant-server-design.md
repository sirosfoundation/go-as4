# go-as4 Multi-Tenant Messaging Server Design

## 1. Executive Summary

This document describes the design for a multi-tenant AS4 messaging server built on go-as4. The primary purpose is to **experiment with wallet-to-wallet messaging** in the context of an EU pilot activity, exploring how AS4 can serve as a standards-based messaging layer for EU Business Wallets.

### Design Philosophy

This server is an **experimentation platform**. While we have clear requirements for the core messaging infrastructure, the wallet-specific message types and protocols will evolve as specifications become available. The design therefore separates:

1. **Core Messaging Infrastructure** (build now) - Multi-tenant AS4 server with mailbox API
2. **Wallet Integration Patterns** (experiment) - How wallets discover and communicate
3. **Message Type Mappings** (defer) - Specific credential/presentation protocols over AS4

### What We Know

- **Discovery**: SMP publication is the discovery mechanism
- **Transport**: AS4 over HTTPS with standard eDelivery security profiles
- **Multi-tenancy**: Container-based deployment behind HTTPS proxy

### What We're Exploring

- Tenant model for wallet backends
- Party identification (DIDs vs. business identifiers)
- Access API design (JMAP vs. REST vs. other)
- Key management integration
- Credential flow patterns

### Primary Use Cases (Initial)

1. **Generic Document Exchange** - Send/receive arbitrary payloads with non-repudiation
2. **Notification Delivery** - Async notifications between wallet backends  
3. **Future: Credential Exchange** - Once specifications are available

## 2. Architecture Overview

### 2.1 Wallet Integration Architecture

> **Note**: This diagram shows the target architecture. Initial implementation will focus on the AS4 Messaging Server component, with wallet integration evolving as we experiment.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Wallet Frontend (React)                            │
│                          wallet-frontend project                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ Credentials │  │ Presentations│  │  (Future)   │  │     (Future)       │ │
│  │    View     │  │    View     │  │  Messaging  │  │   Business Inbox   │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────────┬───────────┘ │
└─────────┼────────────────┼────────────────┼─────────────────────┼───────────┘
          │                │                │                     │
          ▼                ▼                ▼                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      Wallet Backend (go-wallet-backend)                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ Credential  │  │Presentation │  │  OpenID4VC  │  │  (Future) AS4      │ │
│  │   Store     │  │    Store    │  │   Service   │  │  Messaging Client  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┬───────────┘ │
└───────────────────────────────────────────────────────────────┼─────────────┘
                                                                │
                     Access API (TBD)                           │
                                                                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        AS4 Messaging Server (MVP)                            │
│                      go-as4/cmd/as4-server                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Tenant    │  │   Mailbox   │  │    AS4     │  │   SMP Discovery    │ │
│  │ Management  │  │   Service   │  │  Processor │  │   & Publication    │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└───────────────────────────────────────────────────────────────┬─────────────┘
                                                                │
                            AS4/ebMS3                           │
                                                                ▼
                    ┌───────────────────────────────────────────┐
                    │          Other AS4 Endpoints              │
                    │  (Domibus, phase4, Other Wallet Servers)  │
                    └───────────────────────────────────────────┘
```

### 2.2 Deployment Architecture

### 2.2 Deployment Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      HTTPS Reverse Proxy                        │
│                   (nginx/traefik/envoy)                         │
│              URL routing: /tenant/{tenant-id}/as4               │
└─────────────────────────┬───────────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          │               │               │
    ┌─────▼─────┐   ┌─────▼─────┐   ┌─────▼─────┐
    │ go-as4    │   │ go-as4    │   │ go-as4    │
    │ Instance  │   │ Instance  │   │ Instance  │
    │    #1     │   │    #2     │   │    #3     │
    └─────┬─────┘   └─────┬─────┘   └─────┬─────┘
          │               │               │
          └───────────────┼───────────────┘
                          │
          ┌───────────────┴───────────────┐
          │                               │
    ┌─────▼─────┐                   ┌─────▼─────┐
    │  MongoDB  │                   │  Redis    │
    │  Cluster  │                   │ (session  │
    │ + GridFS  │                   │   keys)   │
    └───────────┘                   └───────────┘
```

> **Key Simplification:** No separate object storage (S3/MinIO) or secrets manager (Vault/KMS). 
> Payloads stored in MongoDB GridFS. Signing keys encrypted with FIDO2/PRF-derived keys, 
> stored as encrypted blobs. Redis provides optional session key caching for decrypted keys.

## 3. Core Concepts

### 3.1 Mapping to Wallet Concepts

| AS4 Server Concept | Wallet Concept | Description |
|--------------------|----------------|-------------|
| **Tenant** | Wallet Backend Instance | A deployment of go-wallet-backend |
| **Participant** | Legal Entity / User | A company or organization using the wallet |
| **Mailbox** | Message Inbox | Per-entity inbox for credentials/documents |
| **Message** | Credential/Document Delivery | AS4 UserMessage carrying VC payloads |
| **Partner** | Remote Wallet/Issuer | Another wallet backend or credential issuer |

### 3.2 Tenant Model

A **Tenant** represents an organization operating an Access Point:

```go
type Tenant struct {
    ID           string              `bson:"_id" json:"id"`
    Name         string              `bson:"name" json:"name"`
    Domain       string              `bson:"domain" json:"domain"`        // e.g., "acme.example.com"
    Status       TenantStatus        `bson:"status" json:"status"`        // active, suspended, pending
    
    // AS4 Identity
    PartyID      string              `bson:"party_id" json:"partyId"`     // ebCore party identifier
    PartyIDType  string              `bson:"party_id_type" json:"partyIdType"`
    
    // Endpoints
    AS4Endpoint  string              `bson:"as4_endpoint" json:"as4Endpoint"`  // Incoming AS4 URL
    APIEndpoint  string              `bson:"api_endpoint" json:"apiEndpoint"`  // JMAP API URL
    
    // Configuration
    Settings     TenantSettings      `bson:"settings" json:"settings"`
    
    // Audit
    CreatedAt    time.Time           `bson:"created_at" json:"createdAt"`
    UpdatedAt    time.Time           `bson:"updated_at" json:"updatedAt"`
}

type TenantSettings struct {
    MaxMessageSize    int64         `bson:"max_message_size" json:"maxMessageSize"`
    RetentionDays     int           `bson:"retention_days" json:"retentionDays"`
    CompressionEnabled bool         `bson:"compression_enabled" json:"compressionEnabled"`
    SecurityProfile   string        `bson:"security_profile" json:"securityProfile"` // as4v2, edelivery, domibus
    
    // Rate limits
    MaxMessagesPerHour int          `bson:"max_messages_per_hour" json:"maxMessagesPerHour"`
    MaxBandwidthMBps   float64      `bson:"max_bandwidth_mbps" json:"maxBandwidthMbps"`
}
```

### 3.2 Participant Model

A **Participant** is a sender/receiver served by a tenant's Access Point:

```go
type Participant struct {
    ID           string              `bson:"_id" json:"id"`
    TenantID     string              `bson:"tenant_id" json:"tenantId"`
    
    // Party identification
    PartyID      string              `bson:"party_id" json:"partyId"`
    PartyIDType  string              `bson:"party_id_type" json:"partyIdType"`
    Name         string              `bson:"name" json:"name"`
    
    // Mailbox configuration  
    MailboxID    string              `bson:"mailbox_id" json:"mailboxId"`
    
    // Access control
    APICredentials []APICredential   `bson:"api_credentials" json:"-"`  // OAuth2 client credentials
    
    // Document types this participant can send/receive
    DocumentTypes []DocumentTypeBinding `bson:"document_types" json:"documentTypes"`
    
    Status       ParticipantStatus   `bson:"status" json:"status"`
    CreatedAt    time.Time           `bson:"created_at" json:"createdAt"`
}

type DocumentTypeBinding struct {
    DocumentTypeID string            `bson:"document_type_id" json:"documentTypeId"`
    ProcessID      string            `bson:"process_id" json:"processId"`
    Direction      Direction         `bson:"direction" json:"direction"` // send, receive, both
}
```

### 3.3 Mailbox Model

A **Mailbox** stores messages for a participant:

```go
type Mailbox struct {
    ID            string             `bson:"_id" json:"id"`
    TenantID      string             `bson:"tenant_id" json:"tenantId"`
    ParticipantID string             `bson:"participant_id" json:"participantId"`
    Name          string             `bson:"name" json:"name"`
    
    // Message counts (denormalized for performance)
    TotalMessages int64              `bson:"total_messages" json:"totalMessages"`
    UnreadCount   int64              `bson:"unread_count" json:"unreadCount"`
    
    // State for JMAP
    State         string             `bson:"state" json:"state"`  // Changes trigger state updates
    
    CreatedAt     time.Time          `bson:"created_at" json:"createdAt"`
    UpdatedAt     time.Time          `bson:"updated_at" json:"updatedAt"`
}
```

### 3.4 Message Model

```go
type Message struct {
    ID             string             `bson:"_id" json:"id"`
    TenantID       string             `bson:"tenant_id" json:"tenantId"`
    MailboxID      string             `bson:"mailbox_id" json:"mailboxId"`
    
    // AS4 Message identification
    MessageID      string             `bson:"message_id" json:"messageId"`
    ConversationID string             `bson:"conversation_id" json:"conversationId"`
    RefToMessageID string             `bson:"ref_to_message_id,omitempty" json:"refToMessageId,omitempty"`
    
    // Direction and status
    Direction      Direction          `bson:"direction" json:"direction"`  // inbound, outbound
    Status         MessageStatus      `bson:"status" json:"status"`
    
    // Party information
    FromParty      PartyInfo          `bson:"from_party" json:"fromParty"`
    ToParty        PartyInfo          `bson:"to_party" json:"toParty"`
    OriginalSender string             `bson:"original_sender,omitempty" json:"originalSender,omitempty"`
    FinalRecipient string             `bson:"final_recipient,omitempty" json:"finalRecipient,omitempty"`
    
    // Business context
    Service        string             `bson:"service" json:"service"`
    Action         string             `bson:"action" json:"action"`
    
    // Payloads (metadata - actual data in GridFS)
    Payloads       []PayloadRef       `bson:"payloads" json:"payloads"`
    
    // Timestamps
    ReceivedAt     time.Time          `bson:"received_at" json:"receivedAt"`
    ProcessedAt    *time.Time         `bson:"processed_at,omitempty" json:"processedAt,omitempty"`
    DeliveredAt    *time.Time         `bson:"delivered_at,omitempty" json:"deliveredAt,omitempty"`
    ReadAt         *time.Time         `bson:"read_at,omitempty" json:"readAt,omitempty"`
    
    // Non-repudiation
    ReceiptID      string             `bson:"receipt_id,omitempty" json:"receiptId,omitempty"`
    SignatureValid bool               `bson:"signature_valid" json:"signatureValid"`
    
    // Retry tracking (for outbound)
    RetryCount     int                `bson:"retry_count" json:"retryCount"`
    NextRetryAt    *time.Time         `bson:"next_retry_at,omitempty" json:"nextRetryAt,omitempty"`
    LastError      string             `bson:"last_error,omitempty" json:"lastError,omitempty"`
}

type PayloadRef struct {
    ID           string              `bson:"id" json:"id"`
    ContentID    string              `bson:"content_id" json:"contentId"`  // cid: reference
    MimeType     string              `bson:"mime_type" json:"mimeType"`
    Size         int64               `bson:"size" json:"size"`
    Compressed   bool                `bson:"compressed" json:"compressed"`
    GridFSID     string              `bson:"gridfs_id" json:"-"`           // GridFS file ID
    Checksum     string              `bson:"checksum" json:"checksum"`     // SHA-256
}

type MessageStatus string

const (
    StatusPending    MessageStatus = "pending"     // Queued for sending
    StatusSending    MessageStatus = "sending"     // Currently being sent
    StatusSent       MessageStatus = "sent"        // Sent, awaiting receipt
    StatusDelivered  MessageStatus = "delivered"   // Receipt received
    StatusFailed     MessageStatus = "failed"      // Permanently failed
    StatusReceived   MessageStatus = "received"    // Inbound, received OK
    StatusRead       MessageStatus = "read"        // Read by recipient
)
```

### 3.5 Message Types (Deferred)

> **Note**: Wallet-specific message types (credential offers, presentation requests, etc.) will be defined later as specifications become available. The initial implementation treats all payloads as opaque binary data with MIME types.

For now, AS4 Service/Action combinations are:
- Configurable per P-Mode template
- Not tied to specific wallet semantics
- Generic document exchange focus

Example generic services:
```go
const (
    // Generic document exchange
    ServiceGenericDocument = "urn:siros:service:document:1.0"
    ActionSubmit           = "Submit"
    ActionAcknowledge      = "Acknowledge"
    
    // Notification service
    ServiceNotification    = "urn:siros:service:notification:1.0"
    ActionNotify           = "Notify"
)
```

## 4. Key Management

### 4.1 Design Philosophy: Client-Side Key Protection

Following the wallet-frontend approach, AS4 signing keys are protected using **FIDO2 PRF extension** for client-side encryption. The server never has access to plaintext private keys.

```
┌─────────────────────────────────────────────────────────────────┐
│                     Client (Browser/App)                        │
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │   FIDO2     │───▶│ PRF-derived │───▶│  Decrypt AS4       │ │
│  │   Token     │    │     Key     │    │  Signing Key       │ │
│  └─────────────┘    └─────────────┘    └─────────────────────┘ │
│                                                  │              │
│                                                  ▼              │
│                                         ┌─────────────────────┐ │
│                                         │  Sign AS4 Message  │ │
│                                         └─────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ Encrypted blob only
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Server (MongoDB)                         │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │  EncryptedKeyStore: {                                       ││
│  │    tenantId: "...",                                         ││
│  │    jwe: "<encrypted-signing-key>",  // Cannot decrypt       ││
│  │    prfKeys: [...],                  // Salt info only       ││
│  │    publicKey: "<signing-cert>"      // Public, for partners ││
│  │  }                                                          ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 How wallet-frontend Does It

The wallet-frontend uses this approach for wallet private data:

1. **FIDO2 PRF Extension** derives a stable secret from the authenticator
2. **HKDF** expands the PRF output into an AES-256 key
3. **JWE** encrypts private data (credentials, keys) with this key
4. **Server stores** only the encrypted JWE blob + PRF salt metadata
5. **Decryption** requires physical presence of the FIDO2 token

```typescript
// From wallet-frontend/src/services/keystore.ts
type WebauthnPrfEncryptionKeyInfoV2 = {
    credentialId: Uint8Array,
    prfSalt: Uint8Array,           // Sent to authenticator
    hkdfSalt: Uint8Array,          // For key derivation
    hkdfInfo: Uint8Array,
    keypair: EncapsulationKeypairInfo,  // ECDH for key wrapping
    unwrapKey: { wrappedKey, ... }
}
```

### 4.3 Applying to AS4 Keys

For AS4 signing keys, we follow the same pattern:

```go
// Encrypted tenant key store - stored in MongoDB
type EncryptedTenantKeyStore struct {
    TenantID        string                 `bson:"_id" json:"tenantId"`
    
    // Encrypted AS4 signing key (JWE, decrypted client-side)
    SigningKeyJWE   string                 `bson:"signing_key_jwe" json:"signingKeyJwe"`
    
    // Public certificate (for partners to verify our signatures)
    SigningCertPEM  string                 `bson:"signing_cert_pem" json:"signingCertPem"`
    
    // PRF key metadata (salts, not the derived keys)
    PRFKeys         []PRFKeyInfo           `bson:"prf_keys" json:"prfKeys"`
    
    // Optional: Password-derived key info (for backup access)
    PasswordKeyInfo *PasswordKeyInfo       `bson:"password_key,omitempty" json:"passwordKey,omitempty"`
    
    // Key algorithm info
    Algorithm       string                 `bson:"algorithm" json:"algorithm"` // Ed25519, RSA, etc.
    
    CreatedAt       time.Time              `bson:"created_at" json:"createdAt"`
    UpdatedAt       time.Time              `bson:"updated_at" json:"updatedAt"`
}

type PRFKeyInfo struct {
    CredentialID    []byte                 `bson:"credential_id" json:"credentialId"`
    PRFSalt         []byte                 `bson:"prf_salt" json:"prfSalt"`
    HKDFSalt        []byte                 `bson:"hkdf_salt" json:"hkdfSalt"`
    HKDFInfo        []byte                 `bson:"hkdf_info" json:"hkdfInfo"`
    // Wrapped key info for asymmetric decapsulation
    Keypair         EncapsulationKeypair   `bson:"keypair" json:"keypair"`
    UnwrapKeyInfo   UnwrapKeyInfo          `bson:"unwrap_key" json:"unwrapKey"`
}
```

### 4.4 Signing Flow

Since signing requires the private key, and the private key is encrypted with a PRF-derived key, **signing must happen client-side**:

```
1. User initiates outbound message
2. Frontend requests PRF from FIDO2 token
3. Frontend derives decryption key
4. Frontend decrypts AS4 signing key
5. Frontend signs AS4 message (or signing portion)
6. Frontend sends signed message to AS4 server
7. AS4 server forwards to recipient
```

**Alternative: Server-side signing with session key**

For better UX, the signing key can be temporarily decrypted and held in a session:

```
1. User authenticates with FIDO2 + PRF
2. Frontend decrypts signing key
3. Frontend sends decrypted key to server over TLS (short-lived session)
4. Server uses key for signing during session
5. Key is cleared on session end/timeout
```

This trades some security for convenience - the server has access to the key during the session, but only in memory.

### 4.5 HSM Consideration

For high-security deployments, the signing key could be:
- Generated inside an HSM
- Never exported (signing operations via HSM API)
- PRF-derived key used only for HSM authentication

This is a future enhancement, not MVP scope.

## 5. P-Mode Management

### 5.1 P-Mode Templates

Tenants configure P-Mode templates that are instantiated per-exchange:

```go
type PModeTemplate struct {
    ID              string              `bson:"_id" json:"id"`
    TenantID        string              `bson:"tenant_id" json:"tenantId"`
    Name            string              `bson:"name" json:"name"`
    
    // Matching criteria
    Service         string              `bson:"service" json:"service"`
    Action          string              `bson:"action" json:"action"`
    
    // Security profile
    SecurityProfile string              `bson:"security_profile" json:"securityProfile"`
    
    // Protocol settings
    SOAPVersion     string              `bson:"soap_version" json:"soapVersion"`
    
    // Reception awareness
    RetryEnabled    bool                `bson:"retry_enabled" json:"retryEnabled"`
    MaxRetries      int                 `bson:"max_retries" json:"maxRetries"`
    RetryInterval   time.Duration       `bson:"retry_interval" json:"retryInterval"`
    
    // Compression
    CompressionType string              `bson:"compression_type" json:"compressionType"`
    
    // Receipt handling
    ReceiptRequired bool                `bson:"receipt_required" json:"receiptRequired"`
    
    Status          string              `bson:"status" json:"status"`
    CreatedAt       time.Time           `bson:"created_at" json:"createdAt"`
}
```

### 5.2 Partner Configuration

```go
type Partner struct {
    ID              string              `bson:"_id" json:"id"`
    TenantID        string              `bson:"tenant_id" json:"tenantId"`
    
    // Partner identification
    PartyID         string              `bson:"party_id" json:"partyId"`
    PartyIDType     string              `bson:"party_id_type" json:"partyIdType"`
    Name            string              `bson:"name" json:"name"`
    
    // Endpoint (for outbound)
    EndpointURL     string              `bson:"endpoint_url" json:"endpointUrl"`
    
    // Partner certificates
    SigningCert     string              `bson:"signing_cert" json:"signingCert"`      // PEM
    EncryptionCert  string              `bson:"encryption_cert" json:"encryptionCert"` // PEM
    
    // Discovery
    UseSMPDiscovery bool                `bson:"use_smp_discovery" json:"useSmpDiscovery"`
    SMPLocator      string              `bson:"smp_locator" json:"smpLocator"`  // SML/BDXL domain
    
    // P-Mode overrides
    PModeOverrides  map[string]any      `bson:"pmode_overrides" json:"pmodeOverrides"`
    
    Status          string              `bson:"status" json:"status"`
}
```

## 6. API Design

### 6.1 JMAP-Inspired Mailbox API

JMAP (RFC 8620, 8621) provides an excellent model for message access:

```
Base URL: https://api.example.com/tenant/{tenant-id}/jmap
```

#### 6.1.1 JMAP Session

```json
GET /tenant/{tenant-id}/.well-known/jmap

{
  "capabilities": {
    "urn:siros:params:jmap:as4": {
      "maxSizeUpload": 52428800,
      "maxMessagesPerQuery": 100
    }
  },
  "accounts": {
    "participant-123": {
      "name": "ACME Corp",
      "isPersonal": false,
      "accountCapabilities": {
        "urn:siros:params:jmap:as4": {
          "mailboxes": ["inbox", "outbox", "sent", "failed"]
        }
      }
    }
  },
  "primaryAccounts": {
    "urn:siros:params:jmap:as4": "participant-123"
  },
  "apiUrl": "https://api.example.com/tenant/{tenant-id}/jmap",
  "uploadUrl": "https://api.example.com/tenant/{tenant-id}/upload",
  "downloadUrl": "https://api.example.com/tenant/{tenant-id}/download/{blobId}"
}
```

#### 6.1.2 JMAP Methods

**Mailbox/get** - List mailboxes:
```json
{
  "using": ["urn:siros:params:jmap:as4"],
  "methodCalls": [
    ["Mailbox/get", {
      "accountId": "participant-123",
      "ids": null
    }, "0"]
  ]
}
```

**AS4Message/query** - Query messages:
```json
{
  "using": ["urn:siros:params:jmap:as4"],
  "methodCalls": [
    ["AS4Message/query", {
      "accountId": "participant-123",
      "filter": {
        "mailboxId": "inbox",
        "status": "received",
        "after": "2026-01-01T00:00:00Z"
      },
      "sort": [{"property": "receivedAt", "isAscending": false}],
      "limit": 50
    }, "0"]
  ]
}
```

**AS4Message/get** - Get message details:
```json
{
  "using": ["urn:siros:params:jmap:as4"],
  "methodCalls": [
    ["AS4Message/get", {
      "accountId": "participant-123",
      "ids": ["msg-abc123"],
      "properties": ["id", "messageId", "fromParty", "toParty", "service", "action", "payloads", "receivedAt"]
    }, "0"]
  ]
}
```

**AS4Message/set** - Send message (create in outbox):
```json
{
  "using": ["urn:siros:params:jmap:as4"],
  "methodCalls": [
    ["AS4Message/set", {
      "accountId": "participant-123",
      "create": {
        "draft-1": {
          "mailboxId": "outbox",
          "toParty": {
            "partyId": "receiver-456",
            "partyIdType": "urn:oasis:names:tc:ebcore:partyid-type:unregistered"
          },
          "service": "urn:example:service:invoice",
          "action": "Submit",
          "payloads": [
            {"blobId": "blob-xyz", "mimeType": "application/xml"}
          ]
        }
      }
    }, "0"]
  ]
}
```

**AS4Message/changes** - Get changes since state:
```json
{
  "using": ["urn:siros:params:jmap:as4"],
  "methodCalls": [
    ["AS4Message/changes", {
      "accountId": "participant-123",
      "sinceState": "state-abc"
    }, "0"]
  ]
}
```

### 6.2 OAuth2 Authentication

```
Authorization Server: https://auth.example.com

Scopes:
- as4:read          - Read messages and mailboxes
- as4:write         - Send messages
- as4:admin         - Manage participants and configuration
- as4:tenant:admin  - Tenant administration
```

#### Token Request (Client Credentials)
```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=participant-123
&client_secret=secret
&scope=as4:read as4:write
```

#### API Request
```http
POST /tenant/{tenant-id}/jmap
Authorization: Bearer <access_token>
Content-Type: application/json

{...}
```

### 6.3 Webhook Notifications

For real-time message notifications:

```go
type WebhookConfig struct {
    ID            string              `bson:"_id" json:"id"`
    TenantID      string              `bson:"tenant_id" json:"tenantId"`
    ParticipantID string              `bson:"participant_id" json:"participantId"`
    
    URL           string              `bson:"url" json:"url"`
    Secret        string              `bson:"secret" json:"-"`  // For HMAC signature
    
    Events        []WebhookEvent      `bson:"events" json:"events"`
    
    Status        string              `bson:"status" json:"status"`
}

type WebhookEvent string

const (
    EventMessageReceived   WebhookEvent = "message.received"
    EventMessageDelivered  WebhookEvent = "message.delivered"
    EventMessageFailed     WebhookEvent = "message.failed"
    EventReceiptReceived   WebhookEvent = "receipt.received"
)
```

Webhook payload:
```json
{
  "event": "message.received",
  "timestamp": "2026-01-11T10:30:00Z",
  "data": {
    "messageId": "msg-abc123",
    "as4MessageId": "uuid@sender.example.com",
    "fromParty": "sender-123",
    "service": "urn:example:service:invoice",
    "action": "Submit"
  }
}
```

## 7. Storage Architecture

### 7.1 Storage Interface

```go
type Storage interface {
    // Tenant operations
    TenantStore() TenantStore
    
    // Participant operations
    ParticipantStore() ParticipantStore
    
    // Mailbox operations
    MailboxStore() MailboxStore
    
    // Message operations
    MessageStore() MessageStore
    
    // P-Mode operations
    PModeStore() PModeStore
    
    // Partner operations
    PartnerStore() PartnerStore
    
    // Transaction support
    WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error
}

type MessageStore interface {
    Create(ctx context.Context, msg *Message) error
    Get(ctx context.Context, tenantID, id string) (*Message, error)
    GetByAS4MessageID(ctx context.Context, tenantID, messageID string) (*Message, error)
    
    Query(ctx context.Context, tenantID string, query MessageQuery) ([]Message, error)
    Count(ctx context.Context, tenantID string, query MessageQuery) (int64, error)
    
    Update(ctx context.Context, msg *Message) error
    UpdateStatus(ctx context.Context, tenantID, id string, status MessageStatus) error
    
    // For duplicate detection
    ExistsByAS4MessageID(ctx context.Context, tenantID, messageID string) (bool, error)
    
    // Changes tracking for sync API
    GetChanges(ctx context.Context, tenantID, mailboxID, sinceState string) (*Changes, error)
}
```

### 7.2 Storage Architecture: MongoDB-Only Approach

**Decision: Use MongoDB GridFS for payload storage instead of separate S3/object storage.**

#### Why Not S3?

| Concern | S3 Approach | MongoDB GridFS Approach |
|---------|-------------|------------------------|
| **Operational complexity** | Two systems to manage | Single system |
| **Data consistency** | Eventual, complex transactions | Strong, atomic operations |
| **Access control** | Separate IAM/policies | Same auth as metadata |
| **Deployment** | Cloud dependency or MinIO | Self-contained |
| **Backup/restore** | Two backup strategies | Single backup strategy |
| **Cost** | Additional service cost | Included in MongoDB |

#### When S3 Would Be Needed

S3/object storage becomes necessary when:
1. **Payload size > 16MB** (MongoDB document limit) - Use GridFS to handle this
2. **Extremely large payloads (>100MB)** - AS4 Split/Join handles large messages anyway
3. **CDN integration** - Direct downloads via presigned URLs
4. **Cold storage** - Very old messages archived cheaply

For the EU Business Wallet use case, typical payloads are:
- Verifiable credentials: <100KB
- Presentation requests: <10KB  
- Documents (PoA, etc.): <10MB

**GridFS handles all of these efficiently.**

#### GridFS Integration

```go
// PayloadStore using GridFS
type PayloadStore interface {
    // Store payload, returns GridFS file ID
    Store(ctx context.Context, tenantID, messageID string, data io.Reader, metadata PayloadMetadata) (string, error)
    
    // Retrieve payload
    Get(ctx context.Context, fileID string) (io.ReadCloser, *PayloadMetadata, error)
    
    // Delete payload
    Delete(ctx context.Context, fileID string) error
    
    // Stream directly to HTTP response (efficient for large files)
    StreamTo(ctx context.Context, fileID string, w io.Writer) error
}

type PayloadMetadata struct {
    TenantID    string    `bson:"tenant_id"`
    MessageID   string    `bson:"message_id"`
    ContentID   string    `bson:"content_id"`
    MimeType    string    `bson:"mime_type"`
    Size        int64     `bson:"size"`
    Checksum    string    `bson:"checksum"`
    Compressed  bool      `bson:"compressed"`
    UploadedAt  time.Time `bson:"uploaded_at"`
}
```

#### Future: Optional S3 Backend

If S3 becomes necessary later, the `PayloadStore` interface abstracts this:

```go
// Factory creates the appropriate storage backend
func NewPayloadStore(cfg StorageConfig) PayloadStore {
    if cfg.ObjectStorage.Enabled {
        return NewS3PayloadStore(cfg.ObjectStorage)
    }
    return NewGridFSPayloadStore(cfg.MongoDB)
}
```

### 7.3 MongoDB Schema

Collections:
- `tenants` - Tenant configuration
- `participants` - Participant records  
- `mailboxes` - Mailbox metadata
- `messages` - Message metadata and state
- `pmode_templates` - P-Mode templates
- `partners` - Partner configurations
- `receipts` - AS4 receipts for NRR
- `fs.files` / `fs.chunks` - GridFS payload storage

Indexes:
```javascript
// messages collection
db.messages.createIndex({ "tenant_id": 1, "mailbox_id": 1, "received_at": -1 })
db.messages.createIndex({ "tenant_id": 1, "message_id": 1 }, { unique: true })
db.messages.createIndex({ "tenant_id": 1, "status": 1, "next_retry_at": 1 })
db.messages.createIndex({ "tenant_id": 1, "conversation_id": 1 })

// participants collection
db.participants.createIndex({ "tenant_id": 1, "party_id": 1 }, { unique: true })
db.participants.createIndex({ "tenant_id": 1, "mailbox_id": 1 })

// GridFS metadata index
db.fs.files.createIndex({ "metadata.tenant_id": 1, "metadata.message_id": 1 })
```

## 8. AS4 Message Processing

### 8.1 Inbound Message Flow

```
1. HTTPS Request → Reverse Proxy
2. URL Routing → /tenant/{tenant-id}/as4
3. Tenant Resolution → Load tenant config
4. WS-Security Validation:
   - Verify signature using partner's certificate
   - Decrypt using tenant's encryption key (if encrypted)
5. P-Mode Resolution:
   - Match Service/Action to P-Mode template
   - Lookup partner configuration
6. Duplicate Detection:
   - Check MessageID against recent messages
7. Message Storage:
   - Store payloads in GridFS
   - Create message record in MongoDB
   - Update mailbox state
8. Receipt Generation:
   - Sign receipt with tenant's signing key
   - Return synchronous receipt
9. Webhook Notification:
   - Notify wallet backend of new message
```

### 8.2 Outbound Message Flow (Client-Side Signing)

```
1. Wallet Backend → Create message via API
2. AS4 Server stores unsigned message
3. Server notifies client: "message ready for signing"
4. Client:
   - Authenticates with FIDO2 + PRF
   - Decrypts signing key
   - Downloads message envelope
   - Signs with decrypted key
   - Uploads signed message
5. Server sends signed message to recipient
6. Server processes receipt
7. Server notifies client of delivery status
```

**Alternative: Session-based signing (simpler UX)**

```
1. User authenticates with FIDO2 + PRF at session start
2. Client decrypts and sends signing key to server
3. Server holds key in memory for session duration
4. Messages are signed server-side during session
5. Key cleared on session end
```

### 8.3 Outbound Message Flow (Legacy)

```
1. API Request → Create message in outbox
2. Worker picks up pending message
3. Recipient Resolution:
   - Use SMP discovery or static partner config
   - Retrieve recipient endpoint and certificates
4. Message Construction:
   - Build AS4 UserMessage
   - Apply compression
5. Security Processing:
   - Sign with tenant's signing key
   - Encrypt for recipient
6. Send via HTTPS:
   - TLS with optional client cert
7. Receipt Processing:
   - Verify receipt signature
   - Update message status
8. Retry on Failure:
   - Exponential backoff per P-Mode
   - Update message with error
```

## 9. Implementation Plan

### Phase 1: Core Infrastructure (2 weeks)

1. **Storage Layer**
   - MongoDB implementation for metadata
   - GridFS integration for payloads
   - Storage interfaces and factory

2. **Tenant Management**
   - Tenant CRUD operations
   - Tenant resolution middleware
   - Basic configuration

3. **Key Management**
   - Encrypted key blob storage
   - PRF-based key encryption/decryption
   - Session key caching (Redis)

### Phase 2: AS4 Processing (2 weeks)

4. **Inbound Processing**
   - AS4 endpoint handler
   - Tenant-aware security processor
   - Message storage pipeline
   - Receipt generation

5. **Outbound Processing**
   - Message queue/worker
   - Tenant-aware sending
   - Retry mechanism
   - Receipt handling

6. **P-Mode Management**
   - P-Mode template CRUD
   - Partner management
   - Dynamic P-Mode resolution

### Phase 3: API Layer (2 weeks)

7. **OAuth2 Integration**
   - Token validation middleware
   - Scope-based authorization
   - Participant authentication

8. **JMAP API**
   - Session endpoint
   - Mailbox methods
   - Message methods
   - Changes/state tracking

9. **Upload/Download**
   - Blob upload endpoint
   - Presigned download URLs
   - Streaming support

### Phase 4: Operations (1 week)

10. **Webhooks**
    - Webhook configuration
    - Event dispatching
    - Retry with backoff

11. **Monitoring**
    - Prometheus metrics
    - Health checks
    - Audit logging

12. **Admin API**
    - Tenant management
    - Participant management
    - Configuration API

## 10. Project Structure

```
cmd/
    as4-server/
        main.go              # Server entry point
    as4-admin/
        main.go              # Admin CLI

internal/
    server/
        server.go            # HTTP server setup
        middleware/
            tenant.go        # Tenant resolution
            auth.go          # OAuth2 validation
            logging.go       # Request logging
        
    as4/
        handler.go           # AS4 endpoint handler
        inbound.go           # Inbound processing
        outbound.go          # Outbound processing
        worker.go            # Background worker
        
    api/
        jmap/
            session.go       # JMAP session
            mailbox.go       # Mailbox methods
            message.go       # Message methods
            changes.go       # State tracking
        upload.go            # Blob upload
        download.go          # Blob download
        webhook.go           # Webhook management
        
    tenant/
        service.go           # Tenant business logic
        keystore.go          # Tenant key management
        pmode.go             # P-Mode resolution
        
    storage/
        interface.go         # Storage interfaces
        mongodb/
            store.go         # MongoDB implementation
            tenant.go
            participant.go
            mailbox.go
            message.go
            gridfs.go        # GridFS for large payloads
            
    keystore/
        interface.go         # Key storage interface
        encrypted.go         # Encrypted key blobs (PRF-based)
        session.go           # Session key management
        
    config/
        config.go            # Configuration loading

pkg/
    jmap/
        types.go             # JMAP type definitions
        request.go           # Request parsing
        response.go          # Response building
```

## 11. Configuration

```yaml
# config.yaml
server:
  listen: ":8080"
  basePath: "/tenant"
  
  tls:
    enabled: false  # Handled by reverse proxy
    
storage:
  mongodb:
    uri: "mongodb://localhost:27017"
    database: "as4"
    # GridFS settings for large payloads
    gridfs:
      bucketName: "payloads"
      chunkSizeBytes: 261120  # 255KB chunks
    
signing:
  # Mode determines how signing keys are managed
  # - "client": Keys encrypted with PRF-derived keys, client signs
  # - "session": Keys decrypted server-side during authenticated session
  mode: "session"
  
  # Session mode settings
  session:
    keyTTL: "15m"           # How long decrypted keys remain in memory
    maxKeys: 100            # Maximum cached keys per instance
    
oauth2:
  issuer: "https://auth.example.com"
  audience: "as4-api"
  jwksUrl: "https://auth.example.com/.well-known/jwks.json"
  
observability:
  metrics:
    enabled: true
    path: "/metrics"
  tracing:
    enabled: true
    endpoint: "http://jaeger:14268/api/traces"
```

## 12. Wallet Backend Integration

> **Note**: This section outlines integration patterns for experimentation. The specific APIs and data models will evolve based on pilot learnings.

### 12.1 Integration Approach

The AS4 server exposes a **generic mailbox API** that wallet backends consume. The server is agnostic to payload semantics - it handles reliable delivery, receipts, and storage. Wallet backends interpret payloads according to emerging specifications.

```
┌─────────────────────┐         ┌─────────────────────┐
│  go-wallet-backend  │         │   AS4 Server        │
│                     │         │                     │
│  ┌───────────────┐  │  API    │  ┌───────────────┐  │
│  │ AS4 Client    │◄─┼─────────┼──│ Mailbox API   │  │
│  │ (pkg/as4)     │  │         │  │               │  │
│  └───────────────┘  │         │  └───────────────┘  │
│         │           │         │         │           │
│         ▼           │  AS4    │         ▼           │
│  ┌───────────────┐  │◄────────┼──┌───────────────┐  │
│  │ Message       │  │ Webhook │  │ AS4 Processor │  │
│  │ Handler       │  │         │  │               │  │
│  └───────────────┘  │         │  └───────────────┘  │
└─────────────────────┘         └─────────────────────┘
```

### 12.2 Client Library Sketch

A minimal client for wallet backends:

```go
// pkg/as4client/client.go

package as4client

// Client provides access to AS4 mailbox operations
type Client struct {
    baseURL     string
    tenantID    string
    httpClient  *http.Client
    auth        AuthProvider  // TBD: token, mTLS, etc.
}

// Core operations - generic, not wallet-specific

// ListMessages returns messages in the inbox
func (c *Client) ListMessages(ctx context.Context, opts ListOptions) (*MessageList, error)

// GetMessage retrieves a single message
func (c *Client) GetMessage(ctx context.Context, id string) (*Message, error)

// GetPayload downloads a message payload
func (c *Client) GetPayload(ctx context.Context, messageID, payloadID string) (io.ReadCloser, error)

// SendMessage queues a message for delivery
func (c *Client) SendMessage(ctx context.Context, msg *OutboundMessage) (*SendResult, error)

// MarkRead marks a message as read
func (c *Client) MarkRead(ctx context.Context, id string) error

// GetChanges returns changes since a state token (for sync)
func (c *Client) GetChanges(ctx context.Context, sinceState string) (*Changes, error)
```

### 12.3 Access API (To Be Determined)

The mailbox access API design is an open question:

| Option | Pros | Cons |
|--------|------|------|
| **Simple REST** | Easy to implement, well understood | No built-in sync semantics |
| **JMAP** | Excellent sync/changes support | Complex, may be overkill |
| **GraphQL** | Flexible queries | Complexity, caching challenges |
| **gRPC** | Efficient, streaming | Browser support via proxy |

**Initial approach**: Start with simple REST, add sync semantics as needed.

### 12.4 Discovery via SMP

This is the one certainty. Wallet backends register their AS4 endpoints via SMP:

```
1. Wallet backend registers participant:
   - PartyID: Business identifier (LEI, EORI, etc.) or DID
   - DocumentTypes: Generic document exchange initially
   
2. AS4 server publishes to SMP:
   - Endpoint URL: https://as4.example.com/tenant/{id}/as4
   - Certificate: Tenant's AS4 signing certificate
   
3. Sender discovers recipient:
   - Query SMP for PartyID
   - Retrieve endpoint and certificate
   - Send AS4 message
```

### 12.5 Webhook Notifications

For real-time updates to wallet backends:

```go
// Webhook event - generic structure
type WebhookEvent struct {
    Type      string          `json:"type"`       // message.received, message.delivered, etc.
    Timestamp time.Time       `json:"timestamp"`
    TenantID  string          `json:"tenantId"`
    Data      json.RawMessage `json:"data"`       // Event-specific payload
}

// Wallet backend handles events
func (h *WebhookHandler) HandleAS4Event(event *WebhookEvent) {
    switch event.Type {
    case "message.received":
        // Trigger inbox sync or process immediately
        h.processNewMessage(event.Data)
    case "message.delivered":
        // Update outbound message status
        h.updateMessageStatus(event.Data)
    }
}
```

## 13. Open Questions for Experimentation

These questions will be explored during the pilot. We don't need answers upfront - the server is designed to allow experimentation.

### Architecture

| Question | Options | Notes |
|----------|---------|-------|
| Tenant model | Per-wallet-backend vs. multi-operator | TBD |
| Deployment | Separate service vs. embedded library | TBD |
| Storage | Shared vs. separate MongoDB | TBD |

### Access API

| Question | Options | Notes |
|----------|---------|-------|
| API style | REST, JMAP, GraphQL, gRPC | Start with REST |
| Authentication | OAuth2, mTLS, API keys | TBD |
| Real-time updates | Webhooks, SSE, WebSocket | Start with webhooks |

### Identity & Discovery

| Question | Options | Notes |
|----------|---------|-------|
| Party ID | Business IDs, DIDs, or both | TBD |
| Discovery | **SMP publication** | ✅ Decided |

### Operations

| Question | Options | Notes |
|----------|---------|-------|
| Key management | **FIDO2/PRF client-side encryption** | ✅ Decided |
| Storage | **MongoDB + GridFS** | ✅ Decided |
| Retention | Per-tenant config | TBD |
| Audit level | TBD per compliance needs | TBD |

## 14. Implementation Plan

### Phase 1: Core Server (3-4 weeks)

**Goal**: Working AS4 server with basic mailbox functionality

1. **Server Skeleton**
   - HTTP server with tenant routing
   - Configuration loading
   - Health checks

2. **Storage Layer**  
   - MongoDB: tenants, participants, messages
   - GridFS for payloads (>255KB)

3. **AS4 Processing**
   - Inbound handler (reuse go-as4 security)
   - Receipt generation
   - Basic outbound sending

4. **Simple REST API**
   - `GET /messages` - List inbox
   - `GET /messages/{id}` - Get message
   - `GET /messages/{id}/payloads/{pid}` - Download payload
   - `POST /messages` - Send message

5. **SMP Integration**
   - Publish participant endpoints
   - Query for recipient discovery

### Phase 2: Integration & Notifications (2-3 weeks)

**Goal**: Connect to go-wallet-backend

6. **Client Library** (`pkg/as4client`)
   - Go client for mailbox API
   - Integration helpers

7. **Webhooks**
   - Event dispatching
   - Retry with backoff

8. **P-Mode Management**
   - Template configuration
   - Partner management

### Phase 3: Production Readiness (2 weeks)

**Goal**: Deployable for pilot

9. **Multi-tenancy**
   - Full tenant isolation
   - Per-tenant config

10. **Observability**
    - Prometheus metrics
    - Structured logging

11. **Security**
    - Secrets management
    - Rate limiting

### Deferred (Post-Specifications)

- Wallet-specific message types
- Credential/presentation protocols
- Frontend inbox UI
- Full JMAP API
- Split/Join, Pull MEP

## 15. References

- [JMAP Core (RFC 8620)](https://www.rfc-editor.org/rfc/rfc8620)
- [JMAP Mail (RFC 8621)](https://www.rfc-editor.org/rfc/rfc8621)
- [OAuth 2.0 (RFC 6749)](https://www.rfc-editor.org/rfc/rfc6749)
- [eDelivery AS4 2.0](https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/845480153/eDelivery+AS4+-+2.0)
- [DIDComm Messaging v2](https://identity.foundation/didcomm-messaging/spec/) - Conceptual comparison
- [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [EU Digital Identity Wallet Architecture](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework)
- [go-as4 Documentation](../IMPLEMENTATION.md)
- [go-wallet-backend](https://github.com/sirosfoundation/go-wallet-backend)
