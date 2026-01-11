// Package mongodb implements storage interfaces using MongoDB
package mongodb

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/gridfs"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/sirosfoundation/go-as4/internal/keystore"
	"github.com/sirosfoundation/go-as4/internal/storage"
)

// Store implements storage.Store using MongoDB
type Store struct {
	client *mongo.Client
	db     *mongo.Database
	gridfs *gridfs.Bucket

	// Collections
	tenants      *mongo.Collection
	participants *mongo.Collection
	mailboxes    *mongo.Collection
	messages     *mongo.Collection
	keys         *mongo.Collection
	certs        *mongo.Collection
}

// Config holds MongoDB connection settings
type Config struct {
	URI            string
	Database       string
	GridFSBucket   string
	ChunkSizeBytes int32
}

// NewStore creates a new MongoDB store
func NewStore(ctx context.Context, cfg *Config) (*Store, error) {
	// Connect to MongoDB
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.URI))
	if err != nil {
		return nil, fmt.Errorf("connecting to MongoDB: %w", err)
	}

	// Verify connection
	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("pinging MongoDB: %w", err)
	}

	db := client.Database(cfg.Database)

	// Create GridFS bucket for payloads
	bucketName := cfg.GridFSBucket
	if bucketName == "" {
		bucketName = "payloads"
	}
	chunkSize := cfg.ChunkSizeBytes
	if chunkSize == 0 {
		chunkSize = 261120 // 255KB
	}
	bucket, err := gridfs.NewBucket(db, options.GridFSBucket().
		SetName(bucketName).
		SetChunkSizeBytes(chunkSize))
	if err != nil {
		return nil, fmt.Errorf("creating GridFS bucket: %w", err)
	}

	s := &Store{
		client:       client,
		db:           db,
		gridfs:       bucket,
		tenants:      db.Collection("tenants"),
		participants: db.Collection("participants"),
		mailboxes:    db.Collection("mailboxes"),
		messages:     db.Collection("messages"),
		keys:         db.Collection("encrypted_keys"),
		certs:        db.Collection("certificates"),
	}

	// Create indexes
	if err := s.createIndexes(ctx); err != nil {
		return nil, fmt.Errorf("creating indexes: %w", err)
	}

	return s, nil
}

func (s *Store) createIndexes(ctx context.Context) error {
	// Tenant indexes
	_, err := s.tenants.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "domain", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "status", Value: 1}}},
	})
	if err != nil {
		return fmt.Errorf("creating tenant indexes: %w", err)
	}

	// Participant indexes
	_, err = s.participants.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "party_id.value", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "mailbox_id", Value: 1}}},
	})
	if err != nil {
		return fmt.Errorf("creating participant indexes: %w", err)
	}

	// Mailbox indexes
	_, err = s.mailboxes.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "participant_id", Value: 1}}},
	})
	if err != nil {
		return fmt.Errorf("creating mailbox indexes: %w", err)
	}

	// Message indexes
	_, err = s.messages.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "as4_message_id", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "mailbox_id", Value: 1}, {Key: "status", Value: 1}}},
		{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "status", Value: 1}, {Key: "next_retry_at", Value: 1}}},
		{Keys: bson.D{{Key: "conversation_id", Value: 1}}},
		{Keys: bson.D{{Key: "received_at", Value: -1}}},
	})
	if err != nil {
		return fmt.Errorf("creating message indexes: %w", err)
	}

	// Key indexes
	_, err = s.keys.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "tenant_id", Value: 1}, {Key: "key_id", Value: 1}}, Options: options.Index().SetUnique(true)},
	})
	if err != nil {
		return fmt.Errorf("creating key indexes: %w", err)
	}

	return nil
}

// Close closes the MongoDB connection
func (s *Store) Close(ctx context.Context) error {
	return s.client.Disconnect(ctx)
}

// Ping verifies database connectivity
func (s *Store) Ping(ctx context.Context) error {
	return s.client.Ping(ctx, nil)
}

// TenantStore implementation

func (s *Store) CreateTenant(ctx context.Context, tenant *storage.Tenant) error {
	tenant.CreatedAt = time.Now()
	tenant.UpdatedAt = tenant.CreatedAt
	if tenant.ID == "" {
		tenant.ID = primitive.NewObjectID().Hex()
	}

	_, err := s.tenants.InsertOne(ctx, tenant)
	if mongo.IsDuplicateKeyError(err) {
		return fmt.Errorf("tenant with domain %s already exists", tenant.Domain)
	}
	return err
}

func (s *Store) GetTenant(ctx context.Context, id string) (*storage.Tenant, error) {
	var tenant storage.Tenant
	err := s.tenants.FindOne(ctx, bson.M{"_id": id}).Decode(&tenant)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	return &tenant, err
}

func (s *Store) GetTenantByDomain(ctx context.Context, domain string) (*storage.Tenant, error) {
	var tenant storage.Tenant
	err := s.tenants.FindOne(ctx, bson.M{"domain": domain}).Decode(&tenant)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	return &tenant, err
}

func (s *Store) UpdateTenant(ctx context.Context, tenant *storage.Tenant) error {
	tenant.UpdatedAt = time.Now()
	_, err := s.tenants.ReplaceOne(ctx, bson.M{"_id": tenant.ID}, tenant)
	return err
}

func (s *Store) DeleteTenant(ctx context.Context, id string) error {
	_, err := s.tenants.UpdateOne(ctx, bson.M{"_id": id}, bson.M{
		"$set": bson.M{
			"status":     storage.TenantStatusSuspended,
			"updated_at": time.Now(),
		},
	})
	return err
}

func (s *Store) ListTenants(ctx context.Context, filter *storage.TenantFilter) ([]*storage.Tenant, error) {
	query := bson.M{}
	if filter != nil && filter.Status != "" {
		query["status"] = filter.Status
	}

	opts := options.Find()
	if filter != nil {
		if filter.Limit > 0 {
			opts.SetLimit(int64(filter.Limit))
		}
		if filter.Offset > 0 {
			opts.SetSkip(int64(filter.Offset))
		}
	}

	cursor, err := s.tenants.Find(ctx, query, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var tenants []*storage.Tenant
	if err := cursor.All(ctx, &tenants); err != nil {
		return nil, err
	}
	return tenants, nil
}

// ParticipantStore implementation

func (s *Store) CreateParticipant(ctx context.Context, participant *storage.Participant) error {
	participant.CreatedAt = time.Now()
	participant.UpdatedAt = participant.CreatedAt
	if participant.ID == "" {
		participant.ID = primitive.NewObjectID().Hex()
	}

	_, err := s.participants.InsertOne(ctx, participant)
	return err
}

func (s *Store) GetParticipant(ctx context.Context, tenantID, id string) (*storage.Participant, error) {
	var participant storage.Participant
	err := s.participants.FindOne(ctx, bson.M{"_id": id, "tenant_id": tenantID}).Decode(&participant)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	return &participant, err
}

func (s *Store) GetParticipantByPartyID(ctx context.Context, tenantID string, partyID storage.PartyID) (*storage.Participant, error) {
	var participant storage.Participant
	err := s.participants.FindOne(ctx, bson.M{
		"tenant_id":      tenantID,
		"party_id.type":  partyID.Type,
		"party_id.value": partyID.Value,
	}).Decode(&participant)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	return &participant, err
}

func (s *Store) UpdateParticipant(ctx context.Context, participant *storage.Participant) error {
	participant.UpdatedAt = time.Now()
	_, err := s.participants.ReplaceOne(ctx, bson.M{"_id": participant.ID, "tenant_id": participant.TenantID}, participant)
	return err
}

func (s *Store) DeleteParticipant(ctx context.Context, tenantID, id string) error {
	_, err := s.participants.DeleteOne(ctx, bson.M{"_id": id, "tenant_id": tenantID})
	return err
}

func (s *Store) ListParticipants(ctx context.Context, tenantID string, filter *storage.ParticipantFilter) ([]*storage.Participant, error) {
	query := bson.M{"tenant_id": tenantID}
	if filter != nil && filter.Status != "" {
		query["status"] = filter.Status
	}

	opts := options.Find()
	if filter != nil {
		if filter.Limit > 0 {
			opts.SetLimit(int64(filter.Limit))
		}
		if filter.Offset > 0 {
			opts.SetSkip(int64(filter.Offset))
		}
	}

	cursor, err := s.participants.Find(ctx, query, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var participants []*storage.Participant
	if err := cursor.All(ctx, &participants); err != nil {
		return nil, err
	}
	return participants, nil
}

// MailboxStore implementation

func (s *Store) GetMailbox(ctx context.Context, tenantID, id string) (*storage.Mailbox, error) {
	var mailbox storage.Mailbox
	err := s.mailboxes.FindOne(ctx, bson.M{"_id": id, "tenant_id": tenantID}).Decode(&mailbox)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	return &mailbox, err
}

func (s *Store) GetMailboxByParticipant(ctx context.Context, tenantID, participantID string) (*storage.Mailbox, error) {
	var mailbox storage.Mailbox
	err := s.mailboxes.FindOne(ctx, bson.M{"tenant_id": tenantID, "participant_id": participantID}).Decode(&mailbox)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	return &mailbox, err
}

func (s *Store) CreateMailbox(ctx context.Context, mailbox *storage.Mailbox) error {
	mailbox.CreatedAt = time.Now()
	if mailbox.ID == "" {
		mailbox.ID = primitive.NewObjectID().Hex()
	}
	mailbox.StateID = primitive.NewObjectID().Hex()

	_, err := s.mailboxes.InsertOne(ctx, mailbox)
	return err
}

func (s *Store) UpdateMailbox(ctx context.Context, mailbox *storage.Mailbox) error {
	mailbox.StateID = primitive.NewObjectID().Hex() // Update state on any change
	_, err := s.mailboxes.ReplaceOne(ctx, bson.M{"_id": mailbox.ID, "tenant_id": mailbox.TenantID}, mailbox)
	return err
}

func (s *Store) ListMailboxes(ctx context.Context, tenantID string) ([]*storage.Mailbox, error) {
	cursor, err := s.mailboxes.Find(ctx, bson.M{"tenant_id": tenantID})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var mailboxes []*storage.Mailbox
	if err := cursor.All(ctx, &mailboxes); err != nil {
		return nil, err
	}
	return mailboxes, nil
}

// MessageStore implementation

func (s *Store) CreateMessage(ctx context.Context, msg *storage.Message) error {
	if msg.ID == "" {
		msg.ID = primitive.NewObjectID().Hex()
	}
	if msg.ReceivedAt.IsZero() {
		msg.ReceivedAt = time.Now()
	}

	_, err := s.messages.InsertOne(ctx, msg)
	return err
}

func (s *Store) GetMessage(ctx context.Context, tenantID, id string) (*storage.Message, error) {
	var msg storage.Message
	err := s.messages.FindOne(ctx, bson.M{"_id": id, "tenant_id": tenantID}).Decode(&msg)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	return &msg, err
}

func (s *Store) GetMessageByAS4ID(ctx context.Context, tenantID, as4MessageID string) (*storage.Message, error) {
	var msg storage.Message
	err := s.messages.FindOne(ctx, bson.M{"tenant_id": tenantID, "as4_message_id": as4MessageID}).Decode(&msg)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	return &msg, err
}

func (s *Store) UpdateMessage(ctx context.Context, msg *storage.Message) error {
	_, err := s.messages.ReplaceOne(ctx, bson.M{"_id": msg.ID, "tenant_id": msg.TenantID}, msg)
	return err
}

func (s *Store) UpdateMessageStatus(ctx context.Context, tenantID, id string, status storage.MessageStatus) error {
	_, err := s.messages.UpdateOne(ctx, bson.M{"_id": id, "tenant_id": tenantID}, bson.M{
		"$set": bson.M{"status": status},
	})
	return err
}

func (s *Store) ListMessages(ctx context.Context, tenantID string, filter *storage.MessageFilter) ([]*storage.Message, error) {
	query := bson.M{"tenant_id": tenantID}
	if filter != nil {
		if filter.MailboxID != "" {
			query["mailbox_id"] = filter.MailboxID
		}
		if filter.Direction != "" {
			query["direction"] = filter.Direction
		}
		if filter.Status != "" {
			query["status"] = filter.Status
		}
		if filter.Service != "" {
			query["service"] = filter.Service
		}
		if filter.Action != "" {
			query["action"] = filter.Action
		}
		if filter.Since != nil {
			query["received_at"] = bson.M{"$gte": *filter.Since}
		}
	}

	opts := options.Find().SetSort(bson.D{{Key: "received_at", Value: -1}})
	if filter != nil {
		if filter.Limit > 0 {
			opts.SetLimit(int64(filter.Limit))
		}
		if filter.Offset > 0 {
			opts.SetSkip(int64(filter.Offset))
		}
	}

	cursor, err := s.messages.Find(ctx, query, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var messages []*storage.Message
	if err := cursor.All(ctx, &messages); err != nil {
		return nil, err
	}
	return messages, nil
}

func (s *Store) CountMessages(ctx context.Context, tenantID string, filter *storage.MessageFilter) (int64, error) {
	query := bson.M{"tenant_id": tenantID}
	if filter != nil {
		if filter.MailboxID != "" {
			query["mailbox_id"] = filter.MailboxID
		}
		if filter.Direction != "" {
			query["direction"] = filter.Direction
		}
		if filter.Status != "" {
			query["status"] = filter.Status
		}
	}

	return s.messages.CountDocuments(ctx, query)
}

func (s *Store) GetPendingOutbound(ctx context.Context, tenantID string, limit int) ([]*storage.Message, error) {
	now := time.Now()
	query := bson.M{
		"tenant_id": tenantID,
		"direction": storage.DirectionOutbound,
		"status":    storage.StatusPending,
		"$or": []bson.M{
			{"next_retry_at": nil},
			{"next_retry_at": bson.M{"$lte": now}},
		},
	}

	opts := options.Find().
		SetSort(bson.D{{Key: "received_at", Value: 1}}).
		SetLimit(int64(limit))

	cursor, err := s.messages.Find(ctx, query, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var messages []*storage.Message
	if err := cursor.All(ctx, &messages); err != nil {
		return nil, err
	}
	return messages, nil
}

// PayloadStore implementation using GridFS

func (s *Store) StorePayload(ctx context.Context, tenantID string, payload *storage.PayloadData) (string, error) {
	// Calculate checksum if not provided
	if payload.Checksum == "" {
		hash := sha256.Sum256(payload.Data)
		payload.Checksum = hex.EncodeToString(hash[:])
	}

	// Generate ID
	if payload.ID == "" {
		payload.ID = primitive.NewObjectID().Hex()
	}

	// Store in GridFS with metadata
	filename := fmt.Sprintf("%s/%s/%s", tenantID, payload.ID, payload.ContentID)
	uploadOpts := options.GridFSUpload().SetMetadata(bson.M{
		"tenant_id":  tenantID,
		"content_id": payload.ContentID,
		"mime_type":  payload.MimeType,
		"checksum":   payload.Checksum,
	})

	uploadStream, err := s.gridfs.OpenUploadStream(filename, uploadOpts)
	if err != nil {
		return "", fmt.Errorf("opening upload stream: %w", err)
	}
	defer uploadStream.Close()

	_, err = uploadStream.Write(payload.Data)
	if err != nil {
		return "", fmt.Errorf("writing payload: %w", err)
	}

	return uploadStream.FileID.(primitive.ObjectID).Hex(), nil
}

func (s *Store) GetPayload(ctx context.Context, tenantID, id string) (*storage.PayloadData, error) {
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, fmt.Errorf("invalid payload ID: %w", err)
	}

	downloadStream, err := s.gridfs.OpenDownloadStream(objID)
	if err != nil {
		return nil, fmt.Errorf("opening download stream: %w", err)
	}
	defer downloadStream.Close()

	// Read all data
	data := make([]byte, downloadStream.GetFile().Length)
	_, err = downloadStream.Read(data)
	if err != nil {
		return nil, fmt.Errorf("reading payload: %w", err)
	}

	file := downloadStream.GetFile()
	metadata := file.Metadata

	contentID, _ := metadata.Lookup("content_id").StringValueOK()
	mimeType, _ := metadata.Lookup("mime_type").StringValueOK()
	checksum, _ := metadata.Lookup("checksum").StringValueOK()

	return &storage.PayloadData{
		ID:        id,
		ContentID: contentID,
		MimeType:  mimeType,
		Data:      data,
		Checksum:  checksum,
	}, nil
}

func (s *Store) DeletePayload(ctx context.Context, tenantID, id string) error {
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return fmt.Errorf("invalid payload ID: %w", err)
	}
	return s.gridfs.Delete(objID)
}

// EncryptedKeyStore implementation (for PRF mode)

type encryptedKeyDoc struct {
	TenantID     string `bson:"tenant_id"`
	KeyID        string `bson:"key_id"`
	Algorithm    string `bson:"algorithm"`
	EncryptedKey []byte `bson:"encrypted_key"`
	IV           []byte `bson:"iv"`
	Tag          []byte `bson:"tag"`
	Salt         []byte `bson:"salt"`
}

func (s *Store) GetEncryptedKey(ctx context.Context, tenantID, keyID string) (*keystore.EncryptedKeyBlob, error) {
	var doc encryptedKeyDoc
	err := s.keys.FindOne(ctx, bson.M{"tenant_id": tenantID, "key_id": keyID}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, keystore.ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}

	return &keystore.EncryptedKeyBlob{
		KeyID:        doc.KeyID,
		Algorithm:    doc.Algorithm,
		EncryptedKey: doc.EncryptedKey,
		IV:           doc.IV,
		Tag:          doc.Tag,
		Salt:         doc.Salt,
	}, nil
}

func (s *Store) StoreEncryptedKey(ctx context.Context, tenantID string, blob *keystore.EncryptedKeyBlob) error {
	doc := encryptedKeyDoc{
		TenantID:     tenantID,
		KeyID:        blob.KeyID,
		Algorithm:    blob.Algorithm,
		EncryptedKey: blob.EncryptedKey,
		IV:           blob.IV,
		Tag:          blob.Tag,
		Salt:         blob.Salt,
	}

	opts := options.Replace().SetUpsert(true)
	_, err := s.keys.ReplaceOne(ctx, bson.M{"tenant_id": tenantID, "key_id": blob.KeyID}, doc, opts)
	return err
}

func (s *Store) GetCertificate(ctx context.Context, tenantID, keyID string) (*x509.Certificate, error) {
	var doc struct {
		CertDER []byte `bson:"cert_der"`
	}
	err := s.certs.FindOne(ctx, bson.M{"tenant_id": tenantID, "key_id": keyID}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, keystore.ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(doc.CertDER)
}

func (s *Store) StoreCertificate(ctx context.Context, tenantID, keyID string, cert *x509.Certificate) error {
	doc := bson.M{
		"tenant_id":  tenantID,
		"key_id":     keyID,
		"cert_der":   cert.Raw,
		"subject":    cert.Subject.String(),
		"not_before": cert.NotBefore,
		"not_after":  cert.NotAfter,
	}

	opts := options.Replace().SetUpsert(true)
	_, err := s.certs.ReplaceOne(ctx, bson.M{"tenant_id": tenantID, "key_id": keyID}, doc, opts)
	return err
}

func (s *Store) ListKeys(ctx context.Context, tenantID string) ([]keystore.KeyInfo, error) {
	cursor, err := s.certs.Find(ctx, bson.M{"tenant_id": tenantID})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var keys []keystore.KeyInfo
	for cursor.Next(ctx) {
		var doc struct {
			KeyID     string    `bson:"key_id"`
			Subject   string    `bson:"subject"`
			NotBefore time.Time `bson:"not_before"`
			NotAfter  time.Time `bson:"not_after"`
		}
		if err := cursor.Decode(&doc); err != nil {
			continue
		}
		keys = append(keys, keystore.KeyInfo{
			KeyID:              doc.KeyID,
			Label:              doc.KeyID,
			NotBefore:          doc.NotBefore,
			NotAfter:           doc.NotAfter,
			CertificateSubject: doc.Subject,
		})
	}
	return keys, nil
}

func (s *Store) DeleteKey(ctx context.Context, tenantID, keyID string) error {
	_, err := s.keys.DeleteOne(ctx, bson.M{"tenant_id": tenantID, "key_id": keyID})
	if err != nil {
		return err
	}
	_, err = s.certs.DeleteOne(ctx, bson.M{"tenant_id": tenantID, "key_id": keyID})
	return err
}

// StateStore implementation

// GetState returns the current state for a data type
// State is derived from the most recent update timestamp in the collection
func (s *Store) GetState(ctx context.Context, tenantID, dataType string) (string, error) {
	coll := s.collectionForDataType(dataType)
	if coll == nil {
		return "", fmt.Errorf("unknown data type: %s", dataType)
	}

	// Find the most recently updated document
	opts := options.FindOne().SetSort(bson.D{{Key: "updated_at", Value: -1}}).SetProjection(bson.M{"updated_at": 1})

	filter := bson.M{}
	if dataType != "Tenant" {
		filter["tenant_id"] = tenantID
	}

	var result struct {
		UpdatedAt time.Time `bson:"updated_at"`
	}
	err := coll.FindOne(ctx, filter, opts).Decode(&result)
	if err == mongo.ErrNoDocuments {
		// No documents, return initial state
		return encodeState(time.Time{}), nil
	}
	if err != nil {
		return "", fmt.Errorf("getting state: %w", err)
	}

	return encodeState(result.UpdatedAt), nil
}

// GetChanges returns changes since a given state
func (s *Store) GetChanges(ctx context.Context, tenantID, dataType, sinceState string, maxChanges int) (*storage.Changes, error) {
	sinceTime, err := decodeState(sinceState)
	if err != nil {
		return nil, storage.ErrStateNotFound
	}

	coll := s.collectionForDataType(dataType)
	if coll == nil {
		return nil, fmt.Errorf("unknown data type: %s", dataType)
	}

	if maxChanges <= 0 {
		maxChanges = 500
	}

	// Build filter for documents changed since sinceTime
	filter := bson.M{}
	if dataType != "Tenant" {
		filter["tenant_id"] = tenantID
	}

	// Query for created documents (created_at > sinceTime)
	createdFilter := copyFilter(filter)
	createdFilter["created_at"] = bson.M{"$gt": sinceTime}

	createdCursor, err := coll.Find(ctx, createdFilter,
		options.Find().SetProjection(bson.M{"_id": 1}).SetLimit(int64(maxChanges)))
	if err != nil {
		return nil, fmt.Errorf("finding created: %w", err)
	}
	defer createdCursor.Close(ctx)

	var created []string
	for createdCursor.Next(ctx) {
		var doc struct {
			ID string `bson:"_id"`
		}
		if err := createdCursor.Decode(&doc); err == nil {
			created = append(created, doc.ID)
		}
	}

	// Query for updated documents (updated_at > sinceTime AND created_at <= sinceTime)
	updatedFilter := copyFilter(filter)
	updatedFilter["updated_at"] = bson.M{"$gt": sinceTime}
	updatedFilter["created_at"] = bson.M{"$lte": sinceTime}

	updatedCursor, err := coll.Find(ctx, updatedFilter,
		options.Find().SetProjection(bson.M{"_id": 1}).SetLimit(int64(maxChanges)))
	if err != nil {
		return nil, fmt.Errorf("finding updated: %w", err)
	}
	defer updatedCursor.Close(ctx)

	var updated []string
	for updatedCursor.Next(ctx) {
		var doc struct {
			ID string `bson:"_id"`
		}
		if err := updatedCursor.Decode(&doc); err == nil {
			updated = append(updated, doc.ID)
		}
	}

	// Get current state
	newState, err := s.GetState(ctx, tenantID, dataType)
	if err != nil {
		return nil, err
	}

	// Check if there are more changes
	hasMore := len(created)+len(updated) >= maxChanges

	return &storage.Changes{
		OldState:       sinceState,
		NewState:       newState,
		HasMoreChanges: hasMore,
		Created:        created,
		Updated:        updated,
		Destroyed:      []string{}, // Soft deletes tracked via status field
	}, nil
}

// Subscribe returns a channel for real-time state change notifications
// Uses MongoDB change streams when available (replica set required)
func (s *Store) Subscribe(ctx context.Context, tenantID string, dataTypes []string) (<-chan storage.StateChange, error) {
	ch := make(chan storage.StateChange, 100)

	// Try to use change streams (requires replica set)
	go s.watchChanges(ctx, tenantID, dataTypes, ch)

	return ch, nil
}

func (s *Store) watchChanges(ctx context.Context, tenantID string, dataTypes []string, ch chan<- storage.StateChange) {
	defer close(ch)

	// Build pipeline to filter by tenant
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.D{
			{Key: "operationType", Value: bson.M{"$in": []string{"insert", "update", "replace", "delete"}}},
		}}},
	}

	// Watch the database for changes
	opts := options.ChangeStream().SetFullDocument(options.UpdateLookup)

	stream, err := s.db.Watch(ctx, pipeline, opts)
	if err != nil {
		// Change streams not available (standalone MongoDB)
		// Fall back to polling
		s.pollChanges(ctx, tenantID, dataTypes, ch)
		return
	}
	defer stream.Close(ctx)

	for stream.Next(ctx) {
		var event struct {
			OperationType string `bson:"operationType"`
			NS            struct {
				Coll string `bson:"coll"`
			} `bson:"ns"`
			FullDocument bson.M `bson:"fullDocument"`
			DocumentKey  struct {
				ID string `bson:"_id"`
			} `bson:"documentKey"`
		}
		if err := stream.Decode(&event); err != nil {
			continue
		}

		// Map collection to data type
		dataType := s.dataTypeForCollection(event.NS.Coll)
		if dataType == "" {
			continue
		}

		// Check if this data type is subscribed
		subscribed := false
		for _, dt := range dataTypes {
			if dt == dataType {
				subscribed = true
				break
			}
		}
		if !subscribed {
			continue
		}

		// Check tenant filter (if not tenant collection)
		if dataType != "Tenant" {
			if docTenant, ok := event.FullDocument["tenant_id"].(string); ok {
				if docTenant != tenantID {
					continue
				}
			}
		}

		// Get new state for this data type
		newState, err := s.GetState(ctx, tenantID, dataType)
		if err != nil {
			continue
		}

		// Send state change
		select {
		case ch <- storage.StateChange{
			TenantID:  tenantID,
			DataTypes: map[string]string{dataType: newState},
		}:
		case <-ctx.Done():
			return
		}
	}
}

// pollChanges is a fallback for when change streams aren't available
func (s *Store) pollChanges(ctx context.Context, tenantID string, dataTypes []string, ch chan<- storage.StateChange) {
	// Track last known state for each data type
	lastStates := make(map[string]string)
	for _, dt := range dataTypes {
		state, _ := s.GetState(ctx, tenantID, dt)
		lastStates[dt] = state
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			changed := make(map[string]string)
			for _, dt := range dataTypes {
				state, err := s.GetState(ctx, tenantID, dt)
				if err != nil {
					continue
				}
				if state != lastStates[dt] {
					changed[dt] = state
					lastStates[dt] = state
				}
			}
			if len(changed) > 0 {
				select {
				case ch <- storage.StateChange{
					TenantID:  tenantID,
					DataTypes: changed,
				}:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func (s *Store) collectionForDataType(dataType string) *mongo.Collection {
	switch dataType {
	case "AS4Message":
		return s.messages
	case "AS4Mailbox":
		return s.mailboxes
	case "AS4Participant":
		return s.participants
	case "Tenant":
		return s.tenants
	default:
		return nil
	}
}

func (s *Store) dataTypeForCollection(coll string) string {
	switch coll {
	case "messages":
		return "AS4Message"
	case "mailboxes":
		return "AS4Mailbox"
	case "participants":
		return "AS4Participant"
	case "tenants":
		return "Tenant"
	default:
		return ""
	}
}

// State encoding: base64(timestamp_nanoseconds)
func encodeState(t time.Time) string {
	if t.IsZero() {
		return "AAAAAAAAAA"
	}
	// Use hex-encoded nanoseconds since epoch
	ns := t.UnixNano()
	return hex.EncodeToString([]byte(fmt.Sprintf("%016x", ns)))
}

func decodeState(state string) (time.Time, error) {
	if state == "" || state == "AAAAAAAAAA" {
		return time.Time{}, nil
	}

	// Decode hex
	decoded, err := hex.DecodeString(state)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid state encoding")
	}

	// Parse as nanoseconds
	var ns int64
	_, err = fmt.Sscanf(string(decoded), "%016x", &ns)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid state format")
	}

	return time.Unix(0, ns), nil
}

func copyFilter(f bson.M) bson.M {
	result := make(bson.M, len(f))
	for k, v := range f {
		result[k] = v
	}
	return result
}
