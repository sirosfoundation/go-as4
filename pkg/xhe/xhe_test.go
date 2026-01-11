package xhe

import (
	"strings"
	"testing"
	"time"
)

func TestNewBuilder(t *testing.T) {
	builder := NewBuilder()
	if builder == nil {
		t.Fatal("NewBuilder returned nil")
	}
	if builder.xhe == nil {
		t.Fatal("Builder.xhe is nil")
	}
	if builder.xhe.XHEVersionID != "1.0" {
		t.Errorf("XHEVersionID = %q, want %q", builder.xhe.XHEVersionID, "1.0")
	}
	if builder.xhe.CustomizationID != SDKCustomizationID {
		t.Errorf("CustomizationID = %q, want %q", builder.xhe.CustomizationID, SDKCustomizationID)
	}
}

func TestBuilderBuild(t *testing.T) {
	testTime := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)

	xhe, err := NewBuilder().
		WithID("test-id-123").
		WithUUID("550e8400-e29b-41d4-a716-446655440000").
		WithCreationTime(testTime).
		WithFromParty("iso6523-actorid-upis", "0203:sender-org").
		WithToParty("iso6523-actorid-upis", "0203:recipient-org").
		AddXMLPayload("payload-1", []byte("<TestDocument/>")).
		Build()

	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if xhe.Header.ID != "test-id-123" {
		t.Errorf("Header.ID = %q, want %q", xhe.Header.ID, "test-id-123")
	}
	if xhe.Header.UUID != "550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("Header.UUID = %q, want %q", xhe.Header.UUID, "550e8400-e29b-41d4-a716-446655440000")
	}
	if xhe.Header.FromParty.PartyID.Value != "0203:sender-org" {
		t.Errorf("FromParty = %q, want %q", xhe.Header.FromParty.PartyID.Value, "0203:sender-org")
	}
	if len(xhe.Header.ToParty) != 1 {
		t.Fatalf("ToParty length = %d, want 1", len(xhe.Header.ToParty))
	}
	if xhe.Header.ToParty[0].PartyID.Value != "0203:recipient-org" {
		t.Errorf("ToParty[0] = %q, want %q", xhe.Header.ToParty[0].PartyID.Value, "0203:recipient-org")
	}
	if len(xhe.Payloads.Payload) != 1 {
		t.Fatalf("Payload length = %d, want 1", len(xhe.Payloads.Payload))
	}
}

func TestBuilderValidation(t *testing.T) {
	tests := []struct {
		name    string
		builder func() *Builder
		wantErr string
	}{
		{
			name: "missing ID",
			builder: func() *Builder {
				return NewBuilder().
					WithFromParty("scheme", "from").
					WithToParty("scheme", "to").
					AddXMLPayload("p1", []byte("<doc/>"))
			},
			wantErr: "header ID is required",
		},
		{
			name: "missing FromParty",
			builder: func() *Builder {
				return NewBuilder().
					WithID("id").
					WithToParty("scheme", "to").
					AddXMLPayload("p1", []byte("<doc/>"))
			},
			wantErr: "FromParty is required",
		},
		{
			name: "missing ToParty",
			builder: func() *Builder {
				return NewBuilder().
					WithID("id").
					WithFromParty("scheme", "from").
					AddXMLPayload("p1", []byte("<doc/>"))
			},
			wantErr: "at least one ToParty is required",
		},
		{
			name: "missing payload",
			builder: func() *Builder {
				return NewBuilder().
					WithID("id").
					WithFromParty("scheme", "from").
					WithToParty("scheme", "to")
			},
			wantErr: "at least one payload is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.builder().Build()
			if err == nil {
				t.Fatal("Build() expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Build() error = %q, want to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestXHEMarshalParse(t *testing.T) {
	original, err := NewBuilder().
		WithID("test-123").
		WithFromParty("iso6523-actorid-upis", "0203:sender").
		WithToParty("iso6523-actorid-upis", "0203:recipient").
		WithBusinessScope("DOCUMENTID", "urn:example:doc:1", "").
		AddXMLPayload("payload-1", []byte("<Invoice xmlns=\"urn:example\"><Amount>100.00</Amount></Invoice>")).
		Build()

	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	// Marshal to XML
	data, err := original.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// Verify XML contains expected elements
	xmlStr := string(data)
	if !strings.Contains(xmlStr, "XHEVersionID") {
		t.Error("Marshal() output missing XHEVersionID")
	}
	if !strings.Contains(xmlStr, "0203:sender") {
		t.Error("Marshal() output missing sender party")
	}

	// Parse back
	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if parsed.Header.ID != original.Header.ID {
		t.Errorf("Parsed ID = %q, want %q", parsed.Header.ID, original.Header.ID)
	}
	if parsed.Header.FromParty.PartyID.Value != original.Header.FromParty.PartyID.Value {
		t.Errorf("Parsed FromParty = %q, want %q",
			parsed.Header.FromParty.PartyID.Value, original.Header.FromParty.PartyID.Value)
	}
}

func TestGetFirstToParty(t *testing.T) {
	xhe, _ := NewBuilder().
		WithID("id").
		WithFromParty("scheme", "from").
		WithToParty("scheme", "to1").
		WithToParty("scheme", "to2").
		AddXMLPayload("p", []byte("<doc/>")).
		Build()

	first := xhe.GetFirstToParty()
	if first.PartyID.Value != "to1" {
		t.Errorf("GetFirstToParty() = %q, want %q", first.PartyID.Value, "to1")
	}
}

func TestGetPayloadByID(t *testing.T) {
	xhe, _ := NewBuilder().
		WithID("id").
		WithFromParty("scheme", "from").
		WithToParty("scheme", "to").
		AddXMLPayload("payload-1", []byte("<doc1/>")).
		AddXMLPayload("payload-2", []byte("<doc2/>")).
		Build()

	p1 := xhe.GetPayloadByID("payload-1")
	if p1 == nil {
		t.Fatal("GetPayloadByID(payload-1) returned nil")
	}
	if p1.ID != "payload-1" {
		t.Errorf("GetPayloadByID() ID = %q, want %q", p1.ID, "payload-1")
	}

	pNone := xhe.GetPayloadByID("nonexistent")
	if pNone != nil {
		t.Error("GetPayloadByID(nonexistent) should return nil")
	}
}

func TestMultipleToParties(t *testing.T) {
	xhe, err := NewBuilder().
		WithID("multi-recipient").
		WithFromParty("iso6523-actorid-upis", "0203:sender").
		WithToParty("iso6523-actorid-upis", "0203:recipient1").
		WithToParty("iso6523-actorid-upis", "0203:recipient2").
		WithToParty("iso6523-actorid-upis", "0203:recipient3").
		AddXMLPayload("p", []byte("<doc/>")).
		Build()

	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if len(xhe.Header.ToParty) != 3 {
		t.Errorf("ToParty count = %d, want 3", len(xhe.Header.ToParty))
	}
}
