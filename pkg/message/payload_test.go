package message

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractPayloadMetadata(t *testing.T) {
	tests := []struct {
		name     string
		userMsg  *UserMessage
		wantLen  int
		wantKeys []string
	}{
		{
			name:    "nil user message",
			userMsg: nil,
			wantLen: 0,
		},
		{
			name:    "nil payload info",
			userMsg: &UserMessage{PayloadInfo: nil},
			wantLen: 0,
		},
		{
			name: "single part info with properties",
			userMsg: &UserMessage{
				PayloadInfo: &PayloadInfo{
					PartInfo: []PartInfo{
						{
							Href: "cid:attachment@example.com",
							PartProperties: &PartProperties{
								Property: []Property{
									{Name: "MimeType", Value: "application/xml"},
									{Name: "CompressionType", Value: "application/gzip"},
									{Name: "CharacterSet", Value: "UTF-8"},
									{Name: "CustomProp", Value: "custom-value"},
								},
							},
						},
					},
				},
			},
			wantLen:  1,
			wantKeys: []string{"attachment@example.com"},
		},
		{
			name: "multiple part infos",
			userMsg: &UserMessage{
				PayloadInfo: &PayloadInfo{
					PartInfo: []PartInfo{
						{Href: "cid:part1@example.com"},
						{Href: "cid:part2@example.com"},
						{Href: "part3@example.com"}, // without cid: prefix
					},
				},
			},
			wantLen:  3,
			wantKeys: []string{"part1@example.com", "part2@example.com", "part3@example.com"},
		},
		{
			name: "part info without properties",
			userMsg: &UserMessage{
				PayloadInfo: &PayloadInfo{
					PartInfo: []PartInfo{
						{Href: "cid:simple@example.com"},
					},
				},
			},
			wantLen:  1,
			wantKeys: []string{"simple@example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractPayloadMetadata(tt.userMsg)
			assert.Len(t, result, tt.wantLen)
			for _, key := range tt.wantKeys {
				_, exists := result[key]
				assert.True(t, exists, "expected key %s to exist", key)
			}
		})
	}
}

func TestExtractPayloadMetadata_PropertyExtraction(t *testing.T) {
	userMsg := &UserMessage{
		PayloadInfo: &PayloadInfo{
			PartInfo: []PartInfo{
				{
					Href: "cid:test@example.com",
					PartProperties: &PartProperties{
						Property: []Property{
							{Name: "MimeType", Value: "text/xml"},
							{Name: "CompressionType", Value: "gzip"},
							{Name: "CharacterSet", Value: "ISO-8859-1"},
						},
					},
				},
			},
		},
	}

	result := ExtractPayloadMetadata(userMsg)
	meta := result["test@example.com"]

	assert.Equal(t, "cid:test@example.com", meta.Href)
	assert.Equal(t, "test@example.com", meta.ContentID)
	assert.Equal(t, "text/xml", meta.MimeType)
	assert.Equal(t, "gzip", meta.CompressionType)
	assert.Equal(t, "ISO-8859-1", meta.CharacterSet)
	assert.Equal(t, "text/xml", meta.Properties["MimeType"])
}

func TestNormalizeContentID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"cid:test@example.com", "test@example.com"},
		{"<test@example.com>", "test@example.com"},
		{"cid:<test@example.com>", "test@example.com"},
		{"test@example.com", "test@example.com"},
		{"<cid:test@example.com>", "cid:test@example.com"}, // cid: inside brackets not stripped
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizeContentID(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchContentID(t *testing.T) {
	tests := []struct {
		id1      string
		id2      string
		expected bool
	}{
		{"cid:test@example.com", "test@example.com", true},
		{"<test@example.com>", "cid:test@example.com", true},
		{"test@example.com", "test@example.com", true},
		{"test@example.com", "other@example.com", false},
		{"cid:a@b.com", "cid:c@d.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.id1+"_vs_"+tt.id2, func(t *testing.T) {
			result := MatchContentID(tt.id1, tt.id2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetPartInfoByContentID(t *testing.T) {
	userMsg := &UserMessage{
		PayloadInfo: &PayloadInfo{
			PartInfo: []PartInfo{
				{Href: "cid:part1@example.com"},
				{Href: "cid:part2@example.com"},
				{Href: "cid:part3@example.com"},
			},
		},
	}

	tests := []struct {
		name      string
		msg       *UserMessage
		contentID string
		wantNil   bool
		wantHref  string
	}{
		{"find existing part", userMsg, "part2@example.com", false, "cid:part2@example.com"},
		{"find with cid prefix", userMsg, "cid:part1@example.com", false, "cid:part1@example.com"},
		{"find with brackets", userMsg, "<part3@example.com>", false, "cid:part3@example.com"},
		{"not found", userMsg, "nonexistent@example.com", true, ""},
		{"nil message", nil, "test", true, ""},
		{"nil payload info", &UserMessage{PayloadInfo: nil}, "test", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetPartInfoByContentID(tt.msg, tt.contentID)
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, tt.wantHref, result.Href)
			}
		})
	}
}

func TestGetPropertyValue(t *testing.T) {
	partInfo := &PartInfo{
		Href: "cid:test@example.com",
		PartProperties: &PartProperties{
			Property: []Property{
				{Name: "MimeType", Value: "application/xml"},
				{Name: "Custom", Value: "custom-value"},
			},
		},
	}

	tests := []struct {
		name     string
		partInfo *PartInfo
		propName string
		expected string
	}{
		{"existing property", partInfo, "MimeType", "application/xml"},
		{"custom property", partInfo, "Custom", "custom-value"},
		{"non-existing property", partInfo, "NonExistent", ""},
		{"nil partInfo", nil, "MimeType", ""},
		{"nil partProperties", &PartInfo{Href: "test"}, "MimeType", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetPropertyValue(tt.partInfo, tt.propName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewPartInfo(t *testing.T) {
	tests := []struct {
		name         string
		contentID    string
		expectedHref string
	}{
		{"without cid prefix", "test@example.com", "cid:test@example.com"},
		{"with cid prefix", "cid:test@example.com", "cid:test@example.com"},
		{"with brackets", "<test@example.com>", "cid:test@example.com"},
		{"with cid and brackets", "cid:<test@example.com>", "cid:<test@example.com>"}, // already has cid: prefix
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewPartInfo(tt.contentID)
			assert.Equal(t, tt.expectedHref, result.Href)
		})
	}
}

func TestPartInfo_AddPartProperty(t *testing.T) {
	partInfo := NewPartInfo("test@example.com")

	// Initially nil
	assert.Nil(t, partInfo.PartProperties)

	// Add first property
	partInfo.AddPartProperty("Name1", "Value1")
	assert.NotNil(t, partInfo.PartProperties)
	assert.Len(t, partInfo.PartProperties.Property, 1)

	// Add second property
	partInfo.AddPartProperty("Name2", "Value2")
	assert.Len(t, partInfo.PartProperties.Property, 2)

	assert.Equal(t, "Name1", partInfo.PartProperties.Property[0].Name)
	assert.Equal(t, "Value1", partInfo.PartProperties.Property[0].Value)
	assert.Equal(t, "Name2", partInfo.PartProperties.Property[1].Name)
	assert.Equal(t, "Value2", partInfo.PartProperties.Property[1].Value)
}

func TestPartInfo_SetMimeType(t *testing.T) {
	partInfo := NewPartInfo("test@example.com")
	partInfo.SetMimeType("application/json")

	assert.NotNil(t, partInfo.PartProperties)
	assert.Len(t, partInfo.PartProperties.Property, 1)
	assert.Equal(t, "MimeType", partInfo.PartProperties.Property[0].Name)
	assert.Equal(t, "application/json", partInfo.PartProperties.Property[0].Value)
}

func TestPartInfo_SetCompressionType(t *testing.T) {
	partInfo := NewPartInfo("test@example.com")
	partInfo.SetCompressionType("application/gzip")

	assert.NotNil(t, partInfo.PartProperties)
	assert.Len(t, partInfo.PartProperties.Property, 1)
	assert.Equal(t, "CompressionType", partInfo.PartProperties.Property[0].Name)
	assert.Equal(t, "application/gzip", partInfo.PartProperties.Property[0].Value)
}

func TestPartInfo_SetCharacterSet(t *testing.T) {
	partInfo := NewPartInfo("test@example.com")
	partInfo.SetCharacterSet("UTF-8")

	assert.NotNil(t, partInfo.PartProperties)
	assert.Len(t, partInfo.PartProperties.Property, 1)
	assert.Equal(t, "CharacterSet", partInfo.PartProperties.Property[0].Name)
	assert.Equal(t, "UTF-8", partInfo.PartProperties.Property[0].Value)
}

func TestPartInfo_CombinedProperties(t *testing.T) {
	partInfo := NewPartInfo("test@example.com")
	partInfo.SetMimeType("application/xml")
	partInfo.SetCompressionType("gzip")
	partInfo.SetCharacterSet("UTF-8")
	partInfo.AddPartProperty("CustomProp", "CustomValue")

	assert.Len(t, partInfo.PartProperties.Property, 4)

	// Verify values
	assert.Equal(t, "application/xml", GetPropertyValue(&partInfo, "MimeType"))
	assert.Equal(t, "gzip", GetPropertyValue(&partInfo, "CompressionType"))
	assert.Equal(t, "UTF-8", GetPropertyValue(&partInfo, "CharacterSet"))
	assert.Equal(t, "CustomValue", GetPropertyValue(&partInfo, "CustomProp"))
}
