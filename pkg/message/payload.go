// Package message provides AS4 message helper functions for payload handling.
package message

import (
	"strings"
)

// PayloadMetadata contains metadata extracted from PartInfo for a payload
type PayloadMetadata struct {
	// Href is the Content-ID reference (e.g., "cid:attachment@example.com")
	Href string
	// ContentID is the href without the "cid:" prefix
	ContentID string
	// MimeType is the original MIME type from PartProperties
	MimeType string
	// CompressionType indicates compression (e.g., "application/gzip")
	CompressionType string
	// CharacterSet is the character encoding
	CharacterSet string
	// Properties contains all PartProperties as a map
	Properties map[string]string
}

// ExtractPayloadMetadata extracts metadata from UserMessage PayloadInfo.
// Returns a map from Content-ID (without cid: prefix) to PayloadMetadata.
func ExtractPayloadMetadata(userMsg *UserMessage) map[string]*PayloadMetadata {
	result := make(map[string]*PayloadMetadata)

	if userMsg == nil || userMsg.PayloadInfo == nil {
		return result
	}

	for _, partInfo := range userMsg.PayloadInfo.PartInfo {
		meta := &PayloadMetadata{
			Href:       partInfo.Href,
			Properties: make(map[string]string),
		}

		// Extract Content-ID from href (remove "cid:" prefix)
		contentID := partInfo.Href
		if strings.HasPrefix(contentID, "cid:") {
			contentID = strings.TrimPrefix(contentID, "cid:")
		}
		meta.ContentID = contentID

		// Extract properties
		if partInfo.PartProperties != nil {
			for _, prop := range partInfo.PartProperties.Property {
				meta.Properties[prop.Name] = prop.Value

				// Extract well-known properties
				switch prop.Name {
				case "MimeType":
					meta.MimeType = prop.Value
				case "CompressionType":
					meta.CompressionType = prop.Value
				case "CharacterSet":
					meta.CharacterSet = prop.Value
				}
			}
		}

		// Store with normalized Content-ID (without angle brackets or cid:)
		normalizedID := NormalizeContentID(contentID)
		result[normalizedID] = meta
	}

	return result
}

// NormalizeContentID normalizes a Content-ID by removing angle brackets and cid: prefix
func NormalizeContentID(contentID string) string {
	// Remove cid: prefix
	contentID = strings.TrimPrefix(contentID, "cid:")
	// Remove angle brackets
	contentID = strings.TrimPrefix(contentID, "<")
	contentID = strings.TrimSuffix(contentID, ">")
	return contentID
}

// MatchContentID checks if two Content-IDs match, ignoring formatting differences
func MatchContentID(id1, id2 string) bool {
	return NormalizeContentID(id1) == NormalizeContentID(id2)
}

// GetPartInfoByContentID finds PartInfo by Content-ID
func GetPartInfoByContentID(userMsg *UserMessage, contentID string) *PartInfo {
	if userMsg == nil || userMsg.PayloadInfo == nil {
		return nil
	}

	normalizedID := NormalizeContentID(contentID)

	for i := range userMsg.PayloadInfo.PartInfo {
		partInfo := &userMsg.PayloadInfo.PartInfo[i]
		partID := NormalizeContentID(partInfo.Href)
		if partID == normalizedID {
			return partInfo
		}
	}

	return nil
}

// GetPropertyValue gets a property value from PartInfo by name
func GetPropertyValue(partInfo *PartInfo, name string) string {
	if partInfo == nil || partInfo.PartProperties == nil {
		return ""
	}

	for _, prop := range partInfo.PartProperties.Property {
		if prop.Name == name {
			return prop.Value
		}
	}

	return ""
}

// NewPartInfo creates a new PartInfo with the given Content-ID
func NewPartInfo(contentID string) PartInfo {
	// Ensure cid: prefix
	href := contentID
	if !strings.HasPrefix(href, "cid:") {
		href = "cid:" + NormalizeContentID(contentID)
	}

	return PartInfo{
		Href: href,
	}
}

// AddPartProperty adds a property to PartInfo
func (p *PartInfo) AddPartProperty(name, value string) {
	if p.PartProperties == nil {
		p.PartProperties = &PartProperties{
			Property: make([]Property, 0),
		}
	}
	p.PartProperties.Property = append(p.PartProperties.Property, Property{
		Name:  name,
		Value: value,
	})
}

// SetMimeType sets the MimeType property
func (p *PartInfo) SetMimeType(mimeType string) {
	p.AddPartProperty("MimeType", mimeType)
}

// SetCompressionType sets the CompressionType property
func (p *PartInfo) SetCompressionType(compressionType string) {
	p.AddPartProperty("CompressionType", compressionType)
}

// SetCharacterSet sets the CharacterSet property
func (p *PartInfo) SetCharacterSet(charset string) {
	p.AddPartProperty("CharacterSet", charset)
}
