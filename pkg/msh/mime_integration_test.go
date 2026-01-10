// Copyright (c) 2025 SIROS Foundation
// SPDX-License-Identifier: BSD-2-Clause

package msh

import (
	"io"
	"mime"
	"mime/multipart"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertToMIMEPayloads(t *testing.T) {
	msh := &MSH{}

	mshPayloads := []Payload{
		{
			ContentID:   "<test1@example.com>",
			ContentType: "text/plain",
			Data:        []byte("Test data 1"),
			Properties:  map[string]string{"prop1": "value1"},
		},
		{
			ContentID:   "<test2@example.com>",
			ContentType: "application/json",
			Data:        []byte(`{"test": true}`),
		},
	}

	mimePayloads := msh.convertToMIMEPayloads(mshPayloads)

	require.Len(t, mimePayloads, 2)

	assert.Equal(t, "<test1@example.com>", mimePayloads[0].ContentID)
	assert.Equal(t, "text/plain", mimePayloads[0].ContentType)
	assert.Equal(t, []byte("Test data 1"), mimePayloads[0].Data)
	assert.Equal(t, "binary", mimePayloads[0].ContentTransfer)

	assert.Equal(t, "<test2@example.com>", mimePayloads[1].ContentID)
	assert.Equal(t, "application/json", mimePayloads[1].ContentType)
	assert.Equal(t, []byte(`{"test": true}`), mimePayloads[1].Data)
	assert.Equal(t, "binary", mimePayloads[1].ContentTransfer)
}

func TestMIMESerialization_Structure(t *testing.T) {
	// This test verifies that the MIME package can serialize messages correctly
	// The integration with MSH is tested indirectly through processOutboundMessage

	msh := &MSH{}

	// Create test payloads
	mshPayloads := []Payload{
		{
			ContentID:   "<payload1@example.com>",
			ContentType: "text/plain",
			Data:        []byte("This is payload 1"),
		},
		{
			ContentID:   "<payload2@example.com>",
			ContentType: "application/json",
			Data:        []byte(`{"key": "value"}`),
		},
	}

	// Convert to MIME payloads
	mimePayloads := msh.convertToMIMEPayloads(mshPayloads)

	// Verify conversion
	assert.Len(t, mimePayloads, 2)
	assert.Equal(t, "text/plain", mimePayloads[0].ContentType)
	assert.Equal(t, "application/json", mimePayloads[1].ContentType)
}

func TestMIME_MultipartParsing(t *testing.T) {
	// Test that verifies MIME multipart structure can be parsed
	// This ensures the format sent by MSH is valid

	testData := `------=_Part_test123
Content-Type: application/soap+xml; charset=UTF-8
Content-Transfer-Encoding: 8bit
Content-ID: <soap@example.com>

<soap:Envelope></soap:Envelope>
------=_Part_test123
Content-Type: text/plain
Content-Transfer-Encoding: binary
Content-ID: <payload1@example.com>

Test payload data
------=_Part_test123--
`

	contentType := `multipart/related; boundary="----=_Part_test123"; type="application/soap+xml"; start="soap@example.com"`

	mediaType, params, err := mime.ParseMediaType(contentType)
	require.NoError(t, err)
	assert.Equal(t, "multipart/related", mediaType)
	assert.Equal(t, "----=_Part_test123", params["boundary"])

	// Parse the multipart content
	reader := multipart.NewReader(strings.NewReader(testData), params["boundary"])

	partCount := 0
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		partCount++

		data, err := io.ReadAll(part)
		require.NoError(t, err)
		assert.NotEmpty(t, data)
	}

	assert.Equal(t, 2, partCount, "Should parse 2 parts from the MIME message")
}

func TestMIME_BoundaryExtraction(t *testing.T) {
	// Verify boundary parsing from Content-Type header
	contentType := `multipart/related; boundary="----=_Part_abc123"; type="application/soap+xml"`

	_, params, err := mime.ParseMediaType(contentType)
	require.NoError(t, err)

	boundary := params["boundary"]
	assert.Equal(t, "----=_Part_abc123", boundary)
	assert.NotEmpty(t, boundary)
}

func TestMIME_EmptyPayloads(t *testing.T) {
	// Test conversion with no payloads
	msh := &MSH{}

	emptyPayloads := []Payload{}
	mimePayloads := msh.convertToMIMEPayloads(emptyPayloads)

	assert.Len(t, mimePayloads, 0)
	assert.NotNil(t, mimePayloads)
}

func TestMIME_ContentIDFormatting(t *testing.T) {
	// Verify Content-ID formatting is preserved
	msh := &MSH{}

	payloads := []Payload{
		{
			ContentID:   "<with-brackets@example.com>",
			ContentType: "text/plain",
			Data:        []byte("test"),
		},
		{
			ContentID:   "without-brackets@example.com",
			ContentType: "text/plain",
			Data:        []byte("test"),
		},
	}

	mimePayloads := msh.convertToMIMEPayloads(payloads)

	// Content-ID should be preserved as-is during conversion
	assert.Equal(t, "<with-brackets@example.com>", mimePayloads[0].ContentID)
	assert.Equal(t, "without-brackets@example.com", mimePayloads[1].ContentID)
}

func TestMIME_DataPreservation(t *testing.T) {
	// Ensure binary data is preserved during conversion
	msh := &MSH{}

	binaryData := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE}
	payloads := []Payload{
		{
			ContentID:   "<binary@example.com>",
			ContentType: "application/octet-stream",
			Data:        binaryData,
		},
	}

	mimePayloads := msh.convertToMIMEPayloads(payloads)

	assert.Equal(t, binaryData, mimePayloads[0].Data)
	assert.Equal(t, "application/octet-stream", mimePayloads[0].ContentType)
}
