// Package compression implements GZIP payload compression per AS4 specification
package compression

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
)

const (
	// CompressionTypeGzip is the standard GZIP compression
	CompressionTypeGzip = "application/gzip"
)

// Compressor handles payload compression
type Compressor struct {
	compressionLevel int
}

// NewCompressor creates a new compressor with default compression level
func NewCompressor() *Compressor {
	return &Compressor{
		compressionLevel: gzip.DefaultCompression,
	}
}

// NewCompressorWithLevel creates a new compressor with specified compression level
func NewCompressorWithLevel(level int) *Compressor {
	return &Compressor{
		compressionLevel: level,
	}
}

// Compress compresses data using GZIP
func (c *Compressor) Compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer

	writer, err := gzip.NewWriterLevel(&buf, c.compressionLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip writer: %w", err)
	}

	if _, err := writer.Write(data); err != nil {
		writer.Close()
		return nil, fmt.Errorf("failed to write data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	return buf.Bytes(), nil
}

// Decompress decompresses GZIP data
func (c *Compressor) Decompress(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer reader.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		return nil, fmt.Errorf("failed to read compressed data: %w", err)
	}

	return buf.Bytes(), nil
}

// ShouldCompress determines if payload should be compressed based on content type
func ShouldCompress(contentType string) bool {
	// Don't compress already compressed formats
	compressedTypes := map[string]bool{
		"application/gzip":   true,
		"application/zip":    true,
		"application/x-gzip": true,
		"image/jpeg":         true,
		"image/png":          true,
		"video/mp4":          true,
		"audio/mp3":          true,
	}

	return !compressedTypes[contentType]
}
