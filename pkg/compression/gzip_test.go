package compression

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompressor_CompressDecompress(t *testing.T) {
	compressor := NewCompressor()

	// Use sufficiently large data for compression to be effective
	// GZIP has overhead (~18-20 bytes), so small data actually gets larger
	repeated := "This is test data that should be compressed. It contains repeated text. "
	testData := []byte(repeated + repeated + repeated + repeated + repeated)

	// Compress
	compressed, err := compressor.Compress(testData)
	require.NoError(t, err)
	assert.NotEmpty(t, compressed)
	// With sufficient repetition, compressed should be smaller
	assert.Less(t, len(compressed), len(testData))

	// Decompress
	decompressed, err := compressor.Decompress(compressed)
	require.NoError(t, err)
	assert.Equal(t, testData, decompressed)
}

func TestCompressor_EmptyData(t *testing.T) {
	compressor := NewCompressor()

	compressed, err := compressor.Compress([]byte{})
	require.NoError(t, err)
	assert.NotEmpty(t, compressed) // GZIP header is present even for empty data

	decompressed, err := compressor.Decompress(compressed)
	require.NoError(t, err)
	assert.Empty(t, decompressed)
}

func TestCompressor_LargeData(t *testing.T) {
	compressor := NewCompressor()

	// Create 1MB of compressible data (repeated pattern compresses very well)
	largeData := bytes.Repeat([]byte("test data "), 100000)

	compressed, err := compressor.Compress(largeData)
	require.NoError(t, err)
	// With repeated data, compression should be very effective
	assert.Less(t, len(compressed), len(largeData)/10, "Compressed size should be much smaller than original for repeated data")

	decompressed, err := compressor.Decompress(compressed)
	require.NoError(t, err)
	assert.Equal(t, largeData, decompressed)
}

func TestCompressor_ShouldCompress(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		expected    bool
	}{
		{"text plain", "text/plain", true},
		{"text html", "text/html", true},
		{"application xml", "application/xml", true},
		{"application json", "application/json", true},
		{"text xml", "text/xml", true},
		{"jpeg already compressed", "image/jpeg", false},
		{"png already compressed", "image/png", false},
		{"gzip already compressed", "application/gzip", false},
		{"zip already compressed", "application/zip", false},
		{"mp4 video", "video/mp4", false},
		{"with charset", "text/plain; charset=utf-8", true},
		{"empty", "", true}, // Default to compressible
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ShouldCompress(tt.contentType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCompressor_InvalidCompressedData(t *testing.T) {
	compressor := &Compressor{}

	invalidData := []byte("this is not gzip compressed data")

	_, err := compressor.Decompress(invalidData)
	assert.Error(t, err)
}

func TestCompressor_CorruptedData(t *testing.T) {
	compressor := NewCompressor()

	// Create valid compressed data
	originalData := []byte("test data for corruption testing with more content to ensure proper compression")
	compressed, err := compressor.Compress(originalData)
	require.NoError(t, err)

	// Corrupt the GZIP header magic number (first 2 bytes should be 0x1f, 0x8b)
	// This will definitely cause decompression to fail
	corrupted := make([]byte, len(compressed))
	copy(corrupted, compressed)
	corrupted[0] = 0xFF
	corrupted[1] = 0xFF

	// Decompression should fail
	_, err = compressor.Decompress(corrupted)
	assert.Error(t, err, "Decompressing corrupted GZIP header should fail")
}

func TestCompressor_MultipleCompressions(t *testing.T) {
	compressor := NewCompressor()

	testData := []byte("test data for multiple compression cycles")

	// First compression
	compressed1, err := compressor.Compress(testData)
	require.NoError(t, err)

	// Second compression of already compressed data
	compressed2, err := compressor.Compress(compressed1)
	require.NoError(t, err)

	// Double decompression
	temp, err := compressor.Decompress(compressed2)
	require.NoError(t, err)

	final, err := compressor.Decompress(temp)
	require.NoError(t, err)

	assert.Equal(t, testData, final)
}
