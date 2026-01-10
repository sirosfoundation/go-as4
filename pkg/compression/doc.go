// Copyright (c) 2024 SIROS Foundation
// SPDX-License-Identifier: BSD-2-Clause

/*
Package compression provides GZIP payload compression for AS4.

This package implements payload compression as specified in the OASIS AS4
Profile, which requires GZIP compression for applicable content types.

# Compression

Compress payloads before sending:

	compressor := compression.NewCompressor()
	compressed, err := compressor.Compress(payload)

Decompress received payloads:

	decompressed, err := compressor.Decompress(compressed)

# Content Type Detection

The package determines which content types should be compressed:

	if compression.ShouldCompress("application/xml") {
	    // Compress XML content
	}

Typically compressed:
  - application/xml
  - application/json
  - text/*

Not compressed (already compressed):
  - application/gzip
  - application/zip
  - image/jpeg, image/png

# References

  - OASIS AS4 Compression: https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/
  - GZIP RFC 1952: https://datatracker.ietf.org/doc/html/rfc1952
*/
package compression
