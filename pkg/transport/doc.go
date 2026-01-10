// Copyright (c) 2024 SIROS Foundation
// SPDX-License-Identifier: BSD-2-Clause

/*
Package transport implements HTTPS transport layer for AS4.

This package provides secure HTTP transport for AS4 messages with
TLS 1.2/1.3 support as specified in the eDelivery AS4 profile.

# TLS Configuration

The package recommends TLS 1.3 with fallback to TLS 1.2:

	config := transport.DefaultHTTPSConfig()
	// MinTLSVersion: TLS 1.2
	// MaxTLSVersion: TLS 1.3

For TLS 1.2, the following cipher suites are recommended:
  - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

# Client Usage

Create and use an HTTPS client:

	client := transport.NewHTTPSClient(&transport.HTTPSConfig{
	    MinTLSVersion: transport.TLS12,
	    Certificates:  []tls.Certificate{clientCert},
	    RootCAs:       certPool,
	})

	response, err := client.Send(ctx, envelope, "https://receiver.example.com/as4")

# Server Usage

Create an HTTPS server:

	server := transport.NewHTTPSServer(&transport.HTTPSConfig{
	    MinTLSVersion: transport.TLS12,
	    ClientAuth:    tls.RequireAndVerifyClientCert,
	    ClientCAs:     clientCAPool,
	})

# Content Types

AS4 messages use specific content types:

	ContentTypeSOAP     = "application/soap+xml"
	ContentTypeMultipart = "multipart/related"

# References

  - eDelivery AS4 Transport: https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/
  - TLS 1.3 RFC 8446: https://datatracker.ietf.org/doc/html/rfc8446
  - TLS 1.2 RFC 5246: https://datatracker.ietf.org/doc/html/rfc5246
*/
package transport
