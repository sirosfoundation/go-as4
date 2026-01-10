// Copyright (c) 2024 SIROS Foundation
// SPDX-License-Identifier: BSD-2-Clause

/*
Package goas4 implements the European Commission's eDelivery AS4 2.0 specification
for secure, reliable business-to-business messaging.

# Overview

go-as4 is a comprehensive Go implementation of the AS4 (Applicability Statement 4)
messaging protocol, which is part of the European Commission's eDelivery Building Block.
It enables secure, reliable exchange of business documents between organizations.

# Specifications Implemented

This library implements the following specifications:

  - eDelivery AS4 2.0: https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/845480153/eDelivery+AS4+-+2.0
  - OASIS AS4 Profile of ebMS 3.0 Version 1.0: https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/
  - OASIS ebXML Messaging Services v3.0: https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/core/os/
  - WS-Security 1.1.1: https://docs.oasis-open.org/wss/v1.1/
  - XML Signature Syntax and Processing: https://www.w3.org/TR/xmldsig-core1/
  - XML Encryption Syntax and Processing: https://www.w3.org/TR/xmlenc-core1/

# Package Structure

The library is organized into the following packages:

	github.com/sirosfoundation/go-as4/pkg/as4        - Main AS4 client API
	github.com/sirosfoundation/go-as4/pkg/message   - AS4 message structures and builders
	github.com/sirosfoundation/go-as4/pkg/security  - WS-Security, signing, and encryption
	github.com/sirosfoundation/go-as4/pkg/transport - HTTPS transport with TLS 1.2/1.3
	github.com/sirosfoundation/go-as4/pkg/pmode     - Processing Mode configuration
	github.com/sirosfoundation/go-as4/pkg/reliability - Reception awareness and duplicate detection
	github.com/sirosfoundation/go-as4/pkg/compression - GZIP payload compression
	github.com/sirosfoundation/go-as4/pkg/mep       - Message Exchange Patterns
	github.com/sirosfoundation/go-as4/pkg/msh       - Message Service Handler
	github.com/sirosfoundation/go-as4/pkg/mime      - MIME multipart handling

# Quick Start

To send an AS4 message:

	import (
	    "github.com/sirosfoundation/go-as4/pkg/as4"
	    "github.com/sirosfoundation/go-as4/pkg/message"
	    "github.com/sirosfoundation/go-as4/pkg/security"
	)

	// Create message
	builder := message.NewUserMessage(
	    message.WithFrom("sender-id", "urn:oasis:names:tc:ebcore:partyid-type:unregistered"),
	    message.WithTo("receiver-id", "urn:oasis:names:tc:ebcore:partyid-type:unregistered"),
	    message.WithService("http://example.com/service"),
	    message.WithAction("processOrder"),
	)
	msg := builder.Build()

	// Configure security
	secConfig := security.NewSecurityConfig(
	    security.WithSigningKey(privateKey),
	    security.WithSigningCert(cert),
	)

	// Create client and send
	client, _ := as4.NewClient(&as4.ClientConfig{
	    SecurityConfig: secConfig,
	})
	receipt, err := client.SendMessage(ctx, msg, payloads, "https://receiver.example.com/as4")

# Security Features

The library provides comprehensive security features:

## Digital Signatures

  - RSA-SHA256: Interoperable with existing AS4 implementations (phase4, Domibus)
  - Ed25519: Modern signature algorithm (AS4 2.0)
  - Canonicalization: Exclusive XML Canonicalization with InclusiveNamespaces

## Encryption

  - AES-128-GCM: Data encryption
  - RSA-OAEP: Key transport (interoperable)
  - X25519: Key exchange (AS4 2.0)

## Certificate References

The library supports multiple WS-Security token reference methods:

  - X509IssuerSerial: Universal compatibility
  - SubjectKeyIdentifier: For X.509v3 certificates with SKI extension
  - BinarySecurityToken: Embeds full certificate
  - ThumbprintSHA1: Certificate fingerprint reference

# Interoperability

This library is tested for interoperability with:

  - phase4 (https://github.com/phax/phase4)
  - Domibus (https://ec.europa.eu/digital-building-blocks/wikis/display/DIGITAL/Domibus)
  - Holodeck B2B

# References

  - eDelivery: https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/
  - OASIS ebMS TC: https://www.oasis-open.org/committees/ebxml-msg/
  - WS-Security: https://www.oasis-open.org/committees/wss/

# License

BSD-2-Clause License
*/
package goas4
