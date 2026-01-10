// Copyright (c) 2024 SIROS Foundation
// SPDX-License-Identifier: BSD-2-Clause

/*
Package mime handles MIME multipart packaging for AS4.

This package implements SOAP with Attachments (SwA) packaging for AS4
messages with binary payloads.

# MIME Structure

AS4 messages with attachments use multipart/related:

	Content-Type: multipart/related;
	    type="application/soap+xml";
	    start="<soap-envelope>";
	    boundary="----=_Part_..."

	------=_Part_...
	Content-Type: application/soap+xml
	Content-ID: <soap-envelope>

	[SOAP Envelope with encrypted content]

	------=_Part_...
	Content-Type: application/octet-stream
	Content-ID: <payload-1>
	Content-Transfer-Encoding: binary

	[Binary payload data]

# Creating Multipart Messages

Package a SOAP envelope with attachments:

	pkg := mime.NewPackage(envelope)
	pkg.AddAttachment("payload-1", payload, "application/xml")
	multipart, contentType := pkg.Build()

# Parsing Multipart Messages

Parse received multipart messages:

	parts, err := mime.Parse(body, contentType)
	envelope := parts.Envelope()
	attachments := parts.Attachments()

# Content IDs

Attachments are referenced by Content-ID (CID):

	cid:payload-1

The CID scheme allows payloads to be referenced from within the
SOAP envelope.

# References

  - SOAP with Attachments: https://www.w3.org/TR/SOAP-attachments
  - MIME Multipart: https://datatracker.ietf.org/doc/html/rfc2046
*/
package mime
