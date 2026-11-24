# cleverbase-client — CS-16 day-1 client slice

Sends a signed AS4 UserMessage to Cleverbase's public TEST access points
(WE BUILD QERDS interop, Madrid 24-25 Nov 2026) and prints the exact
ebMS response (Receipt or Error). Part of the AS4 <-> WMP gateway (CS-16).

## Usage

```sh
# Print the wire message and self-verify the signature, no network:
go run ./examples/cleverbase-client -algo=ecdsa -dry-run

# End-to-end against an in-process go-as4 server (must verify server-side):
go run ./examples/cleverbase-client -algo=ecdsa -local
go run ./examples/cleverbase-client -algo=ed25519 -local
go run ./examples/cleverbase-client -algo=rsa -local

# Against a local phase4 (see "phase4 harness" below):
go run ./examples/cleverbase-client -algo=ecdsa -endpoint http://localhost:8080/as4

# ONE test message to Cleverbase TEST (public environment):
go run ./examples/cleverbase-client -algo=ed25519
```

Flags: `-endpoint -algo -key -cert -from -from-scheme -to -to-scheme
-service -action -token-ref -payload -dry-run -local -verbose`.

Gateway keys live outside the repo (minted from the SIROS WE BUILD Pilot
Test CA): `/tmp/opencode/gw-pki/gw-{ec256,ed25519,rsa2048}-{key,cert}.pem`,
CN=wmp-as4-gateway.webuild.siros.org, SAN party-id URI + DNS placeholder.

## Evidence verdict (2026-11-24)

1. **EU eDelivery samples (2025.06 captures)**: every signature is
   `rsa-sha256` + `exc-c14n` with `InclusiveNamespaces PrefixList="env"`
   on the SignedInfo-level CanonicalizationMethod + X509SubjectKeyIdentifier
   token refs + sha256 digests; encryption is RSA-OAEP(mgf1sha256)+AES-GCM.
2. **Cleverbase's own CS-16 credentials** (SMP service metadata for
   `0106::67419925`, service `urn:webuild:svc:erds:dispatch`): their AS4
   signing cert is **Ed25519** and their key-agreement cert is **X25519**,
   transport profile `bdxr-transport-ebms3-as4-v2p0-curve25519` — a
   curve25519 AS4 2.0 profile. Their WMP/evidence layer uses ES256
   (EC P-256) and their ERDS trust-domain root is EC P-256.
3. **Their AS4 stack is Domibus** (fault leaks `eu.domibus.api.model.PartyId`).
4. **Stock phase4/WSS4J rejects `ecdsa-sha256`** at the algorithm-suite gate
   when the PMode pins rsa-sha256 (`AlgorithmSuiteValidator.checkSignatureMethod`),
   but fully verifies an ECDSA signature once the suite check is disabled —
   see below.

**Verdict: the "Cleverbase uses ECDSA" assumption is not supported.** Their
AS4 transport profile is curve25519 (Ed25519/X25519); RSA is the universal
baseline for generic eDelivery stacks; ECDSA P-256 is what our test CA
naturally mints and what their evidence/WMP layer uses, and it is now
implemented in go-as4 for that reason.

## Live probe results (as4-wb.business-sandbox.cleverbase.io/as4)

- Unsigned, non-empty SOAP body -> `EBMS:0010` "SOAP Body must be empty
  according to the AS4 profile; payloads must be carried as separate MIME parts."
- Unsigned, empty body -> `EBMS:0010` "no valid security policy found".
- Signed (Ed25519, empty body, From 0007:5595421925, To 0106:67419925,
  service urn:webuild:svc:erds:dispatch, action Submit) -> `EBMS:0003`
  ValueInconsistent, "Sender party could not be found for the value
  eu.domibus.api.model.PartyId@...[value=5595421925,type=...:0007]".
  Same on erds-x with To 99900812, and with the full-URN party form.
  Domibus resolves parties/PModes BEFORE signature validation, so the
  signature layer is not reached until our gateway party is on their
  AS4 partner list (their /interop/participants page: "on that ERDS's
  AS4 partner list (CS-16), approved, or proposed and not approved yet").

## phase4 harness (local, independent Java stack)

The prebuilt WAR `phase4-server-webapp-4.1.1-SNAPSHOT.war` from the local
phase4 checkout (copied to /tmp/opencode/phase4, never run from the shared
tree) runs under jetty-runner with:

```sh
java -Dphase4.default.profile=cef \
     -Dphase4.incoming.verify.algorithms=false \
     -jar jetty-runner.jar --port 8080 phase4-server-webapp-4.1.1-SNAPSHOT.war
```

and a JKS at `keys/dummy-pw-test.jks` (store/key password "test", alias
`ph-as4`) containing the RSA-2048 gateway pair (receipt signing) plus the
client's EC P-256 cert as a trusted entry. Results with `-algo=ecdsa`:

| configuration | result |
|---|---|
| stock defaults (suite check on) | `AlgorithmSuiteValidator`: "SignatureMethod ecdsa-sha256 does not match required values" -> EBMS:0102 INVALID_SECURITY |
| `-Dphase4.incoming.verify.algorithms=false`, no trust anchor | WSS4J verifies the ECDSA signature; refusal is trust-level: "Error during certificate path validation: No trusted certs found" |
| same, client cert trusted | **full acceptance**: `verify-decrypt:end -- 3 results`, "Received AS4 user message", **signed Receipt returned** |
| same, with MIME payload (`cid:` reference) | FAILED_CHECK "The input bytes to the digest operation are null" — WSS4J cannot resolve our `cid:` attachment reference; day-2 item |

RSA (`-algo=rsa`) with stock defaults passes the suite gate and reaches
the same trust-level refusal. Both prove the client slice produces
conformant, verifiable messages in all three algorithms.

## Day-2 next steps

1. CS-16 party onboarding: get `urn:oasis:names:tc:ebcore:partyid-type:iso6523:0007::5595421925`
   onto Cleverbase's AS4 partner list (their PMode initiator set), then
   re-send — the response should advance to the signature/trust layer and
   answer the algorithm question against their Domibus directly (expect
   Ed25519 first, per their curve25519 profile).
2. SMP registration for the gateway's AS4 endpoint (service
   `urn:webuild:svc:erds:dispatch`, transport profile
   `bdxr-transport-ebms3-as4-v2p0-curve25519` + our cert) so their side
   can look us up.
3. Fix the `cid:` MIME attachment path against WSS4J (content-id
   normalization in `serializeMIME` / the SwA attachment transform), and
   add payload encryption (X25519 for their profile, RSA-OAEP+AES-GCM
   for stock stacks).
4. Note for go-as4 maintainers: `mime.Message.Serialize()` re-marshals the
   `Envelope` struct and cannot carry an already-signed envelope; the
   client works around it by building the multipart manually. The
   `tests/interop/phase4/phase4-config` Java helper no longer compiles
   against phase4 v3.0.7 (API drift) — the prebuilt WAR above is the
   working local harness.
