# Tessio.Verifier

**The .NET / ASP.NET Core verifier for the EU Digital Identity (EUDI) Wallet.**

[![CI](https://github.com/tripledownab/tessio-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/tripledownab/tessio-verifier/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/Tessio.Verifier.AspNetCore.svg)](https://www.nuget.org/packages/Tessio.Verifier.AspNetCore)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Verify credentials presented by EUDI Wallets directly from your .NET backend, over **OpenID4VP 1.0** with **SD-JWT VC** and **mdoc** credentials. Native to ASP.NET Core and Azure, with a built-in **demo mode** so you can run a full verification flow today, before any production wallet ships.

> Relying-party (verifier) side only. This library never acts as a wallet or an issuer.

> **Status: the full pipeline runs on `main`, and the quickstart below works end to end.** It is [on NuGet](https://www.nuget.org/packages/Tessio.Verifier.AspNetCore). **SD-JWT VC** and **mso_mdoc** credentials (ISO 18013-5/-7 mobile documents, e.g. the mDL) are verified through the same pipeline, over either the OpenID4VP redirect flow or the **W3C Digital Credentials API transport** (ISO/IEC 18013-7 Annex C), and every layer is validated against external artifacts rather than fixtures we wrote ourselves. What changed in each release lives in the [release notes](https://github.com/tripledownab/tessio-verifier/releases), which is the only place it is maintained.

## Why this exists

The EUDI Wallet arrives under Regulation (EU) 2024/1183. Member states must make a wallet available by **24 December 2026**. From **24 December 2027** a relying party that is required to use strong user authentication for online identification must also accept a wallet, and only when the user chooses to present one. Micro and small enterprises are out of scope, and both dates run from the implementing acts that entered into force on 24 December 2024 rather than from the regulation itself.

If you verify those credentials from .NET, this library does the protocol and the cryptography and then proves it against tests written by someone else. It passes the OpenID Foundation conformance suite for OpenID4VP 1.0 HAIP verifiers in both credential formats the wallet uses, and every run is pinned to the source tree it ran against in `conformance-record.json`.

## What you get

- OpenID4VP 1.0 verifier flow, cross-device by QR code and same-device with the redirect back bound to the browser that started it ([how](docs/going-live.md#the-same-device-flow)), **DCQL** queries, JAR-signed requests (RFC 9101) carrying your access certificate chain in `x5c`, checked for the usual mistakes before anything is signed: a root or self-signed signer in the chain, certificates out of order, a first certificate that does not hold the signing key (`SignedPresentationRequestBuilder`; [what is checked](docs/going-live.md#2-sign-your-requests))
- **EU Age Verification profile** requests: unsigned, with the DCQL query in plain parameters and no request object, as that profile specifies (`AvPresentationRequestBuilder`)
- **SD-JWT VC** verification: issuer signature (JWT VC Issuer Metadata and X.509), selective disclosure, key binding (KB-JWT), transaction data
- **mdoc** (`mso_mdoc`) verification: ISO 18013-5/-7 mobile documents like the mDL, validated against the spec's own vectors and an independent implementation
- **W3C Digital Credentials API transport** (ISO/IEC 18013-7 Annex C): build the `{deviceRequest, encryptionInfo}` request pair, open the HPKE-encrypted response (RFC 9180, checked against the RFC's own vectors) and verify device auth over the Annex C session transcript (`Iso18013AnnexC`). The request can be signed with `readerAuth` by your reader certificate (`MdocReaderKey`, construction checked against the ISO 18013-5 Annex D signed request as reproduced in the multipaz test vectors) and carry your registration certificate under `euWrprc`
- **OpenID4VP over the W3C Digital Credentials API** (OpenID4VP 1.0 Appendix A): unsigned and signed requests (`openid4vp-v1-unsigned`, and `openid4vp-v1-signed` carrying `expected_origins`) from `DcApiPresentationRequestBuilder`, the response the browser returns read by `WalletResponseParser.ParseDcApiAsync`, and verification bound to the page's origin by `WalletResponseVerifier.VerifyDcApiAsync`. Every request names the page origins it may be answered from and expires; your host stores the request whole and accepts one answer per request. So far checked against this library's own mock wallet only, not yet against a real one
- Revocation checking: the Token Status List for SD-JWT VC, and for mdoc both MSO revocation mechanisms, the status list and the identifier list, each list trusted only through the credential that references it ([how](docs/going-live.md#adjusting-verification-policy))
- **Demo / Mock / Test / Live** modes so you can build before wallets exist, then serve real ones
- Idiomatic ASP.NET Core integration (DI + minimal APIs) and a runnable sample
- **Self-driving and multi-tenant hosting**: verify wallet callbacks for many tenants in one process, each against its own request (`IWalletResponseVerifier`)
- A pluggable trust seam (`ITrustListResolver`) for production trust lists

## Install

```bash
dotnet add package Tessio.Verifier.AspNetCore
```

Runs on **.NET 8, 9 and 10**. The packages target .NET 8 and .NET 10 (both LTS); apps on .NET 9 use the .NET 8 build.

## Quickstart in 5 minutes (DEMO mode)

```csharp
using Tessio.Verifier.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddTessioVerifier(options =>
{
    options.Mode = VerifierMode.Demo;          // auto-completes locally, no real wallet needed
    options.RequestedClaims = ["age_over_18"]; // selective disclosure: ask only for what you need
});

var app = builder.Build();

app.MapTessioVerifier();   // request-init, wallet-callback and result-stream (SSE) endpoints

app.MapGet("/", () => Results.Content(
    """<a href="/verify/start">Start a verification</a>""", "text/html"));

app.Run();
```

Run it, open the page, start a verification, and DEMO mode returns a verified `age_over_18` claim over Server-Sent Events.

## Modes

- **Demo**: auto-completes in seconds, for showcases and first-run experience.
- **Mock**: a built-in mock wallet posts freshly signed credentials through the full verification pipeline, encrypted responses included. Set `options.CredentialFormat = "mso_mdoc"` to run the mdoc pipeline instead of SD-JWT VC.
- **Test**: replays the RFC 9901 conformance vector (the spec's German PID example) through the real verifier, so you see the verifier agree with the specification's own bytes.
- **Live**: sessions wait for real wallets on the callback endpoint. [docs/going-live.md](docs/going-live.md) covers the setup: signed requests, trust lists, session stores and response encryption.

## Packages

| Package | Purpose |
| --- | --- |
| `Tessio.Verifier.Core` | Credential verification (SD-JWT VC, disclosures, KB-JWT). No web dependencies. |
| `Tessio.Verifier.Core.Mdoc` | mdoc verification (ISO 18013-5/-7: MSO, digests, device auth). |
| `Tessio.Verifier.Core.Mdoc.Zk` | Zero knowledge age proofs for mdoc: Longfellow proofs as the EU age verification profile uses them. Linux x64. Set a `LongfellowProofVerifier` as `MdocVerifierOptions.ZkProofVerifier`, with `CheckStatus` false, to check proofs: a proof cannot be checked for revocation, so a verifier that checks status refuses every one. To ask wallets for one, pass its `SystemIds` in a `ZkRequest` to `Iso18013AnnexC.CreateRequest` or `CreateSignedRequest`. Set the same `ZkRequest` on `MdocVerificationContext` when verifying the answer. |
| `Tessio.Verifier.OpenId4Vp` | OpenID4VP protocol layer (request build, JAR, response parsing, `Dcql` query builders). |
| `Tessio.Verifier.AspNetCore` | DI, endpoints, session management, the multi-tenant verification seam, demo/mock/test modes. |
| `Tessio.Verifier.Trust` | `ITrustListResolver` interface + a basic implementation. |

## Going to production

[docs/going-live.md](docs/going-live.md) walks through the code side: signed requests (Key Vault/HSM included), real trust lists, distributed session stores and response-encryption keys every instance can derive. For self-driving or multi-tenant hosting (your own store, one process serving many tenants), see [docs/self-driving-and-multi-tenant.md](docs/self-driving-and-multi-tenant.md). Beyond the code, a signed request to an EUDI Wallet needs a **wallet-relying party access certificate (WRPAC)**. You register as a relying party in your member state, and a certificate authority that member state has authorised issues the certificate, to registered relying parties only (Implementing Regulation (EU) 2025/848, Article 7). Not every profile signs: the EU Age Verification profile sends unsigned requests, so it needs no access certificate. Whether your signing key must sit in a secure device depends on your certificate provider's terms. This library handles the protocol and credential verification. Registration, certificates and trust lists are yours to arrange; [docs/production.md](docs/production.md) covers them.

## Standards

- OpenID4VP 1.0: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html>
- OpenID4VC High Assurance Interoperability Profile (HAIP) 1.0: <https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html>
- EU Age Verification technical specification: <https://github.com/eu-digital-identity-wallet/av-doc-technical-specification>
- SD-JWT VC: <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-13>. Code citations name draft -13 because HAIP 1.0 lists it as a normative reference. Later drafts renumber the sections, so a section number means nothing without its draft number.
- Token Status List: <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-20>, for SD-JWT VC and mdoc alike. Implementing Regulation (EU) 2026/1731 pins -20 for both (its Annex IV, adaptations (1), (5) and (6)). HAIP 1.0 cites -14.
- mdoc revocation (MSO revocation lists, status list and identifier list): Implementing Regulation (EU) 2024/2979, Annex II as replaced by Implementing Regulation (EU) 2026/1731 (<https://eur-lex.europa.eu/eli/reg_impl/2026/1731/oj>, its Annex IV), adaptation (6): clause 6.2.10.1 of ETSI TS 119 472-1 V1.2.1 as adapted there. That annex pins Token Status List draft -20, which the mdoc code cites.
- EUDI Architecture & Reference Framework: <https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework>
- Relying party registration and access certificates: Implementing Regulation (EU) 2025/848, <https://eur-lex.europa.eu/eli/reg_impl/2025/848/oj>
- WRPAC profile: ETSI TS 119 475. Certificate policy: ETSI TS 119 411-8

## Free validators

When a credential will not verify, the quickest way to find out why is to look at it outside your own
code. These are free, need no account, and cover the formats this library handles:

| Validator | What it answers |
| --- | --- |
| [SD-JWT VC Validator](https://labs.tessio.eu/sd-jwt) | Does each disclosure bind to a signed `_sd` digest? |
| [mdoc / mDL Validator](https://labs.tessio.eu/mdoc) | Is the Mobile Security Object intact, and does the IACA chain hold? |
| [eIDAS Signature Validator](https://labs.tessio.eu/ades) | Is this PAdES, CAdES or JAdES signature valid, and is it qualified? |
| [EU Trusted List Checker](https://labs.tessio.eu/trusted-list) | Is this certificate a qualified CA on an EU trusted list? |
| [EUDI Trusted Entity Checker](https://labs.tessio.eu/lote) | Does the EUDI ecosystem trust this certificate, and in which role? |

The SD-JWT VC validator runs in your browser by default, so nothing you paste leaves the machine
unless you opt into issuer-trust anchoring. The other four check against EU trust data that only a
server can fetch, so they post what you give them to the hosted service. Each tool states which it is
doing. They are built by the maintainers of this library, on the same verification engine, and
nothing here depends on them.

## Repository

- **Source:** <https://github.com/tripledownab/tessio-verifier>
- **Issues:** <https://github.com/tripledownab/tessio-verifier/issues>
- **Releases:** <https://github.com/tripledownab/tessio-verifier/releases>

## License

Apache-2.0
