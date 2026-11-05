# Going live

How to take a Tessio.Verifier app from the built-in Demo, Mock and Test modes to real wallets.

The built-in modes exist so you can build and test without a wallet. Going live means four things change: the mode, the request signature, the trust list and the session store. Each is a service you register before `AddTessioVerifier`, which uses `TryAdd` for everything and therefore keeps whatever you registered first. Response encryption (§6) needs no change for a single instance and one deliberate design choice when you scale out.

```csharp
builder.Services.AddSingleton<IPresentationRequestBuilder>(...);   // 2. signed requests
builder.Services.AddSingleton<ITrustListResolver>(...);            // 3. real trust list
builder.Services.AddSingleton<ISessionStore>(...);                 // 4. shared sessions (multi-instance)
builder.Services.AddSingleton(new ResponseEncryptionKeyProvider(...)); // 5. shared decryption key (multi-instance)

builder.Services.AddTessioVerifier(options =>
{
    options.Mode = VerifierMode.Live;                              // 1. no built-in actor completes sessions
    options.ClientId = "x509_san_dns:verifier.example.com";
    options.ExpectedVct = "urn:eudi:pid:1";
    options.RequestedClaims = ["age_over_18"];
});
```

A single-instance deployment only needs steps 1 to 3. Steps 4 and 5 matter once you scale past one process.

### Accepting more than one credential type

`options.ExpectedVct` asks for exactly one type. To accept several, pass a list to `Dcql.SdJwtVc` and drive the session yourself (see [self-driving-and-multi-tenant.md](self-driving-and-multi-tenant.md)):

```csharp
var options = new PresentationRequestOptions
{
    ClientId = "x509_san_dns:verifier.example.com",
    Nonce = /* per request, cryptographically random */,
    DcqlQueryJson = Dcql.SdJwtVc(["urn:eudi:pid:1", "urn:eudi:pid:de:1"], "age_over_18"),
    ResponseUri = new Uri("https://verifier.example.com/verify/callback"),
};
```

OpenID4VP 1.0 §B.3.5 defines `vct_values` as "a non-empty array of strings that specifies allowed values for the type of the requested Verifiable Credential". The verifier reads that whole array back out of the session's own request and accepts a credential whose `vct` is any member, per §8.6: "validate that the returned Credential(s) meet all criteria defined in the query".

Matching is exact, so list every type you accept. A credential that only *inherits* from a listed type is refused, because following SD-JWT VC type inheritance needs Type Metadata that this verifier does not retrieve.

**The single-claim form above names a claim the PID rulebook does not define, and that is deliberate
as an illustration but wrong as a starting point.** The EU PID Rulebook removed its age verification
attributes at version 1.1, 4 September 2025, "following CIR 2024/2977", and **read at version 1.7 of
17 July 2026 it still defines none**, so a conformant `urn:eudi:pid:1` carries no top-level
`age_over_18`. Both the version read and the version that changed are given because a rulebook this
young moves: v1.6 of 1 July 2026 is itself "Aligning with updated CIR 2024/2977", so confirm the
attribute list against the current document rather than against this sentence. Its §4.2 does let a
domestic type add claims, so
`urn:eudi:pid:de:1` may carry one, and whether it does is a question about that type rather than
about this API.

That matters more than a wrong attribute name, because of what happens next. §6.4.1: "If `claims` is
present, but `claim_sets` is absent, the Verifier requests all claims listed in `claims`", and the
wallet "MUST NOT return any claims" when it can satisfy none of them. So a single unsatisfiable claim
does not degrade to a partial answer. It returns nothing, which reads on the wallet as a missing
credential and on the verifier as a holder who declined.

Ask for the alternatives and say which you prefer, as the next section does.

### When those types put the same fact in different places

Listing several types is only half the problem. Two credential types can carry the same fact under
different claim names, or at different depths, and a query that names one claim finds nothing in the
other.

The base PID type carries a date of birth as `birthdate` and no age boolean at all: its rulebook removed
the age verification attributes in version 1.1, following CIR 2024/2977. A domestic type may still carry
one, and may express it as thresholds nested inside a single object rather than as separate top-level
booleans. Note the direction before assuming a national type invented its own shape: the age
attributes were in the base rulebook and were taken OUT of it, so a domestic type carrying one may
simply have kept it. Germany is the case this was written against; whether other member states did the
same is not something this page has checked.

So a query that accepts both types has to ask for both shapes and say which answer it prefers.
`Dcql.SdJwtVcByPath` addresses each claim by path, and `claim_sets` orders the alternatives:

```csharp
DcqlQueryJson = Dcql.SdJwtVcByPath(
    ["urn:eudi:pid:1", "urn:eudi:pid:de:1"],
    [
        new DcqlClaim { Id = "age18", Path = ["age_over_18"] },
        new DcqlClaim { Id = "age18nested", Path = ["age_equal_or_over", "18"] },
        new DcqlClaim { Id = "dob", Path = ["birthdate"] },
    ],
    ["age18"],        // a top-level boolean, if the credential has one
    ["age18nested"],  // the same answer nested, if it has that instead
    ["dob"]),         // and only failing both, the date of birth
```

**The order is the privacy decision, and the specification asks for it by name.** §6.4.1: "Verifiers
SHOULD use the principle of least information disclosure to influence how they order these options. For
example, a proof of age request should prioritize requesting an attribute like `age_over_18` over an
attribute like `birth_date`." The same section says the wallet SHOULD return the first option it can
satisfy and MUST NOT return any claims if it can satisfy none. Put `dob` first and every holder hands
over a full date of birth when a boolean would have done.

**Omitting the claim sets is not the milder choice, it is the harsher one.** §6.4.1: "If `claims` is
present, but `claim_sets` is absent, the Verifier requests all claims listed in `claims`", and "if the
Wallet cannot deliver all claims requested by the Verifier according to these rules, it MUST NOT return
the respective Credential". For the query above that means a holder lacking any one of the three
returns nothing at all, rather than disclosing more than you wanted.

**One set holding several ids is a combination, not a list of alternatives.** `["age18"], ["dob"]` is
two options in preference order. `["age18", "dob"]` is a single option demanding both, and a holder who
cannot produce both satisfies nothing. The two read alike and mean opposite things.

`Dcql.MdocByPath` is the same builder for mdoc. Every path there is the full `[namespace, element]` of
§7.2, and exactly two segments: §7.2.1 has the wallet "abort processing and return an error" for
anything else, so the builder refuses it rather than emitting a query no wallet may answer. A claim may
also carry `IntentToRetain`, which §B.2.4 scopes to mdoc, so setting it on an SD-JWT VC claim is
refused.

The builder refuses these at build time, because each fails the same silent way when it reaches a
wallet: the JSON serialises perfectly and the answer comes back with no claims, which reads as the
holder having nothing to offer. An id outside §6.3's alphanumeric, underscore and hyphen set; two
claims sharing an id; a set naming a claim that is absent; and a claim
that no set names, which §6.4.1 means would never be requested at all.

### Asking only for credentials from issuers you trust

A wallet holding several credentials of the requested type cannot tell which issuers you accept. `Dcql.WithTrustedAuthorities` adds a Trusted Authorities Query of type `aki` to every credential in a query, built from the certificates your trust list names for those issuers:

```csharp
DcqlQueryJson = Dcql.WithTrustedAuthorities(
    Dcql.Mdoc("eu.europa.ec.eudi.pid.1", "eu.europa.ec.eudi.pid.1", "age_over_18"),
    trustedIssuerCertificates),
```

OpenID4VP 1.0 §6.1.1.1 has the wallet match each value against the Authority Key Identifier of a certificate in the credential's chain, so each certificate contributes the value that chain carries:
- **A CA certificate**, such as an IACA, contributes its Subject Key Identifier. RFC 5280 §4.2.1.2 makes that, in conforming CA certificates, the Authority Key Identifier of everything the CA issues. CA status is read from BasicConstraints, which §4.2.1.9 requires in every CA certificate.
- **Any other certificate**, such as a Document Signer a list names directly, contributes its own Authority Key Identifier.

HAIP 1.0 §5 says this query "MUST be supported". A certificate is refused when it lacks the identifier its role contributes, carries an empty one, or repeats an extension. A query whose credentials already name trusted authorities is refused too, because adding to an entry would widen it.

What to pass, because a wrong set makes the wallet offer nothing:
- **The certificates your trust list names**, whether CA or signing certificates. Lists name both: an IACA for one issuer, a Document Signer for another.
- **Not the ones it refuses, nor issuers trusted through metadata** rather than a chain. Ask for their credentials in a query without trusted authorities. A certificate with no key identifier names no authority a wallet could match.
- **Rebuild it when your trust list changes.** The query is fixed when you build it.

It is a filter for the wallet, and it can be wider than your trust list. A signing certificate's value names the CA that issued it, so the wallet may offer any credential signed under that CA. It does not replace your trust check. §6.1 says the wallet SHOULD return only credentials that match, and that verifiers must still verify the issuer's trust themselves, so every response is verified against your `ITrustListResolver` as before.

## 1. Live mode

```csharp
options.Mode = VerifierMode.Live;
```

In `Live` mode a started session stays pending until a wallet posts to the callback endpoint or the session lifetime (`options.SessionLifetime`, default 5 minutes) runs out. Everything else is identical to Mock mode, which is the point: Mock exercises the exact pipeline a live wallet hits.

Live mode also checks the configuration at startup and refuses to run with the demo request builder or the dev trust list still registered, so a demo configuration cannot quietly face real wallets. No demo, mock or test background services are hosted in Live mode.

The endpoints `MapTessioVerifier` exposes (default prefix `/verify`):

| Endpoint | Role |
| --- | --- |
| `GET /verify/start` | Creates a session and renders the request page with the `openid4vp://` authorization URI |
| `GET /verify/request/{id}` | Serves the signed request object (by-reference delivery, see below) |
| `GET /verify/{sessionId}` | Session status and result as JSON, for your own frontend. Carries no authorization request (see "What the session endpoints may say") |
| `GET /verify/{sessionId}/stream` | Server-Sent Events: `pending`, then `attempt_failed` when `failedAttempts` rises (with `CompleteOnlyOnValidResponse` on, and failures close together can share one), then `completed` or `expired` |
| `POST /verify/callback` | The wallet's `response_uri`. Returns 200 with a `redirect_uri` once the response is processed, 400 for invalid or unknown responses, 409 when the session cannot take this response |
| `GET /verify/{sessionId}/return` | The page the wallet's `redirect_uri` lands on. It shows the session, and redeems the response code when the store runs the same-device flow |
| `POST /verify/same-device` | Mints a request bound to this browser and returns the link that opens a wallet on the same device (see "The same-device flow") |
| `POST /verify/callback/same-device` | The `response_uri` of a same-device request |
| `POST /verify/{sessionId}/redeem` | Redeems the response code from the redirect |

The start page and the return page carry a `Content-Security-Policy` header that allows only their own inline script and stylesheet, named by hash, plus connections and images from this origin. No other inline script, event handler or style runs on these pages, including one that markup reaching a page through a value might carry. They cannot be framed. The header on a response is the exact policy. The library sets it when the endpoint writes the page, so a policy your middleware set earlier is replaced. One set later, such as in `Response.OnStarting`, replaces the library's and stops the pages working. So does a second policy header added beside it, because the browser enforces both. So does anything between the server and the browser that rewrites the header or the page.

The callback endpoint enforces `state` correlation and completes each session exactly once, so replayed responses get a 409 (`session_not_pending`) and stray posts a 400. A response in a mode the request did not ask for also gets a 400 and does not end the session. That covers a plaintext presentation answering a `direct_post.jwt` request (a plaintext error response is the exception, see "When the wallet declines"), and a `response` token that is not encrypted: OpenID4VP 1.0 §8.3 requires an unsigned, encrypted JWT. A form that carries a cleartext `vp_token` or `error` beside an encrypted `response` is refused too, by `WalletResponseParser` itself, so a host with its own callback gets the `WalletResponseException` as well. §8.3 puts every response parameter inside the encrypted JWT and gives a cleartext one beside it no role, but neither OpenID4VP 1.0 nor HAIP 1.0 forbids one, so refusing it is this verifier's own choice, the same one it makes on the Digital Credentials API path. Other parameters beside `response`, such as `state`, are ignored, and the response is correlated by the `state` sealed inside it. An encrypted response is also refused, before any key is looked up, when its JWE header lists critical extensions (`crit`, none of which the verifier supports), names a compression (`zip`), repeats a member name, nests deeper than `JweHeaderRules.MaxDepth`, or is anything other than a single JSON object. The `crit`, duplicate and single object rules come from RFC 7516 §4.1.13 and §5.2. Refusing `zip` on every route is this verifier's own choice, which §5.2 leaves to the application: neither OpenID4VP 1.0 nor HAIP 1.0 mentions compressing a response.

**What a response that fails verification does is a setting.** By default it completes the session, and you read `Result.IsValid` false, so a holder whose wallet failed starts again with a new session. With `options.CompleteOnlyOnValidResponse = true` it gets a 400 instead (a wallet's error response still gets the 200 OpenID4VP 1.0 §8.2 requires), is recorded on the session as `LastFailure` and counted in `FailedAttempts`, and the session stays pending for another response until it expires. The status resource carries both, `lastFailure` narrowed exactly like `result`, and the stream sends `attempt_failed`. OpenID4VP 1.0 §8.6 requires the failing VP Token to be rejected and says nothing about the session, so both settings conform. The option is off by default because the frozen `VerificationSessionStatus` contract models a failed verification as completed, and turning it on changes that meaning for your deployment: a session then ends only as completed-and-valid or expired.

It also refuses a session whose stored request cannot be read, or whose query never said which credential type it asked for, with a 409 (`session_not_verifiable`). Verifying either one accepts a credential of any type, because the verifier skips the type comparison when it has nothing to compare rather than failing it.

The built-in store and request builders never produce such a session. Reaching it takes one of three things: a custom store that persisted less than the whole request, a custom `IPresentationRequestBuilder` that emits neither a request object nor the query parameters, or a hand-written DCQL entry that names no type. OpenID4VP 1.0 requires that name in both profiles, `vct_values` by §B.3.5 and `doctype_value` by §B.2.3, so `Dcql` always writes one and a query built through it always passes. See [self-driving-and-multi-tenant.md](self-driving-and-multi-tenant.md#3-persist-the-whole-request) for what has to survive.

### The same-device flow

HAIP 1.0 §5.1 requires a verifier to support the same-device flow, in which the wallet runs on the device whose browser started the request. For that flow it says: "Verifiers MUST reject presentations if Wallets do not follow the redirect back or the redirect back arrives in a different user session to the one the request was initiated in." OpenID4VP 1.0 §14.2 says how: the Response URI "MUST include a fresh secret (Response Code) into the redirect URI returned to the Wallet and the Verifier's Response URI MUST require the frontend to pass the respective Response Code when fetching the Authorization Response". The library gates completing the session rather than fetching its result: a same-device session completes only when the response code and the browser binding both arrive. After that its result is readable by session id, like any other session's.

The start page in Live mode offers a button that opens a wallet on this device. The routes behind it are mapped in every mode, so tests in Mock mode can drive them. It works like this:

1. The page posts to `/verify/same-device`. That route creates a new session bound to this browser by an HttpOnly `__Host-` cookie and answers with the wallet link. The request names `/verify/callback/same-device` as its `response_uri`, so the session carries two marks of being same-device: the store's binding and the stored request. No session that either mark calls same-device completes unbound: the binding holds its presentation, and the mark alone has it refused. The route refuses to hand out a request whose `response_uri` does not carry that path, which a custom `IPresentationRequestBuilder` that ignores the response URI it is given would produce. The page opens the wallet only after all of that succeeds.
2. When the wallet posts a presentation that verifies, the session does not complete. The presentation is held for a short window (`RedemptionWindow` in `SameDeviceSecrets.cs`, two minutes at the time of writing). The callback answers with a `redirect_uri` pointing at `/verify/{sessionId}/return` with a fresh response code in the fragment, which keeps the code out of server logs and `Referer` headers.
3. The return page posts that code to `/verify/{sessionId}/redeem`. With the cookie of the browser that started the request, the session completes with the held result. From any other browser the presentation is rejected with `session_mismatch`, under the same rule as any failed response. By default that completes the session as invalid. With `CompleteOnlyOnValidResponse` on it counts as a failed attempt and the session stays pending.
4. A presentation nobody redeems within the window never completes its session, which is the "do not follow the redirect back" case.

A wallet that opens the redirect in a different browser from the one that started the request is rejected too, because HAIP 1.0 §5.1 requires rejecting a redirect that arrives in a different user session. Expect this for some legitimate users: a wallet may open links in the system's default browser rather than the one the user started in, and that user is told to start again in the browser the wallet opens.

Every 200 from the callback carries a `redirect_uri` with a code, the start page's own cross-device session included. Only the code for a held presentation can be redeemed. The others are stored nowhere, so the return page finds nothing to redeem and shows the session as it stands.

**What this protects, and what it does not.** A same-device request relayed to someone else's device cannot complete its session, because their browser does not hold the binding. The start page's own request, the one in its QR code, stays unbound, because OpenID4VP 1.0 §14.2 says the technique "is not applicable to cross-device scenarios because the browser used by the Wallet will not have the original session".

That leaves the choice of flow with whoever starts the request, an attacker included: they can relay the QR request instead of a same-device one. HAIP 1.0 §5.1 says "Verifiers are RECOMMENDED to use only the "same-device" flow unless the Verifier does not rely on session binding for phishing resistance". The built-in start page offers both. If you rely on session binding, serve your own page that offers only the same-device request, by posting to `/verify/same-device` as the built-in button does.

This covers §5.1's requirements for the same-device flow. The rest of §5.1 depends on your configuration: signed requests (section 2) delivered by reference (section 3) and encrypted responses, which `ResponseMode` asks for by default.

Anyone who saw the wallet link holds the request's `state`. With it they can end a session that is holding a valid presentation by posting a failing response before the browser comes back. Without `CompleteOnlyOnValidResponse` that completes the session as invalid. It is a refusal, never a wrong verdict, and the user starts again.

The cookie is `Secure`, so the flow needs HTTPS, as the callback already does (see the checklist). Over plain HTTP a browser other than on `localhost` drops the cookie, and every redemption is rejected as coming from another browser.

Both POST routes accept JSON only. A form on another site can post without a CORS preflight. A JSON body needs one, so this keeps another site from replacing a browser's binding. Like `/start`, neither route is rate limited by the library: limit all three at your edge, by client address.

### When the wallet declines

A wallet that cannot or will not present posts an Authorization Error Response instead: `error` and the request's `state`, perhaps with an `error_description`. OpenID4VP 1.0 §8.2: "If the Response URI has successfully processed the Authorization Response or Authorization Error Response, it MUST respond with an HTTP status code of 200". So the callback answers it 200 with a `redirect_uri`, as it does for a presentation. The user returns to the session's page in both flows.

The session is refused under the same rule as a presentation that fails verification, with `ErrorCodes.WalletError` and the wallet's code in its message. The message stays with your store: the status resource withholds it, as it withholds every error's message. Without `CompleteOnlyOnValidResponse` that completes the session as invalid; with it, the error counts as a failed attempt and the session stays open. Only the code is kept, after checking it against the characters RFC 6749 §4.1.2.1 allows; `error_description` is text the sender chose and is dropped.

It proves nothing about the holder. Anyone holding `state` can post one, as they can post a failing presentation (see above), so read it as what the sender claimed.

It arrives in either of two forms, and the callback reads both. Under `direct_post.jwt`, which HAIP 1.0 §5.1 requires for the redirect flow, a wallet should seal it in `response` like a presentation: §5.6 says "Both successful and error responses SHOULD be returned using the supplied Response Mode". §8.3.1 also says "If a Wallet is unable to generate an encrypted response, it MAY send an error response without encryption". The callback cannot tell a wallet that was unable from one that chose not to, so it accepts an error in the clear where it would refuse a plaintext presentation. No section defines the payload of a sealed error, so the callback reads `error` and `state` from it, the members the cleartext form carries as fields.

A host with its own callback opts in with `WalletResponseParserOptions.ReadErrorResponses`. `ParseDetailedAsync` then returns such a response with `ParsedWalletResponse.Error` set and no credentials, so read `Error` before the credentials: a check over every credential passes on an empty list. Do not refuse an error for its response mode, for the §8.3.1 reason above. Without the option it throws, as it always did. `ParseAsync`, which returns credentials only, throws either way.

## 2. Sign your requests

Live wallets require JAR-signed request objects (RFC 9101). Replace the default demo builder with `SignedPresentationRequestBuilder` and the key behind your wallet-facing certificate:

```csharp
using Tessio.Verifier.OpenId4Vp;

var cert = ...;          // your WRPAC or access certificate, e.g. from a store or Key Vault
var intermediates = ...; // the CAs between it and the trust anchor, if any; never the anchor itself
builder.Services.AddSingleton<IPresentationRequestBuilder>(new SignedPresentationRequestBuilder(
    new PresentationRequestBuilderOptions
    {
        SigningCredentials = new SigningCredentials(
            new ECDsaSecurityKey(cert.GetECDsaPrivateKey()!), SecurityAlgorithms.EcdsaSha256),
        SigningCertificateChain = [cert, .. intermediates],
    }));
```

`SigningCertificateChain` goes in the request object's `x5c` header, which is how the wallet gets your certificate: OpenID4VP 1.0 section 5.9.3 requires it for the `x509_san_dns` and `x509_hash` client identifier prefixes, HAIP 1.0 section 5 requires `x509_hash` for signed requests, and for a request sent by redirect ETSI TS 119 472-2 V1.2.1 (OIDFVP-HAIP-REDIRECTS_RO-01), which CIR (EU) 2026/1731 applies and does not adapt, requires it outright. The builder checks the chain when it is created and throws an `ArgumentException` naming `options.SigningCertificateChain` if the chain is empty, holds a certificate that names itself as its issuer (a root, or a self-signed signing certificate), is out of order or starts with a CA, and, when the signing key is an `ECDsaSecurityKey`, if the first certificate does not hold its public half. Names are compared by their encoded bytes, so a self-signed certificate whose issuer is encoded differently from its subject is not caught, and with a remote signer only the public half you declare is compared, not the remote key itself. `AllowSelfSignedSigningCertificate` lifts the self-issued and CA rules for a chain of one certificate, for a test environment whose wallet trusts a published self-signed signer; it is not HAIP conformant and has no place in production. The option's documentation lists what is and is not checked. The builder reads the chain and credentials once: to rotate a key, create a new builder.

Any `SigningCredentials` works. For a key that never leaves Azure Key Vault or an HSM, point IdentityModel's signing at the remote key with a custom `CryptoProviderFactory`:

```csharp
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.IdentityModel.Tokens;

sealed class KeyVaultCryptoProviderFactory(CryptographyClient client) : CryptoProviderFactory
{
    public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm) =>
        new KeyVaultSignatureProvider(client, key, algorithm);
}

sealed class KeyVaultSignatureProvider(CryptographyClient client, SecurityKey key, string algorithm)
    : SignatureProvider(key, algorithm)
{
    public override byte[] Sign(byte[] input) =>
        client.SignData(SignatureAlgorithm.ES256, input).Signature;

    public override bool Verify(byte[] input, byte[] signature) => throw new NotSupportedException();

    protected override void Dispose(bool disposing) { }
}
```

```csharp
var client = new CryptographyClient(new Uri("https://myvault.vault.azure.net/keys/verifier-jar"), credential);
var publicKey = new ECDsaSecurityKey(publicEcdsa); // public half, exported once from the vault

builder.Services.AddSingleton<IPresentationRequestBuilder>(new SignedPresentationRequestBuilder(
    new PresentationRequestBuilderOptions
    {
        SigningCredentials = new SigningCredentials(publicKey, SecurityAlgorithms.EcdsaSha256)
        {
            CryptoProviderFactory = new KeyVaultCryptoProviderFactory(client),
        },
        SigningCertificateChain = [cert, .. intermediates], // the access certificate of that key, as above
    }));
```

Set `options.ClientId` to your registered identifier with its client-identifier prefix, for example `x509_hash:` followed by the leaf's hash (`ClientIdentifier.X509Hash(cert)`), which HAIP 1.0 requires, or `x509_san_dns:verifier.example.com`. The prefix tells the wallet how to validate your request against your certificate.

## 3. Deliver the request by reference

By default the signed request object is embedded in the `openid4vp://` URI. The start page renders that URI as a QR code for cross-device scanning, and a multi-kilobyte by-value JAR makes a dense code or exceeds QR capacity entirely (the page then shows the URI without a code). Set `RequestUriBase` and the wallet fetches the JAR over HTTPS instead, keeping the QR small:

```csharp
new PresentationRequestBuilderOptions
{
    SigningCredentials = ...,
    RequestUriBase = new Uri("https://verifier.example.com/verify/request"),
}
```

Point it at `{your host}{route prefix}/request`. `MapTessioVerifier` already serves stored request objects there with the required `application/oauth-authz-req+jwt` content type, and the start endpoint stores each session's JAR automatically. Request objects expire with their session.

## 4. Supply a real trust list

The default resolver trusts only the built-in demo and mock issuers, so real credentials will verify but report `Trusted = false` and fail. Live mode refuses to start with the default in place; register your own resolver before `AddTessioVerifier`.

How much you need to configure depends on how issuers prove their keys:

- **Issuer metadata** (`iss` HTTPS URI): the identifier is proven by control of the issuer's domain, so listing the identifier is enough.
- **X.509 (`x5c` header)**: the signing key comes from the presented certificate, so the identifier proves nothing on its own. Anyone can put a trusted issuer's name in a self-signed certificate. `StaticTrustListResolver` therefore requires the chain to anchor on a certificate you configure, and rejects x5c credentials when no anchors are set.
- **X.509 by URL (`x5u` header)**: the certificate is named by a URL and a thumbprint instead of carried, which CIR (EU) 2026/1731 Annex I has a PID do: `x5u` with `x5t#S256` for SD-JWT VC, `x5u` with a SHA-256 `x5t` for mdoc. The fetched chain is then judged exactly like an `x5c` one. This route is off by default, see below.

**The verifier fetches nothing a credential names for an issuer you do not trust,** unless you turn on `ResolveX5u` (on `SdJwtVcVerifierOptions` and on `MdocVerifierOptions`). A credential that names its certificate by `x5u` and carries no `x5c` or `x5chain` can only be judged after the certificate is fetched, so with the option on that fetch happens before your resolver is asked. The `x5u` is used only when a thumbprint in the header binds it (`x5t#S256`; for mdoc, `x5t`, with the `x5u` itself, in the protected header), and then in preference to an SD-JWT VC's issuer metadata; the fetched certificate must match that thumbprint. An SD-JWT VC's `x5u` with no thumbprint is ignored, so one that also names an HTTPS `iss` still resolves through issuer metadata; with no other way to a key, an unbound `x5u` is refused. The fetch has the limits under [Adjusting verification policy](#adjusting-verification-policy). A resource is kept only for a credential that verified in full, keyed by URL and thumbprint, and reused for an hour from when it was fetched. The issuer whose URL it is learns when its credentials are verified. `AddTessioVerifier` registers both verifiers with the option off; to turn it on, register them yourself as that section shows. With the option off, which is the default, the `x5u` is ignored as it was before it was read: an SD-JWT VC that also names an HTTPS `iss` resolves through issuer metadata, and a credential with no other way to its key fails with `issuer_key_unresolvable` and a message saying x5u resolution is off. Turn it on for a trust source whose issuers name their certificate this way, and not as a setting a customer of yours can change. A status list token is never resolved by `x5u`, whatever the option: HAIP 1.0 Final section 6.1 has its key in `x5c`. On the metadata route, `SdJwtVcVerifier` asks your resolver about the `iss` value, with an empty chain, before it fetches the issuer's key. An untrusted issuer there fails with `issuer_untrusted` alone (`trust_list_expired` when your resolver says its list has lapsed), because its key is never retrieved and nothing else can be checked. On the X.509 route the key arrives in the credential, or with `ResolveX5u` on from the URL it names, so the signature is checked first and your resolver is then asked about the chain. On both routes the status list is fetched only for a trusted issuer, and `StaticTrustListResolver` builds a chain only from the presented certificates and your anchors, never downloading a certificate one of them points to. A Token Status List signer may send its own certificate alone, which HAIP 1.0 Final section 6.1 allows, while section 6.1.1 requires a credential to carry its chain. To accept such a signer, configure the certificate that issued it as an anchor alongside its root: the intermediate alone is not enough, because the chain still has to end on a root you configured. When a chain is refused because it is incomplete, the reason says where it stops and which issuer it names above that, which is the certificate to install. Every certificate on the anchor list is trusted for every purpose, so an intermediate added for status signers is also accepted as the signer of a credential, or as a pinned certificate in its own right.

This makes one demand of a resolver you write yourself. What it receives is chosen by whoever presented the credential: on the metadata route an identifier, before any signature has been checked, and on the X.509 route a chain whose certificates anyone can mint. Answer from your own configuration: a resolver that fetches, meters or records per request does so for input nobody has vouched for. If your resolver cannot decide, throw `HttpRequestException`, `IOException` or `TimeoutException` for a trust source it cannot reach, or `InvalidOperationException` when it is not in a state to answer, and let a timeout's `OperationCanceledException` propagate. The verifier fails the credential closed with `issuer_trust_unresolvable`, or `status_unresolvable` when the question was about a status list signer, and the resolver's message is kept in the error. Any other exception escapes as a defect.

```csharp
using Tessio.Verifier.Trust;

builder.Services.AddSingleton<ITrustListResolver>(new StaticTrustListResolver(
    ["https://pid-issuer.example.de"],
    source: "my-trust-list",
    trustAnchors: [rootCertificate]));   // CA roots or pinned issuer certificates
```

**Certificate validity is read on both paths.** Pinning a certificate says "this exact certificate",
not "this certificate forever": a pinned issuer certificate that has expired, or has not yet begun, is
rejected, and the reason names its window. An anchored chain is judged the same way, by the chain
builder. Expiry is what bounds how long a key stays trusted once nobody is looking after it, and a
pinned leaf is no exception to that.

Pass `clock:` when you verify at a chosen instant rather than at now, such as re-checking a stored
presentation or running a published conformance vector whose certificates have since expired. It
governs **both** paths, the pinned leaf and the chain build, so the answer cannot depend on which of
them a given configuration happens to take. Give it the **same** `TimeProvider` you give the verifier,
or the two halves judge one presentation at two different moments and disagree about exactly the
certificates whose window has closed.

```csharp
var clock = TimeProvider.System;   // or a fixed one, when replaying something frozen
new StaticTrustListResolver(issuers, trustAnchors: [rootCertificate], clock: clock);
```

For metadata-only issuers a plain identifier list works, loaded from a JSON document of the form `{"trusted_issuers": ["https://issuer.example", ...]}` on disk or at an HTTPS URL:

```csharp
builder.Services.AddSingleton<ITrustListResolver>(
    await TrustListLoader.LoadAsync("trusted-issuers.json"));
```

Or implement `ITrustListResolver` directly. It receives the credential's issuer identifier and its X.509 chain when one is present, and returns an `IssuerTrustStatus`. This is the seam for LOTL-derived national trust lists, your own registry or a managed trust service:

```csharp
public sealed class MyTrustResolver : ITrustListResolver
{
    public Task<IssuerTrustStatus> ResolveAsync(
        string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default)
    {
        // Look the issuer up in your trust source; inspect the chain if you anchor on certificates.
    }
}
```

`IssuerTrustStatus` carries more than the verdict, and what you populate is what a caller can record
afterwards. All of it is optional. The first three below reach `VerificationResult.Issuer`. `Reason` becomes
a `VerificationResult.Errors[].Message` instead, and `TrustListExpired` decides that error's code:

| Field | Set it to |
|---|---|
| `TrustListSource` | which list produced the verdict, **on a refusal as well as a pass**. A rejected presentation is the one a relying party has most reason to question, and "not trusted" without naming the list that was asked answers nothing. If your resolver consults several lists and none matched, null is the honest answer: no single list produced that refusal |
| `TrustAnchorSubject` | the anchor that vouched for the key, for a human reading a record. Null wherever no certificate was involved, which is the identifier route, and null on a refusal unless you know which configured anchor was matched and rejected |
| `TrustAnchorThumbprint` | that anchor's SHA-256 over its DER, uppercase hex, from `GetCertHashString(HashAlgorithmName.SHA256)`. This is the identity; a subject is not, because distinguished names are not unique |
| `Reason` | why, when the verdict is false. It may quote what the presenter sent, such as certificate names; the library makes it one line on its way into a result, each character that could break a log line becoming U+FFFD, as it does every failure message in a result |
| `TrustListExpired` | true on a refusal whose cause is the list itself, not the issuer. The credential then fails with `trust_list_expired` instead of `issuer_untrusted`, or instead of `status_invalid` when the party you refused signed a status or revocation list, so whoever reads the result looks at the list's publisher, not the wallet's issuer. Set it for a list past its next update: ETSI TS 119 612 V2.4.1 section 5.3.15, "TL with a Next update occurring in the past shall be discarded as expired". Setting it for a closed list, whose next update is null, is your choice. The code is not secret: like every code, it reaches an anonymous caller of the session status resource, so it tells them your list has lapsed |

**Two things to weigh before you populate them.** `source` is a label, not a location: the built-in
`TrustListLoader` passes the path or URL you hand it straight through, so the string can be a server
filesystem path, and a directory of anchor files can name the parties a deployment trusts. And these
fields describe the verdict rather than today's configuration, which is the point: reading a deployment's
current anchors back later answers a different question from the one an auditor asked.

### Debugging a chain that will not build

`StaticTrustListResolver` refuses on four paths, and they say different things:

| Refusal | The reason states |
|---|---|
| The identifier is not on the list | the identifier |
| An x5c chain arrived and the list holds no anchors | that this list does not accept a certificate-carried key |
| A pinned certificate matched and its validity window had closed | that certificate's subject and window |
| The chain would not build | the platform's chain status, the leaf's own issuer, and the leaf's authority key identifier |

Only the last one describes why a chain failed, and when its names look right and it still fails, two
environment variables widen it. Both are off by default, because a reason becomes a
`VerificationResult.Errors[].Message`:

| Variable | Set to `1` to add | Affects |
|---|---|---|
| `TESSIO_TRUST_DUMP_ANCHORS` | every configured anchor's subject and subject key identifier, or `none`. This is the usual answer: matching subjects with differing key identifiers is a certificate authority regenerated under its old name, which looks like it should have worked until both are on screen. It is also a list of the parties you anchor on, so turn it on, read it, turn it off | the no-anchors and chain-build refusals |
| `TESSIO_TRUST_DUMP_LEAF` | the presented leaf as base64 DER, for when the identifiers match too | the chain-build refusal |

Neither reaches the session endpoints, which replace every failure message (see below). They are for the
reason as your own code and logs receive it.

### What the session endpoints may say

The session status resource and its SSE stream are **anonymous**. They ask for a session id and nothing
else, and `GET {prefix}/start` hands one out, so treat whatever they return as public.

**Neither carries the authorization request.** A wallet's callback is matched to its session by
`state`, so `state` stays off anything keyed only by a session id. The authorization request URI leads to
`state` in both delivery modes, inside the request object by value or one anonymous fetch of
`request_uri` away by reference. The start page still shows it, as a QR code and a link, to the user
about to hand it to a wallet. If you build your own start page, drive the session yourself as
`self-driving-and-multi-tenant.md` describes, render the authorization URI server-side for that user,
and do not expose it on an endpoint keyed only by the session id.

Both send `Cache-Control: no-store`, because they carry a verdict and disclosed claims to whoever holds
the id, and a cache holding either would outlive the session. So do the start page and the request
object, the two responses that do carry `state`: a cache serving either to a second visitor would give
two people one session.

Both also narrow two things.

**Every failure message is replaced**, with `VerificationError.Code` left intact. The code is the stable
part a caller acts on; the message is prose written by whoever produced the failure, and it has been
observed to carry a locator. The built-in status list checks interpolate a URL and an inner exception
message, and an `ITrustListResolver` is free to name its list in a reason. Dropping all of them needs no
judgement about any one string. Your own surfaces read the stored result, where the messages are intact.

**`TrustListSource` becomes the literal `undisclosed`** unless the deployment has named the value as safe
to publish. The list is an allowlist, empty by default:

```csharp
services.AddTessioVerifier(options =>
{
    // A Commission-published trusted list URL is already public, so naming it helps an integrator.
    options.PublicTrustListSources.Add("https://ec.europa.eu/.../age-verification-list.xml");
});
```

An allowlist rather than a rule that hides paths, because a rule has to judge whether a string looks
sensitive and fails open on the first shape nobody anticipated. This fails closed: unlisted means
undisclosed. Nothing useful is lost, since "a list was consulted and your issuer was not on it" is the
part a caller acts on, and the token still says that.

`undisclosed` and `null` are different answers. `undisclosed` means a list produced this verdict and is
not named here. `null` means no attribution is available, which covers both "no list was consulted" and
"the resolver in use reports no source", and those two cannot be told apart.

The anchor subject and thumbprint are **not** narrowed. The caller's own credential is what produced them,
so they name the one anchor that caller has just proved it chains to, rather than the set you hold. Note
what that does and does not cover: if you pin individual document signer certificates as anchors rather
than a published root, an anonymous caller learns the digest of the one you pinned for that issuer.

The rule generalises, and it is worth applying to any diagnostic field added after this one: **one field,
two boundaries.** The anonymous surface gets a fixed token, and a surface you authorise and scope yourself
gets the whole string. Your own endpoints read `VerificationResult` straight from the session store, which
the narrowing never touches, so the full value is there when the caller is known.

**One more channel to know about.** `IssuerInfo` is a record, so its generated `ToString()` prints every
property, `TrustListSource` included, and `VerificationResult.ToString()` nests it. Nothing in this library
stringifies a result, but a consumer that logs one, interpolates it into a message, or lets it reach an
exception an error monitor captures sends the locator wherever those go. The narrowing is a boundary on
the JSON these endpoints serve, not on the object.

**Values a result carries as data are the presenter's own.** `IssuerInfo.Identifier`, an `iss` or the
subject of a presented certificate, and `VerificationResult.CredentialType` are kept exactly as presented,
because you store and compare them. Failure messages, trust reasons, the messages of the exceptions the
library throws and its own log lines are made one line, each character that could break a log line becoming U+FFFD; these two values are not, so do
the same before writing them to a plain-text log.

## 5. Share sessions across instances

The default `InMemorySessionStore` is process-local. Behind a load balancer the wallet's callback can land on a different instance than the one that started the session, so the store must be shared. Implement `IStateCorrelatingSessionStore` over Redis, SQL or any shared storage:

```csharp
public sealed class RedisSessionStore : IStateCorrelatingSessionStore
{
    public Task<VerificationSession> CreateAsync(PresentationRequestOptions options, CancellationToken ct = default);
    public Task<VerificationSession?> GetAsync(string sessionId, CancellationToken ct = default);
    public Task<VerificationSession?> FindByStateAsync(string state, CancellationToken ct = default);
    public Task CompleteAsync(string sessionId, VerificationResult result, CancellationToken ct = default);
}
```

```csharp
builder.Services.AddSingleton<ISessionStore, RedisSessionStore>();
```

`FindByStateAsync` is the extra member beyond the base `ISessionStore`: a wallet response carries only the OpenID4VP `state` value, so the callback path needs a state index next to the sessions. Registering a store without it fails fast with an explanatory exception on the first callback.

For the same-device flow the store must also implement `ISameDeviceSessionStore`:

- `CreateBoundAsync` keeps a browser's binding with the session.
- `HoldAsync` keeps a verified result without completing the session. The callback calls it for every verified presentation, cross-device ones included, so for a session it holds no binding for it must answer `NotBound` and change nothing, whatever that session's state. Anything else breaks the QR flow.
- `RedeemAsync` completes the session with the held result in one step, and only when the response code and the binding both match. These two comparisons are the protection, and the library does not repeat them, so they must be made here. A browser that sent no cookie is passed a hash nothing was bound to, which the comparison must reject.

The values a store receives are SHA-256 hashes, never the secrets, so compare them with `CryptographicOperations.FixedTimeEquals`.

Without the interface, `MapTessioVerifier` maps no same-device route and logs a warning (`SameDeviceUnavailable`) at startup. Cross-device verification works unchanged, with the return page showing the session and redeeming nothing. HAIP 1.0 §5.1 requires the same-device flow, though, so a HAIP deployment needs the interface.

A session is same-device when either the store's binding or the stored request says so. A store that loses the binding but keeps the request is caught: the callback refuses the presentation with a 409 (`session_not_verifiable`) and logs an error (`SameDeviceBindingLost`) rather than complete the session unbound. A store that keeps the binding and loses the request's `response_uri` still holds through the binding. A store must keep at least one of the two: with neither, the session is indistinguishable from a cross-device one and completes as one.

With `CompleteOnlyOnValidResponse` on, the store must also implement `IAttemptRecordingSessionStore`, whose `RecordFailedAttemptAsync` sets `LastFailure`, increments `FailedAttempts` and leaves the session pending. It must do nothing once the session has left `Pending`, so a failure that loses a race with a valid response cannot overwrite it. A store without it fails fast the same way, when the callback is first built.

If you drive creation and completion from your own API (bypassing `/start` and `/callback`) or host many tenants in one process, see [self-driving-and-multi-tenant.md](self-driving-and-multi-tenant.md) for the `IWalletResponseVerifier` seam, a durable Postgres store and the request-object round-trip.

Two behaviors to know:

- `CreateAsync` builds the presentation request (inject `IPresentationRequestBuilder`) and must index the request's `state`. Complete each session at most once and treat later completions as no-ops or conflicts.
- The SSE stream endpoint gets push notifications from the in-memory store. With a custom store it polls `GetAsync` every 500 ms until the session leaves `Pending` or its `FailedAttempts` changes, which works unchanged with any store.

## 6. Response encryption across instances

With `ResponseMode.DirectPostJwt` (the default and the HAIP baseline) wallets encrypt their responses to a key published in your request's `client_metadata.jwks`.

**The key is ephemeral per authorization request, not per process.** HAIP 1.0 §5 requires this ("Verifiers MUST supply ephemeral encryption public keys specific to each Authorization Request"), OpenID4VP 1.0 §5.1 allows it, and the conformance suite fails a verifier that reuses one. The reasons are real: a single long-lived key means its compromise retrospectively exposes every response ever encrypted against it, and a stable advertised public key is a correlation handle tying separate presentations to one verifier. By default `ResponseEncryptionKeyStore` generates a fresh P-256 key at `/verify/start`, holds it in memory, and the callback finds it again by the `kid` (RFC 7638 thumbprint) the wallet echoes in the JWE header. **The private half never touches disk.**

**Resolving by `kid` is spec-mandated, so decryption requires it with no fallback.** OpenID4VP 1.0 §5 requires that every JWK in `client_metadata.jwks` carry a `kid`, and §8.3 then requires that "if the selected public key contains a `kid` parameter, the JWE MUST include the same value in the `kid` JWE Header Parameter" of the encrypted response. The advertised key always has a `kid`, so a conformant wallet always echoes it. A response that carries none, or names a `kid` the store no longer holds, is rejected rather than decrypted against a guessed key: for `direct_post.jwt` the `state` that correlates the session lives inside the ciphertext, so the `kid` is the only handle available before decryption, and quietly trying "the only key we have" would reintroduce the shared-key ambiguity this design exists to remove. Failing loud surfaces a non-conformant wallet instead of masking it.

That default is complete for a **single process**. Across instances it breaks the same way sessions do: instance A generates the key and holds it in its own memory, so instance B cannot decrypt a response routed to it.

**When you scale out, or need a request's response to survive a redeploy: derive the key, store no key material.** Build the store with `ResponseKeyDerivationOptions` and it derives each request's private key from one master secret and a fresh random salt, and saves only the salt:

```
d    = HKDF-SHA256(master, salt), reduced to a P-256 scalar   // salt: 32 random bytes per request
kid  = base64url SHA-256 thumbprint of the public JWK
```

`ResponseKeyDerivation` says exactly how, and its tests check it against an independent implementation. The salt is stored keyed by `kid`, in storage every instance shares, such as the database you already run for sessions (§5). At the callback, whichever instance receives the response finds the salt for the response's `kid`, derives the key again and decrypts. The salt is not secret: without the master it derives nothing.

```csharp
builder.Services.AddSingleton(sp => new ResponseEncryptionKeyStore(
    sp.GetRequiredService<TimeProvider>(),
    new ResponseKeyDerivationOptions
    {
        Master = LoadResponseKeyMaster(),                        // at least 32 random bytes
        Salts = sp.GetRequiredService<IResponseKeySaltStore>(),  // yours, over shared storage
    }));
```

Registering your own store replaces the default one. Implementing `IResponseKeySaltStore`:
- `Save` must make the salt visible to every instance before it returns, because the request naming the key is sent straight after. If it throws, the request fails and no key is kept.
- `Find` returns null when it has no salt for the `kid`. It may return an expired one, which the store treats as absent. The `kid` it is given is the one the wallet's response names: it has the shape of a `kid` the store issues and is otherwise unchecked, so parameterise the lookup.
- Both are synchronous: the library resolves the key through a synchronous callback inside response decryption, so an implementation over a database blocks on it.
- Delete a salt once it expires. While it is kept, the master derives its key again, and so can decrypt a response to it that someone captured.

**What derivation gives up.** An in-memory key is gone when its request ends, so nothing can decrypt that request's response afterwards. A derived key can be derived again for as long as its salt is kept: the master and a kept salt together decrypt a captured response, and the master with read access to the salts decrypts every response to come until it is replaced. Each request still advertises its own key, because each has its own salt.

**The master is the only long-lived secret, and it lives in process memory**, because the derivation runs there. Load it from your secret store at boot. A key that never leaves an HSM cannot serve as the master. The store copies it and zeroes its copy when disposed; the array you pass in is yours to clear.

**Every instance that shares the salts must hold the same master.** A salt that derives a key with another `kid` means the master is not the one that created it, or the stored salt is corrupt. `Get` then throws `InvalidOperationException` rather than reporting an unknown key, so the callback fails with a server error instead of passing for an expired session or a replay. A `kid` that differs from an issued one only in letter case, which a salt store that ignores case would match, names no key and is refused as unknown. Rotating the master therefore fails the requests still in flight under the old one wherever their key has to be derived again, until they expire (`SessionLifetime`). An instance already holding a key keeps answering with it.

**The key is not the only thing a request needs.** A request object the start endpoint stores for delivery by reference (§3) is held in memory by the instance that stored it, so a wallet that fetches its `request_uri` from another instance, or after a restart, finds nothing. The session must survive too (§5).

Why not the alternatives:
- **Persisting the private key**, even as KMS-encrypted ciphertext in Postgres, puts key material in your database, though the key that encrypts it can stay in hardware. Derivation stores no key material, and pays for it with a master in process memory.
- **Sticky sessions** (route the callback to the instance that issued the request) store nothing, but couple you to load-balancer affinity and lose the key if that instance restarts mid-flow. A reasonable stopgap, not the target.

On a single instance whose requests need not survive a restart, the in-memory default is correct and needs no configuration.

**The Digital Credentials API (Annex C) has its own response key, and you hold it.** `Iso18013AnnexC.CreateRequest` mints one per request and returns its private half as `ResponseKeyPkcs8`, which you store with the session until the answer arrives. So that another instance or this one after a restart can open that answer, pass in a derived key instead. Store only its salt beside the `EncryptionInfo` bytes and derive the key again at the response:

```csharp
var salt = RandomNumberGenerator.GetBytes(32);                    // at least ResponseKeyDerivation.MinimumSaltLength
using (var derived = ResponseKeyDerivation.Derive(master, salt))
using (var responseKey = ECDiffieHellman.Create(derived.ExportParameters(includePrivateParameters: true)))
{
    var request = Iso18013AnnexC.CreateRequest(docType, nameSpace, elements, zkRequest: null, responseKey);
    // Store salt and request.EncryptionInfo with the session; send request.DeviceRequest and EncryptionInfo.
}

// At the response, on any instance:
using var again = ResponseKeyDerivation.Derive(master, storedSalt);
using var key = ECDiffieHellman.Create(again.ExportParameters(includePrivateParameters: true));
var opened = Iso18013AnnexC.OpenResponse(encryptedResponse, key.ExportPkcs8PrivateKey(), storedEncryptionInfo, origin);
```

The same rules hold as for OpenID4VP above. Use a fresh salt per request, so that no two requests advertise one key. Give every instance the same master, and delete each salt once its request expires. One master can serve both transports: each key comes from its own random salt, so the two never derive the same key in practice. `CreateSignedRequest` takes a response key the same way.

`ResponseMode.DirectPost` (cleartext form posts) is also supported, but encrypted responses are the profile default so stay on `DirectPostJwt` unless you have a reason not to.

## Requesting mdocs instead of SD-JWT VC

The same pipeline verifies ISO mobile documents (the mDL and the mdoc flavour of the PID). One option switches the credential format:

```csharp
builder.Services.AddTessioVerifier(options =>
{
    options.Mode = VerifierMode.Live;
    options.CredentialFormat = "mso_mdoc";
    options.ExpectedDocType = "org.iso.18013.5.1.mDL";   // or eu.europa.ec.eudi.pid.1
    options.MdocNamespace = "org.iso.18013.5.1";
    options.RequestedClaims = ["age_over_18"];
});
```

The DCQL query then uses `doctype_value` and `[namespace, element]` claim paths, and responses are verified by `MdocVerifier`: issuer signature via the `x5chain` Document Signer certificate (or the one an `x5u` names, with `ResolveX5u` on), per-item digests against the Mobile Security Object, validity window and the device signature over the OpenID4VP session transcript (which binds your client_id, nonce, response_uri and response-encryption key).

Two things differ from the SD-JWT path:

- **Trust anchors are mandatory.** mdoc trust is X.509 only (IACA roots), so your `ITrustListResolver` must anchor chains; an identifier list alone rejects everything. Pass the IACA certificates as `trustAnchors` and list the Document Signer subjects as issuers.
- **Revocation lists are trusted through the credential.** An mdoc whose MSO carries a `status` element is checked against the MSO revocation list it references, status list or identifier list (Implementing Regulation (EU) 2024/2979, Annex II as replaced by Implementing Regulation (EU) 2026/1731, EAA-6.2.10.1-06). The list's chain must anchor on the certificate the MSO reference names or, where it names none, on the certificate that signed the credential's own Document Signer, and your resolver must vouch for that certificate on the same anchor it placed the Document Signer on. A list your resolver trusts for some other reason is not enough. So anchor on IACA certificates: a resolver that reports no `IssuerTrustStatus.TrustAnchorThumbprint`, or that pins Document Signers themselves, cannot place such a list, and the credential fails with `status_unresolvable` (`StaticTrustListResolver` reports the thumbprint). `MdocVerifierOptions.CheckStatus` turns the check off. The default client does not follow redirects (see below), so a list served through one fails with `status_unresolvable`; draft -20 section 8.2 says clients SHOULD follow them, and a client you supply may.
- **Stay on `direct_post.jwt`.** The high-assurance profile requires encrypted responses for mdocs, and the encryption key's thumbprint is part of what the wallet's device signature covers.

Mock mode works the same way: with `CredentialFormat = "mso_mdoc"` the built-in wallet issues real device-signed DeviceResponses, so you can exercise the whole mdoc flow offline. The mdoc pipeline is verified against external artifacts at every layer: the ISO 18013-5 Annex D worked example (parsing, digests and issuer signature agree with the spec's own bytes), the OpenID4VP Annex B.2.6 transcript vectors (byte-identical to the EUDI reference wallet's own test expectations) and a cross-implementation round trip in which an independent mdoc stack (OpenWallet Foundation wallet-framework-dotnet) built and signed the device authentication that this verifier accepts.

## Adjusting verification policy

`SdJwtVcVerifier` defaults are strict: key binding required, credential status (Token Status List) checked and failing closed, 5 minutes of clock skew. `MdocVerifier` is the same: device authentication required and MSO revocation checked and failing closed (`MdocVerifierOptions`). To change them, register the verifier yourself:

```csharp
using Tessio.Verifier.Core;
using Tessio.Verifier.Core.Mdoc;

builder.Services.AddSingleton<ICredentialVerifier>(sp => new SdJwtVcVerifier(
    sp.GetRequiredService<ITrustListResolver>(),
    new SdJwtVcVerifierOptions
    {
        ClockSkew = TimeSpan.FromMinutes(2),
        // RequireKeyBinding = false,   // only for credentials without cnf
        // CheckStatus = false,         // only if you accept revoked-credential risk
        // ResolveX5u = true,           // only for a trust source whose issuers use x5u (section 4)
    },
    clock: sp.GetRequiredService<TimeProvider>()));

builder.Services.AddSingleton(sp => new MdocVerifier(
    sp.GetRequiredService<ITrustListResolver>(),
    new MdocVerifierOptions
    {
        // ResolveX5u = true,           // as above
    },
    sp.GetRequiredService<TimeProvider>()));
```

Verification results carry stable error codes (`nonce_mismatch`, `untrusted_issuer`, `credential_revoked` and so on) in `VerificationResult.Errors`, so your application logic and your logs can branch on codes rather than messages.

**What a credential can make the verifier fetch, and the limits on it.** An SD-JWT VC can make the verifier fetch its issuer's JWT VC Issuer Metadata and the `jwks_uri` that metadata names, its status list, and the status list signer's metadata and key set. An mdoc can make it fetch the MSO revocation lists its `status` element references. With `ResolveX5u` on, either format can also make it fetch the signing certificate its `x5u` names. Each of those must be HTTPS and is read only up to a size limit, and each has its own deadline, so a credential that causes several waits on them in sequence. A status list is also limited in size once decompressed. The values, and the reason for each, are the constants at the top of `src/Tessio.Verifier.Core/OutboundFetch.cs`, and for an `x5u` resource of `src/Tessio.Verifier.Core/CertificateUrlFetcher.cs`. The verifier's default client also refuses a host that resolves outside the public internet, does not follow redirects and ignores the process proxy, because through a proxy the address check would see only the proxy. The check runs inside the connection, which then connects to exactly the addresses checked, so a DNS answer that changes between the check and the connection cannot slip past. An issuer whose metadata redirects therefore fails with `issuer_key_unresolvable`, and a status list that redirects fails with `status_unresolvable`. If you pass your own `HttpClient`, the deadline and the size limits still apply, but the address check, the redirect refusal and the proxy refusal do not, so give it a handler that enforces them. SD-JWT VC draft -13 section 10.1 requires the address check, a time bound and a size bound for the issuer metadata endpoint. Applying them to every fetch a credential causes, and refusing redirects, are this library's choices.

`VerificationResult.CredentialType` reports what was **presented**: the `vct` for SD-JWT VC, the `docType`
for mdoc. You already know what you asked for, so this only earns its place once a request names several
types, as [above](#when-those-types-put-the-same-fact-in-different-places): then it is the only way to
learn which one the holder actually produced, and it is populated on the failing path too, where it
answers "a mismatch against what?". It is null when verification failed before the type could be read,
which means "not established" rather than "the credential declared none".

## Binding transactions into presentations

For flows where the credential authorizes a specific act (a payment, a contract signature), OpenID4VP transaction data binds the holder's signature to that act. Supply the transaction objects and the rest is automatic: they ride base64url-encoded in the signed request, the wallet hashes each one into its Key Binding JWT and the verifier rejects presentations whose hashes are missing or wrong.

```csharp
options.TransactionData = ["""{"type":"payment_confirmation","amount":"120.00 EUR"}"""];
```

`credential_ids` defaults to the query's credential id. Failures surface as `transaction_data_missing`, `transaction_data_hash_mismatch` or `transaction_data_alg_unsupported`. SD-JWT VC flows only; the mechanism requires key binding.

## Observability

The pipeline logs through `Microsoft.Extensions.Logging`, so whatever your host configures (console, Application Insights, OpenTelemetry) picks it up with no extra wiring. Session creation logs under `Tessio.Verifier.Sessions`; callback handling logs under the `WalletCallbackProcessor` category. Every rejected wallet response logs a warning with the cause (parse failure, missing or unknown state, replay) and every completion logs the verification outcome with its error codes, or the wallet's own code for an error response. Disclosed claims and credential contents are never logged.

## What the library does not cover

Verifying real EUDI wallets in production also requires registering as a relying party in your member state, plus maintained EU trust lists, and for a profile that signs its requests a wallet-relying party access certificate (WRPAC) from a certificate authority your member state has authorised. See [docs/production.md](https://github.com/tripledownab/tessio-verifier/blob/main/docs/production.md) for that landscape. The library covers the protocol and the credential verification; the registration and trust layer is yours or a provider's.

## Checklist

- [ ] `VerifierMode.Live`
- [ ] `SignedPresentationRequestBuilder` with your certificate's key (HSM or Key Vault via `CryptoProviderFactory`)
- [ ] `ClientId` set to your registered identifier with its prefix
- [ ] `RequestUriBase` set so QR codes stay small
- [ ] Real `ITrustListResolver` registered, with trust anchors for issuers that use x5c
- [ ] `PublicTrustListSources` names every trust list identifier you are content to publish, and nothing else
- [ ] Multi-instance: `IStateCorrelatingSessionStore` over shared storage and `ISameDeviceSessionStore` for the same-device flow
- [ ] `/verify/start`, `/verify/same-device` and `/verify/{sessionId}/redeem` rate limited at your edge, and the callback too with derived keys, where each response naming a well-formed `kid` costs a salt store read
- [ ] Multi-instance: `ResponseEncryptionKeyStore` built with `ResponseKeyDerivationOptions`, one master shared by every instance and an `IResponseKeySaltStore` over shared storage
- [ ] Callback endpoint reachable over HTTPS from the public internet
- [ ] Verified end to end in Mock mode first, then against a reference wallet
