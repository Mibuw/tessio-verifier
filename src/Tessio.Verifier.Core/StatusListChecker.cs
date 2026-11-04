using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core;

/// <summary>
/// Resolves and enforces a credential's <c>status</c> claim against a Token Status List: fetches the
/// status list token, validates it (typ, signature, sub↔uri binding, signer trust, expiry),
/// decompresses the bitstring, and maps the referenced index to a verification outcome. The signer is
/// judged by the same <see cref="ITrustListResolver"/> as the credential's own issuer, because the
/// Status Issuer may be a party the issuer authorised rather than the issuer itself. Validated lists are cached
/// per uri for min(cache duration, the token's <c>ttl</c> claim, its <c>exp</c>); failures are
/// never cached, so an unresolvable status stays fail-closed on every attempt.
/// </summary>
// SPEC: draft-ietf-oauth-status-list-20: §6.2 (status claim), §5.1 (status list token in JWT
// format), §8.3 (Relying Party validation rules), §4.1/§4.2 (bit packing and compression),
// §8.3 step 4d and §13.7 (ttl-driven caching). Every bare section number in this file means -20.
// -20 is the draft CIR (EU) 2026/1731 pins for the status member of an SD-JWT VC (its Annex IV,
// adaptations (1) and (5), replacing Annex II of 2024/2979). HAIP 1.0 cites -14.
internal sealed class StatusListChecker
{
    private const string StatusListTyp = "statuslist+jwt";

    /// <summary>A validated, decompressed status list, keyed by the uri it was fetched from.</summary>
    /// <remarks>
    /// It carries NO credential issuer. What validation established is that this token is authentic,
    /// anchors on a configured anchor, and names this uri in its <c>sub</c>. None of those depend on
    /// which credential pointed here, and the index being read comes from the credential rather than
    /// from the cache. Keeping an issuer here while keying the dictionary on the uri alone also made
    /// the cache useless the moment a Status Issuer served one list for several credential issuers:
    /// each one missed the other's entry and then overwrote it, so every check re-fetched.
    /// </remarks>
    private sealed record CachedList(int Bits, byte[] List);

    private readonly StatusListCache<CachedList> _cache = new();
    private readonly HttpClient _httpClient;
    private readonly IssuerKeyResolver _keyResolver;
    private readonly ITrustListResolver _trustListResolver;
    private readonly TimeProvider _clock;
    private readonly TimeSpan _clockSkew;
    private readonly TimeSpan _cacheDuration;

    public StatusListChecker(
        HttpClient httpClient,
        IssuerKeyResolver keyResolver,
        ITrustListResolver trustListResolver,
        TimeProvider clock,
        TimeSpan clockSkew,
        TimeSpan cacheDuration)
    {
        _httpClient = httpClient;
        _keyResolver = keyResolver;
        _trustListResolver = trustListResolver;
        _clock = clock;
        _clockSkew = clockSkew;
        _cacheDuration = cacheDuration;
    }

    /// <summary>
    /// Checks the credential's status when a <c>status</c> claim is present. Returns accumulated
    /// policy errors; an empty list means valid (or no status claim to check).
    /// </summary>
    /// <param name="payload">The processed credential payload.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <remarks>
    /// It deliberately takes NO credential issuer. Nothing here is decided by who issued the
    /// credential: the issuer's say in which list speaks for it is the uri inside the credential it
    /// signed, and the rest is the token's own authenticity. The parameter that used to be here fed a
    /// same-issuer comparison that has been removed.
    /// <para>
    /// Trust here is per SIGNER, not per purpose, because that is what
    /// <see cref="ITrustListResolver"/> answers. So configure anchors on the understanding that one
    /// entry covers every question this library asks about that party, status signing included, and
    /// scope the trust list to signers the deployment means to accept for all of them. Where an
    /// ecosystem publishes issuance and revocation anchors separately, keep that separation by giving
    /// the resolver only what belongs to the deployment's own purpose.
    /// </para>
    /// </remarks>
    public async Task<List<VerificationError>> CheckAsync(JsonObject payload, CancellationToken ct)
    {
        if (!payload.TryGetPropertyValue("status", out var statusNode))
        {
            return [];
        }

        // SPEC: §6.2 — "status": {"status_list": {"idx": <non-negative int>, "uri": <string>}}.
        var statusList = statusNode is JsonObject statusObj
                         && statusObj.TryGetPropertyValue("status_list", out var listNode)
            ? listNode as JsonObject
            : null;
        var idx = statusList?.TryGetPropertyValue("idx", out var idxNode) == true
                  && idxNode?.GetValueKind() == JsonValueKind.Number
            ? (idxNode.GetValue<JsonElement>().TryGetInt64(out var idxValue) ? idxValue : -1)
            : -1;
        var uri = statusList?.TryGetPropertyValue("uri", out var uriNode) == true
                  && uriNode?.GetValueKind() == JsonValueKind.String
            ? uriNode.GetValue<string>()
            : null;

        if (idx < 0 || uri is null)
        {
            return [Error(ErrorCodes.StatusInvalid, "The status claim carries no valid status_list.idx/uri.")];
        }

        // HTTPS, which is the bar JWT VC Issuer Metadata resolution already holds in IssuerKeyResolver.
        // A status list says whether a credential is still valid, so fetching one in clear lets anyone
        // on the path answer that question. This is our bar, not the draft's: section 8.1 asks only for
        // an HTTP GET to the uri.
        //
        // Checked BEFORE the cache, so a cleartext uri cannot be answered from a previously cached list
        // either, and checked here rather than left to the handler, because the failure it prevents is
        // silent: an http:// list is retrieved perfectly well and the answer is whatever the network said.
        if (!Uri.TryCreate(uri, UriKind.Absolute, out var statusUri) || statusUri.Scheme != Uri.UriSchemeHttps)
        {
            return [Error(ErrorCodes.StatusInvalid, $"The status list uri '{uri}' is not an HTTPS URI.")];
        }

        if (_cache.Get(uri, _clock.GetUtcNow()) is { } cached)
        {
            return StatusListValues.Evaluate(cached.Bits, cached.List, idx);
        }

        string statusListJwt;
        try
        {
            // SPEC: §8.1: request the JWT representation.
            var body = await OutboundFetch.GetBoundedAsync(
                _httpClient, statusUri, "application/statuslist+jwt", "status list token",
                OutboundFetch.MaxStatusListTokenBytes, ct).ConfigureAwait(false);
            statusListJwt = Encoding.UTF8.GetString(body);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or InvalidOperationException or UriFormatException)
        {
            // The caller's own cancellation propagates, even when it lands while a fetch is already failing: it
            // asks to stop, and is not an unreachable list.
            ct.ThrowIfCancellationRequested();
            // Fail closed: an unreachable status list means the revocation state is unknown.
            return [Error(ErrorCodes.StatusUnresolvable, $"The status list at '{uri}' could not be retrieved: {e.Message}")];
        }

        return await ValidateStatusListTokenAsync(statusListJwt, uri, idx, ct).ConfigureAwait(false);
    }

    private async Task<List<VerificationError>> ValidateStatusListTokenAsync(
        string statusListJwt, string uri, long idx, CancellationToken ct)
    {
        if (!CompactJwt.TryParse(statusListJwt, out var token))
        {
            return [Error(ErrorCodes.StatusInvalid, "The status list response is not a well-formed JWT.")];
        }

        // SPEC: §5.1 — typ MUST be statuslist+jwt.
        if (!string.Equals(token.Typ, StatusListTyp, StringComparison.Ordinal))
        {
            return [Error(ErrorCodes.StatusInvalid, $"Status list token typ is '{token.Typ}'; expected '{StatusListTyp}'.")];
        }

        if (!SdJwtConstants.AllowedAlgorithms.Contains(token.Alg))
        {
            return [Error(ErrorCodes.StatusInvalid, $"Status list token algorithm '{token.Alg}' is not permitted.")];
        }

        // Identified from the token alone. Its keys are fetched only once the signer is trusted, below.
        IssuerKeyResolution resolution;
        try
        {
            resolution = IssuerKeyResolver.Identify(token);
        }
        catch (SdJwtProcessingException e) when (e.Code == ErrorCodes.StructureInvalid)
        {
            // A token that is not well-formed is not one whose signer is unknown: it is answered as malformed.
            return [Error(ErrorCodes.StatusInvalid, $"The status list token is malformed: {e.Message}")];
        }
        catch (SdJwtProcessingException e)
        {
            return [Error(ErrorCodes.StatusUnresolvable, $"The status list signer's key could not be resolved: {e.Message}")];
        }

        // Two things make a status list token ours to believe, and neither is its issuer identifier.
        // BINDING is the sub check below: sub MUST equal the uri, and that uri rides inside the
        // ISSUER-SIGNED credential, so the issuer chose which list speaks for it. AUTHENTICITY is this
        // call: the token's own chain goes through the same trust seam as the credential's, so a
        // self-signed token served from that uri does not anchor and is refused.
        //
        // WHAT THE SPECIFICATIONS REQUIRE, and the normative weight of each.
        //
        // draft-ietf-oauth-status-list-20 section 8.3 is the Relying Party's MUST list. Signer identity is
        // not on it. The only binding it requires to the referenced token is "The subject claim (sub or
        // 2) of the Status List Token MUST be equal to the uri claim in the status_list object".
        //
        // Section 5.1 does not define iss for this token at all, so omitting it is conformant. The
        // sentence that the Status Issuer "can be either the Issuer or an entity that has been
        // authorized by the Issuer" is section 1, the Introduction: narrative, not a requirement. The
        // working group DELETED the rule this code used to enforce, per the changelog at -04, "remove
        // requirement for matching iss claim in Referenced Token and Status List Token".
        //
        // The NORMATIVE requirement for this call is HAIP 1.0 Final section 6.1, which CONTRIBUTING.md
        // makes authoritative where the IETF drafts are ambiguous: the status token's verifying key
        // "MUST be included in the x5c JOSE header", its trust anchor "MUST NOT be included", and it
        // "MUST NOT be self-signed". That mandates anchoring the token's own chain and nowhere says the
        // anchor is the credential's. EUDI ARF section 6.3.2.4 says the same in the other direction: the
        // two anchor sets "may be the same. However, they also may be different", because revocation can
        // be outsourced.
        //
        // THIS REPLACED an equality check against the credential's issuer, labelled "defense in depth
        // beyond the spec". That check stopped an honest third-party Status Issuer and stopped no
        // attacker: it compared resolution.Issuer, which is iss ?? leaf.Subject and therefore chosen by
        // whoever serves the token, against a credential value that same party can read. Nothing
        // anchored the token's chain, so a self-signed certificate satisfied it.
        //
        // It was also UNSATISFIABLE, but only on one path, and the qualifier matters: when the
        // credential's issuer is an HTTPS URI and the status token omits iss, a subject DN is compared
        // to a URI. Where both resolve to DNs it could pass. Found 2026-09-20 against the EUDI Wallet
        // Reference Implementation, whose lists are served by another host under another CA with no iss.
        // A signer that sends only its own certificate, which HAIP 1.0 Final section 6.1 allows, anchors
        // when the deployment has configured the certificate that issued it. Nothing is fetched to find it.
        var (trust, trustFailure) = await TrustSeam.ResolveAsync(
            _trustListResolver, resolution.Issuer, resolution.CertificateChain, ct).ConfigureAwait(false);

        if (trustFailure is not null)
        {
            // A trust seam may do network I/O. Fail closed and name the cause, as TrustSeam explains.
            return [Error(ErrorCodes.StatusUnresolvable, $"The status list signer's trust could not be resolved: {trustFailure.Message}")];
        }

        if (!trust.Trusted)
        {
            return
            [
                Error(
                    TrustSeam.RefusalCode(trust, ErrorCodes.StatusInvalid),
                    trust.Reason is null
                        ? $"The status list token's signer '{resolution.Issuer}' is not trusted."
                        : $"The status list token's signer is not trusted: {trust.Reason}"),
            ];
        }

        // AFTER the trust verdict, as for the credential's own issuer: on the metadata route this
        // fetches from the host the token names.
        try
        {
            resolution = await _keyResolver.FetchKeysAsync(resolution, ct).ConfigureAwait(false);
        }
        catch (SdJwtProcessingException e)
        {
            return [Error(ErrorCodes.StatusUnresolvable, $"The status list signer's key could not be resolved: {e.Message}")];
        }

        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(statusListJwt, new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            RequireSignedTokens = true,
            IssuerSigningKeys = resolution.Keys,
            TryAllIssuerSigningKeys = true,
        }).ConfigureAwait(false);

        if (!validation.IsValid)
        {
            return [Error(ErrorCodes.StatusInvalid, "The status list token signature does not verify.")];
        }

        // SPEC: §8.3 — sub MUST equal the uri referenced by the credential.
        if (!token.TryGetClaim("sub", out var subClaim) || !string.Equals(subClaim.Value, uri, StringComparison.Ordinal))
        {
            return [Error(ErrorCodes.StatusInvalid, "The status list token sub does not match the referenced uri.")];
        }

        // Read from the JSON itself rather than from the handler's claims, which turn a string "300.5" and the
        // number 300.5 into the same text: §5.1 says what JSON type each claim is, and §8.3 step 4 says "All
        // existing claims in the Status List Token MUST be checked according to the rules in Section 5.1".
        // Parsed as the issuer-signed payload is, so a repeated status_list or bits has no meaning to pick.
        using var payloadDoc = ParseStrict(token.EncodedPayload);
        if (payloadDoc is null)
        {
            return [Error(ErrorCodes.StatusInvalid, $"The status list token payload is not JSON with {StrictJson.Accepts}.")];
        }

        var claims = payloadDoc.RootElement;

        // SPEC: §5.1 — iat is REQUIRED, and §8.3 step 3b says to "Check for the existence of the required claims".
        if (!claims.TryGetProperty("iat", out var iat))
        {
            return [Error(ErrorCodes.StatusInvalid, "The status list token lacks the required iat claim.")];
        }

        // iat, exp and nbf are NumericDates (RFC 7519 section 2), so JSON numbers. A string is refused rather than
        // read, which the handler's claims would do.
        var hasExp = claims.TryGetProperty("exp", out var exp);
        var hasNbf = claims.TryGetProperty("nbf", out var nbf);
        var expiry = default(DateTimeOffset);
        var notBefore = default(DateTimeOffset);
        if (!UnixTime.TryFromNumericDate(iat, out _)
            || (hasExp && !UnixTime.TryFromNumericDate(exp, out expiry))
            || (hasNbf && !UnixTime.TryFromNumericDate(nbf, out notBefore)))
        {
            return [Error(ErrorCodes.StatusInvalid, "The status list token carries an iat, exp or nbf that is not a number.")];
        }

        // SPEC: §5.1 — ttl, if present, "MUST be a positive number encoded in JSON as a number". Refused
        // otherwise, as the mdoc path refuses a non-positive one. A fractional one is a number like any other.
        long? ttlSeconds = null;
        if (claims.TryGetProperty("ttl", out var ttl))
        {
            if (!TryReadPositiveSeconds(ttl, out var seconds))
            {
                return [Error(ErrorCodes.StatusInvalid, "The status list token's ttl is not a positive number.")];
            }

            ttlSeconds = seconds;
        }

        // SPEC: §8.3 — when exp is present, an expired status list token MUST be rejected.
        var now = _clock.GetUtcNow();
        DateTimeOffset? expiresAt = hasExp ? expiry : null;
        if (hasExp && now - _clockSkew >= expiry)
        {
            return [Error(ErrorCodes.StatusUnresolvable, "The status list token is expired; current status is unknown.")];
        }

        // SPEC: §5.1 — "Relying Parties MUST reject JWTs that are not valid in all other respects per "JSON Web
        // Token (JWT)" [RFC7519]", and RFC 7519 section 4.1.5 does not accept a token before its nbf. Lifetime
        // validation is off above, so it is checked here, answered as the mdoc path answers a list not valid yet.
        if (hasNbf && now + _clockSkew < notBefore)
        {
            return [Error(ErrorCodes.StatusUnresolvable, "The status list token is not valid yet; current status is unknown.")];
        }

        // SPEC: §4.2 — status_list: { "bits": 1|2|4|8, "lst": base64url(zlib-deflate(bytes)) }. The kinds are
        // checked first because JsonElement throws when asked for a property of a non-object or a number of a
        // non-number, and that throw would answer structure_invalid for the whole credential.
        if (!claims.TryGetProperty("status_list", out var statusListProp)
            || statusListProp.ValueKind != JsonValueKind.Object
            || !statusListProp.TryGetProperty("bits", out var bitsProp)
            || !statusListProp.TryGetProperty("lst", out var lstProp)
            || bitsProp.ValueKind != JsonValueKind.Number
            || !bitsProp.TryGetInt32(out var bits)
            || !StatusListValues.IsAllowedBits(bits)
            || lstProp.ValueKind != JsonValueKind.String)
        {
            return [Error(ErrorCodes.StatusInvalid, "The status list token carries no valid status_list claim.")];
        }

        byte[] compressed;
        try
        {
            compressed = Base64UrlEncoder.DecodeBytes(lstProp.GetString()!);
        }
        catch (FormatException)
        {
            return [Error(ErrorCodes.StatusInvalid, "The status list bitstring could not be decompressed.")];
        }

        var (decompressed, decompressFailure) = await StatusListValues.DecompressAsync(compressed, ct).ConfigureAwait(false);
        if (decompressed is null)
        {
            return [decompressFailure!];
        }

        CacheList(uri, bits, decompressed, ttlSeconds, expiresAt);
        return StatusListValues.Evaluate(bits, decompressed, idx);
    }

    /// <summary>
    /// Caches the validated, decompressed list. Lifetime is the configured cache duration, shortened
    /// by the token's <c>ttl</c> claim (the issuer's cache ceiling, SPEC §8.3 step 4d and §13.7) and
    /// capped by its <c>exp</c>. A non-positive lifetime disables caching for this list.
    /// </summary>
    private void CacheList(
        string uri, int bits, byte[] list, long? ttlSeconds, DateTimeOffset? expiresAt)
    {
        var now = _clock.GetUtcNow();
        var until = StatusListValues.CacheUntil(now, _cacheDuration, ttlSeconds, expiresAt);
        _cache.Set(uri, new CachedList(bits, list), until, now);
    }

    /// <summary>
    /// The whole seconds of a ttl that is a positive JSON number. The sign and zero are read from the number's
    /// own text, because a double cannot hold every number JSON can write: 1e-400 is positive but reads as 0,
    /// so it caches nothing. A number past what a double holds, such as 1e400, never gets here, because
    /// <see cref="StrictJson"/> refuses the token first; the infinity branch reads one as the longest time.
    /// </summary>
    private static bool TryReadPositiveSeconds(JsonElement value, out long seconds)
    {
        seconds = 0;
        if (value.ValueKind != JsonValueKind.Number)
        {
            return false;
        }

        var text = value.GetRawText();
        var mantissa = text.Split('e', 'E')[0];
        if (text.StartsWith('-') || mantissa.All(c => c is '0' or '.'))
        {
            return false;
        }

        var parsed = value.TryGetDouble(out var d) ? d : double.PositiveInfinity;
        seconds = !double.IsFinite(parsed) || parsed >= long.MaxValue ? long.MaxValue : (long)Math.Floor(parsed);
        return true;
    }

    // Null for a payload StrictJson refuses, trailing content after the JSON value included. The JsonWebToken
    // constructor has already decoded this segment, so a FormatException is not expected; it is caught anyway,
    // so that a decoder disagreement answers status_invalid rather than escaping the status check.
    private static JsonDocument? ParseStrict(string encodedPayload)
    {
        try
        {
            return StrictJson.ParseDocument(Base64UrlEncoder.DecodeBytes(encodedPayload));
        }
        catch (Exception e) when (e is JsonException or FormatException)
        {
            return null;
        }
    }

    private static VerificationError Error(string code, string message) => new() { Code = code, Message = message };
}
