using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core;

/// <summary>
/// Verifies SD-JWT VC credentials (<c>dc+sd-jwt</c>): issuer signature (JWT VC Issuer Metadata or
/// X.509 <c>x5c</c> key resolution), selective-disclosure reconstruction, Key Binding, time claims,
/// and issuer trust via <see cref="ITrustListResolver"/>.
/// </summary>
/// <remarks>
/// Structural violations (malformed credential, failed signature, RFC 9901 MUST-reject rules) yield a
/// single-error invalid result; policy failures (expiry, nonce/audience, trust, vct) are accumulated
/// so callers see every problem at once. Nothing the credential names is fetched for an untrusted
/// issuer: its status list is never requested, and on the metadata route trust is decided before the key
/// is, so that credential fails with the trust error alone. All cryptography is delegated to
/// Microsoft.IdentityModel and <c>System.Security.Cryptography</c> — nothing custom.
/// </remarks>
public sealed class SdJwtVcVerifier : ICredentialVerifier
{
    private static readonly HttpClient DefaultHttpClient = OutboundFetch.CreateClient();

    private readonly ITrustListResolver _trustListResolver;
    private readonly SdJwtVcVerifierOptions _options;
    private readonly IssuerKeyResolver _keyResolver;
    private readonly StatusListChecker _statusChecker;
    private readonly TimeProvider _clock;

    /// <summary>Creates a verifier.</summary>
    /// <param name="trustListResolver">Trust seam deciding whether the issuer is trusted.</param>
    /// <param name="options">Policy options; defaults are HAIP-aligned.</param>
    /// <param name="httpClient">
    /// HTTP client for JWT VC Issuer Metadata, issuer key sets, status lists, and the signing certificate an
    /// issuer JWT names by <c>x5u</c> when <see cref="SdJwtVcVerifierOptions.ResolveX5u"/> is on. Every fetch, on any
    /// client, has a deadline and a size limit. When null, a shared default also refuses non-public
    /// addresses and redirects, and ignores the process proxy. A client supplied here gets none of those
    /// three, so it must enforce them itself.
    /// </param>
    /// <param name="clock">Time source for exp/nbf evaluation; system clock when null.</param>
    public SdJwtVcVerifier(
        ITrustListResolver trustListResolver,
        SdJwtVcVerifierOptions? options = null,
        HttpClient? httpClient = null,
        TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(trustListResolver);
        _trustListResolver = trustListResolver;
        _options = options ?? new SdJwtVcVerifierOptions();
        _keyResolver = new IssuerKeyResolver(
            httpClient ?? DefaultHttpClient,
            _options.ResolveX5u ? new CertificateUrlFetcher(httpClient ?? DefaultHttpClient, clock ?? TimeProvider.System) : null);
        _clock = clock ?? TimeProvider.System;
        // The SAME trust seam the credential's own chain goes through. A status list token is a signed
        // statement about this credential's validity, so it deserves the deployment's trust rules rather
        // than a rule of its own.
        _statusChecker = new StatusListChecker(
            httpClient ?? DefaultHttpClient, _keyResolver, _trustListResolver, _clock,
            _options.ClockSkew, _options.StatusListCacheDuration);
    }

    /// <inheritdoc />
    public Task<VerificationResult> VerifyAsync(
        PresentedCredential credential,
        VerificationContext context,
        CancellationToken ct = default) => VerifyAsync(credential, context, transactionData: null, ct);

    /// <summary>
    /// Verifies a credential that must additionally acknowledge transaction data: the KB-JWT's
    /// <c>transaction_data_hashes</c> must match <paramref name="transactionData"/> exactly.
    /// </summary>
    // SPEC: OpenID4VP 1.0 Annex B.3.3.1.
    public async Task<VerificationResult> VerifyAsync(
        PresentedCredential credential,
        VerificationContext context,
        TransactionDataExpectation? transactionData,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(context);

        try
        {
            return await VerifyCoreAsync(credential, context, transactionData, ct).ConfigureAwait(false);
        }
        catch (SdJwtProcessingException e)
        {
            return Invalid(e.ToError());
        }
        catch (InvalidOperationException e)
        {
            // Contract-level net: IdentityModel's claim accessors throw lazily on payloads whose
            // strings are not valid UTF-8. Verification returns a result; it never throws on input.
            return Invalid(new VerificationError
            {
                Code = ErrorCodes.StructureInvalid,
                Message = $"The credential payload is malformed: {e.Message}",
            });
        }
        catch (System.Security.Cryptography.CryptographicException e)
        {
            // Same net for platform crypto layers rejecting malformed key material (OS-specific subtypes).
            return Invalid(new VerificationError
            {
                Code = ErrorCodes.IssuerKeyUnresolvable,
                Message = $"The credential carries unusable cryptographic material: {e.Message}",
            });
        }
    }

    private async Task<VerificationResult> VerifyCoreAsync(
        PresentedCredential credential,
        VerificationContext context,
        TransactionDataExpectation? transactionData,
        CancellationToken ct)
    {
        // 1. Format identifier. SPEC: OpenID4VP/SD-JWT VC format is "dc+sd-jwt" (not "vc+sd-jwt").
        var formatOk = credential.Format == SdJwtConstants.Typ
                       || (_options.AcceptLegacyVcSdJwtTyp && credential.Format == SdJwtConstants.LegacyTyp);
        if (!formatOk)
        {
            throw new SdJwtProcessingException(
                ErrorCodes.FormatUnsupported, $"Unsupported credential format '{credential.Format}'; expected '{SdJwtConstants.Typ}'.");
        }

        // 2. Compact-serialization structure.
        if (!SdJwtPresentation.TryParse(credential.RawValue, out var presentation))
        {
            throw new SdJwtProcessingException(
                ErrorCodes.StructureInvalid, "The credential is not a valid SD-JWT compact serialization (<jwt>~<disclosures…>~[kb-jwt]).");
        }

        if (!CompactJwt.TryParse(presentation.IssuerJwt, out var issuerJwt))
        {
            throw new SdJwtProcessingException(ErrorCodes.StructureInvalid, "The issuer-signed JWT is malformed.");
        }

        // 3. typ header. SPEC: draft-ietf-oauth-sd-jwt-vc-13 §3.2.1.
        var typOk = string.Equals(issuerJwt.Typ, SdJwtConstants.Typ, StringComparison.Ordinal)
                    || (_options.AcceptLegacyVcSdJwtTyp
                        && string.Equals(issuerJwt.Typ, SdJwtConstants.LegacyTyp, StringComparison.Ordinal));
        if (!typOk)
        {
            throw new SdJwtProcessingException(
                ErrorCodes.TypInvalid, $"Issuer JWT typ is '{issuerJwt.Typ}'; expected '{SdJwtConstants.Typ}'.");
        }

        // 4. Algorithm allowlist (asymmetric only; rejects "none" and HMAC outright).
        if (!SdJwtConstants.AllowedAlgorithms.Contains(issuerJwt.Alg))
        {
            throw new SdJwtProcessingException(
                ErrorCodes.AlgorithmNotAllowed, $"Issuer JWT algorithm '{issuerJwt.Alg}' is not permitted.");
        }

        // 5. The issuer, from the credential alone (x5c chain, x5u with its x5t#S256, or iss for JWT VC Issuer Metadata).
        var identified = _keyResolver.Identify(issuerJwt);

        // 6. On the metadata route, issuer trust BEFORE the key is fetched. The key lives on the host
        // the credential names, so only an issuer the deployment trusts has it requested. The seam is
        // asked with iss and an empty chain, which it can answer from its own configuration. On the x5c
        // route the key is already in hand, so trust is asked below, after the checks that need no fetch.
        // An x5u is fetched below before trust is known, because trust on the X.509 route is judged on the
        // chain it returns. Its fetch has the same bounds as every other, and the same address check on the
        // default client.
        IssuerTrustStatus? trust = null;
        VerificationError? trustFailure = null;
        if (identified.Method == SdJwtConstants.KeyResolutionMetadata)
        {
            (trust, trustFailure) = await TrustSeam.ResolveAsync(
                _trustListResolver, identified.Issuer, identified.CertificateChain, ct).ConfigureAwait(false);
            if (!trust.Trusted)
            {
                // The trust error alone: every later check needs the key this withholds.
                return Invalid(trustFailure ?? Untrusted(trust, identified.Issuer), IssuerInfoFrom(identified, trust));
            }
        }

        var resolution = await _keyResolver.FetchKeysAsync(identified, ct).ConfigureAwait(false);

        // 7. Issuer signature.
        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(presentation.IssuerJwt, new TokenValidationParameters
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
            return Invalid(
                new VerificationError { Code = ErrorCodes.SignatureInvalid, Message = "The issuer signature does not verify against the resolved key." },
                new IssuerInfo { Identifier = resolution.Issuer, ClaimedIssuer = resolution.ClaimedIssuer, Trusted = false, KeyResolutionMethod = resolution.Method });
        }

        // 8. Payload reconstruction per RFC 9901 §7.1 (throws on MUST-reject violations).
        JsonObject payload;
        try
        {
            payload = (JsonObject)StrictJson.Parse(Base64UrlEncoder.DecodeBytes(issuerJwt.EncodedPayload))!;
        }
        catch (JsonException)
        {
            throw new SdJwtProcessingException(
                ErrorCodes.StructureInvalid, $"The issuer-signed payload is not JSON with {StrictJson.Accepts}.");
        }

        var vctIsPlain = payload.ContainsKey("vct");
        var processed = DisclosureProcessor.Process(payload, presentation.Disclosures);

        // 9. Policy checks, accumulated so the caller sees every failure at once.
        var errors = new List<VerificationError>();
        var credentialType = ReadVct(processed);
        CheckVct(credentialType, vctIsPlain, context, errors);
        CheckTimeClaims(processed, errors);
        await CheckKeyBindingAsync(presentation, processed, context, transactionData, errors, ct).ConfigureAwait(false);

        // Issuer trust on the x5c route: after every check that needs nothing but the credential, and before
        // the status list, which is fetched only for a trusted credential that passed them all.
        if (trust is null)
        {
            (trust, trustFailure) = await TrustSeam.ResolveAsync(
                _trustListResolver, resolution.Issuer, resolution.CertificateChain, ct).ConfigureAwait(false);
        }

        var issuerInfo = IssuerInfoFrom(resolution, trust);

        // SPEC: draft-ietf-oauth-status-list-20 §8.3, enforce the status claim when present (revocation), and
        // "If the validation procedures for the Referenced Token determine it is invalid, further procedures
        // regarding Status List MUST NOT be performed, e.g. fetching a Status List Token, unless the Referenced
        // Token procedures or the use case require further evaluation". Verifying a presentation requires
        // nothing more, so the list is fetched only for a credential that is otherwise valid, as on the mdoc
        // path. Untrusted counts as not valid: the uri is the credential's own, and an untrusted
        // credential fails whatever its status says.
        if (_options.CheckStatus && trust.Trusted && errors.Count == 0)
        {
            errors.AddRange(await _statusChecker.CheckAsync(processed, ct).ConfigureAwait(false));
        }

        if (!trust.Trusted)
        {
            errors.Add(trustFailure ?? Untrusted(trust, resolution.Issuer));
        }

        // A claim nested deeper than the result's readers can carry is refused rather than returned. Recursive
        // disclosures (RFC 9901 section 7.1) let one disclosure's value hold another's, so the depth of a disclosed
        // value is not bounded by the depth any one JSON text is parsed at, and a value deep enough fails whatever
        // later serializes the result, such as a session status page. The bound is the one mdoc element values
        // already have (CborValueConverter), far beyond any credential type in use.
        if (JsonValueConverter.DeeperThanAllowed(processed))
        {
            errors.Add(new VerificationError
            {
                Code = ErrorCodes.StructureInvalid,
                Message = $"A disclosed claim nests deeper than {JsonValueConverter.MaxDepth} levels.",
            });
        }

        // CredentialType on BOTH branches. The failing one is the more useful of the two: a caller
        // looking at a vct mismatch wants to know what actually arrived, and every earlier return in
        // this method leaves it null because the payload had not been read yet.
        if (errors.Count > 0)
        {
            return Invalid(errors, issuerInfo) with { CredentialType = credentialType };
        }

        // Verified in full, its chain trusted: only now is an x5u resource worth keeping.
        _keyResolver.Remember(resolution);
        return new VerificationResult
            {
                IsValid = true,
                DisclosedClaims = ExtractClaims(processed),
                Issuer = issuerInfo,
                Errors = [],
                CredentialType = credentialType,
            };
    }

    /// <summary>
    /// The credential's own declared type, or null when it declares none usable.
    /// </summary>
    /// <remarks>
    /// SPEC: draft-ietf-oauth-sd-jwt-vc-13 §3.2.2.2 lists vct among the registered JWT claims that
    /// "MUST NOT be included in the Disclosures, i.e., cannot be selectively disclosed", and marks it
    /// REQUIRED. The section number moved between drafts, so the draft is named with it.
    /// One reader, because two callers now want this value: the check below, and the result, which
    /// reports what was presented. Read twice, the value the caller is told about could differ from the
    /// value that was actually judged.
    /// </remarks>
    private static string? ReadVct(JsonObject processed) =>
        processed.TryGetPropertyValue("vct", out var vctNode) && vctNode?.GetValueKind() == JsonValueKind.String
            ? vctNode.GetValue<string>()
            : null;

    private static void CheckVct(
        string? vct, bool vctIsPlain, VerificationContext context, List<VerificationError> errors)
    {
        if (vct is null || !vctIsPlain)
        {
            errors.Add(new VerificationError { Code = ErrorCodes.VctMissing, Message = "The credential carries no plain vct claim." });
            return;
        }

        // SPEC: OpenID4VP 1.0 §8.6 requires the Verifier to "validate that the returned Credential(s)
        // meet all criteria defined in the query", and §B.3.5 states that criterion as vct_values, "a
        // non-empty array of strings that specifies allowed values for the type of the requested
        // Verifiable Credential". So this is membership of the requested set, not equality with one
        // member of it. Ordinal either way: a vct is an exact identifier, not a display string.
        var accepted = AcceptedVctValues(context);
        if (accepted.Count == 0 || accepted.Contains(vct, StringComparer.Ordinal))
        {
            return;
        }

        errors.Add(new VerificationError
        {
            Code = ErrorCodes.VctMismatch,
            Message = $"The credential type is '{vct}'; this verification expects {Expectation(accepted)}.",
        });
    }

    /// <summary>
    /// Every credential type the context accepts, reading both of its properties. One reader, so the
    /// rule joining them cannot be applied one way here and another way in the next caller.
    /// </summary>
    private static IReadOnlyList<string> AcceptedVctValues(VerificationContext context)
    {
        if (context.ExpectedVctValues is not { Count: > 0 } values)
        {
            return context.ExpectedVct is null ? [] : [context.ExpectedVct];
        }

        return context.ExpectedVct is null || values.Contains(context.ExpectedVct, StringComparer.Ordinal)
            ? values
            : [context.ExpectedVct, .. values];
    }

    /// <summary>
    /// The accepted types, for the mismatch message. A single type keeps the wording this message has
    /// always had, because operators read it out of logs.
    /// </summary>
    private static string Expectation(IReadOnlyList<string> accepted) =>
        accepted.Count == 1
            ? $"'{accepted[0]}'"
            : $"one of {string.Join(", ", accepted.Select(static value => $"'{value}'"))}";

    private void CheckTimeClaims(JsonObject processed, List<VerificationError> errors)
    {
        var now = _clock.GetUtcNow();

        if (ReadUnixTime(processed, "exp", errors) is { } exp && now - _options.ClockSkew >= exp)
        {
            errors.Add(new VerificationError { Code = ErrorCodes.CredentialExpired, Message = $"The credential expired at {exp:O}." });
        }

        if (ReadUnixTime(processed, "nbf", errors) is { } nbf && now + _options.ClockSkew < nbf)
        {
            errors.Add(new VerificationError { Code = ErrorCodes.CredentialNotYetValid, Message = $"The credential is not valid before {nbf:O}." });
        }
    }

    private async Task CheckKeyBindingAsync(
        SdJwtPresentation presentation,
        JsonObject processed,
        VerificationContext context,
        TransactionDataExpectation? transactionData,
        List<VerificationError> errors,
        CancellationToken ct)
    {
        if (presentation.KbJwt is null)
        {
            if (_options.RequireKeyBinding)
            {
                errors.Add(new VerificationError
                {
                    Code = ErrorCodes.KeyBindingMissing,
                    Message = "The presentation carries no KB-JWT, but key binding is required.",
                });
            }

            if (transactionData is not null)
            {
                // SPEC: OpenID4VP 1.0 Annex B.3.3 — the transaction data mechanism requires
                // cryptographic holder binding; without a KB-JWT the acknowledgment cannot exist.
                errors.Add(new VerificationError
                {
                    Code = ErrorCodes.TransactionDataMissing,
                    Message = "The request carried transaction_data, but the presentation has no KB-JWT to acknowledge it.",
                });
            }

            return;
        }

        // SPEC: RFC 9901 §4.1.2 / §7.3 — the holder key comes from the credential's cnf claim (jwk).
        var jwkNode = processed.TryGetPropertyValue("cnf", out var cnfNode) && cnfNode is JsonObject cnf
            ? cnf.TryGetPropertyValue("jwk", out var jwk) ? jwk as JsonObject : null
            : null;

        if (jwkNode is null)
        {
            errors.Add(new VerificationError
            {
                Code = ErrorCodes.ConfirmationKeyMissing,
                Message = "A KB-JWT was presented but the credential carries no cnf.jwk holder key.",
            });
            return;
        }

        SecurityKey holderKey;
        try
        {
            holderKey = JwkKeyMembers.Key(jwkNode.ToJsonString());
        }
        catch (ArgumentException)
        {
            errors.Add(new VerificationError { Code = ErrorCodes.ConfirmationKeyMissing, Message = "The credential's cnf.jwk is not a valid JWK, or names no key." });
            return;
        }

        errors.AddRange(await KeyBindingVerifier.VerifyAsync(
            presentation.KbJwt, holderKey, context, presentation.PresentationWithoutKbJwt,
            _clock.GetUtcNow(), _options.MaxKeyBindingAge, _options.ClockSkew, ct, transactionData).ConfigureAwait(false));
    }

    private static Dictionary<string, object> ExtractClaims(JsonObject processed)
    {
        var claims = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var property in processed)
        {
            if (!SdJwtConstants.NonClaimKeys.Contains(property.Key))
            {
                claims[property.Key] = JsonValueConverter.ToClrValue(property.Value)!;
            }
        }

        return claims;
    }

    // SPEC: RFC 7519 §4.1.4 and §4.1.5, "Its value MUST be a number containing a NumericDate value."
    // Anything else present is refused rather than skipped, since skipping an exp is never expiring.
    private static DateTimeOffset? ReadUnixTime(JsonObject payload, string claim, List<VerificationError> errors)
    {
        if (!payload.TryGetPropertyValue(claim, out var node))
        {
            return null;
        }

        if (!UnixTime.TryFromNumericDate(node, out var date))
        {
            errors.Add(new VerificationError { Code = ErrorCodes.StructureInvalid, Message = $"The {claim} claim is not a NumericDate." });
            return null;
        }

        return date;
    }

    private static IssuerInfo IssuerInfoFrom(IssuerKeyResolution resolution, IssuerTrustStatus trust) => new()
    {
        Identifier = resolution.Issuer,
        ClaimedIssuer = resolution.ClaimedIssuer,
        Trusted = trust.Trusted,
        KeyResolutionMethod = resolution.Method,
        // Carried on both verdicts, as on the mdoc path. On this path the anchor fields are null
        // whenever the key came from issuer metadata, which is the common case here and is the
        // mechanism rather than a gap.
        TrustListSource = trust.TrustListSource,
        TrustAnchorSubject = trust.TrustAnchorSubject,
        TrustAnchorThumbprint = trust.TrustAnchorThumbprint,
    };

    private static VerificationError Untrusted(IssuerTrustStatus trust, string issuer) =>
        TrustSeam.Refusal(trust, $"Issuer '{issuer}' does not chain to a trusted list.");

    private static VerificationResult Invalid(VerificationError error, IssuerInfo? issuer = null) =>
        Invalid([error], issuer);

    private static VerificationResult Invalid(IReadOnlyList<VerificationError> errors, IssuerInfo? issuer = null) =>
        VerificationResult.Invalid(
            errors, issuer ?? new IssuerInfo { Identifier = "unknown", Trusted = false, KeyResolutionMethod = "none" });
}
