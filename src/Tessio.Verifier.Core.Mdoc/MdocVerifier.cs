using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Verifies an mdoc presentation (<c>mso_mdoc</c>, ISO/IEC 18013-5 over OpenID4VP Annex B.2):
/// DeviceResponse decoding, issuerAuth signature via the x5chain Document Signer certificate,
/// MSO validity window, per-item digest checks and IACA trust through
/// <see cref="ITrustListResolver"/>. Structural failures fail fast; policy failures accumulate
/// into <see cref="VerificationResult.Errors"/> with stable codes.
/// </summary>
/// <remarks>
/// Device authentication verifies the holder's signature over the OpenID4VP session transcript
/// (Annex B.2.6.1), built from the context's client_id, nonce, encryption key thumbprint and
/// response_uri. Required by default (<see cref="MdocVerifierOptions.RequireDeviceAuth"/>).
/// <para>
/// An MSO that carries a <c>status</c> element has its revocation checked, through a status list or an
/// identifier list, unless <see cref="MdocVerifierOptions.CheckStatus"/> is off.
/// </para>
/// </remarks>
public sealed partial class MdocVerifier
{
    /// <summary>The OpenID4VP credential format identifier this verifier accepts.</summary>
    public const string Format = "mso_mdoc";

    private static readonly HttpClient DefaultHttpClient = OutboundFetch.CreateClient();

    private readonly ITrustListResolver _trustListResolver;
    private readonly MdocVerifierOptions _options;
    private readonly TimeProvider _clock;
    private readonly MsoRevocationChecker _revocation;
    private readonly CertificateUrlFetcher? _x5u;

    /// <summary>Creates a verifier.</summary>
    /// <param name="trustListResolver">
    /// Trust seam deciding whether the Document Signer chain anchors on a trusted IACA root. The
    /// issuer identifier passed to it is the Document Signer certificate subject. It is also asked about an
    /// MSO revocation list's anchor, which it must place on the same anchor as the Document Signer, unless the
    /// MSO reference names the certificate itself (see <see cref="MdocVerifierOptions.CheckStatus"/>).
    /// </param>
    /// <param name="options">Policy options; defaults match the SD-JWT verifier.</param>
    /// <param name="clock">Time source for the MSO validity window; system clock when null.</param>
    /// <param name="httpClient">
    /// HTTP client for MSO revocation lists, and for the Document Signer certificate an issuerAuth names by
    /// <c>x5u</c> when it carries no <c>x5chain</c> and <see cref="MdocVerifierOptions.ResolveX5u"/> is on. Every
    /// fetch, on any client, has a deadline and a size limit.
    /// When null, a shared default also refuses non-public addresses and redirects, and ignores the process
    /// proxy. A client supplied here gets none of those three, so it must enforce them itself.
    /// </param>
    public MdocVerifier(
        ITrustListResolver trustListResolver,
        MdocVerifierOptions? options = null,
        TimeProvider? clock = null,
        HttpClient? httpClient = null)
    {
        ArgumentNullException.ThrowIfNull(trustListResolver);
        _trustListResolver = trustListResolver;
        _options = options ?? new MdocVerifierOptions();
        _clock = clock ?? TimeProvider.System;
        _revocation = new MsoRevocationChecker(
            httpClient ?? DefaultHttpClient, _trustListResolver, _clock, _options.ClockSkew, _options.StatusListCacheDuration);
        _x5u = _options.ResolveX5u ? new CertificateUrlFetcher(httpClient ?? DefaultHttpClient, _clock) : null;
    }

    /// <summary>Creates a verifier. Kept so code compiled against earlier versions still binds.</summary>
    /// <param name="trustListResolver">See the four-parameter constructor.</param>
    /// <param name="options">Policy options; defaults when null.</param>
    /// <param name="clock">Time source; system clock when null.</param>
    public MdocVerifier(ITrustListResolver trustListResolver, MdocVerifierOptions? options, TimeProvider? clock)
        : this(trustListResolver, options, clock, httpClient: null)
    {
    }

    /// <summary>Verifies one presented mdoc.</summary>
    public async Task<VerificationResult> VerifyAsync(
        PresentedCredential credential, MdocVerificationContext context, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(context);

        try
        {
            return await VerifyCoreAsync(credential, context, ct).ConfigureAwait(false);
        }
        catch (MdocProcessingException e)
        {
            return Failure(e.Code, e.Message);
        }
        catch (System.Security.Cryptography.CryptographicException e)
        {
            // Contract-level net: platform crypto layers throw OS-specific subtypes on malformed
            // key material. Verification returns a result; it never throws on bad input.
            return Failure(MdocErrorCodes.StructureInvalid, $"The presentation carries unusable cryptographic material: {e.Message}");
        }
    }

    private async Task<VerificationResult> VerifyCoreAsync(
        PresentedCredential credential, MdocVerificationContext context, CancellationToken ct)
    {
        if (!string.Equals(credential.Format, Format, StringComparison.Ordinal))
        {
            return Failure(MdocErrorCodes.FormatUnsupported, $"Format '{credential.Format}' is not '{Format}'.");
        }

        var response = DeviceResponseParser.Parse(credential.RawValue);
        if (response.Status != 0)
        {
            return Failure(MdocErrorCodes.StructureInvalid, $"The DeviceResponse status is {response.Status}, not OK (0).");
        }

        if (response.Documents.Count == 0 && response.HasZkDocuments)
        {
            // Its own code, not the generic structure error below: an operator must be able to tell an
            // answer this verifier is not set up to check from a malformed one. Without a proof verifier the
            // zkDocuments entries are not parsed, so nothing here says they are well formed.
            return _options.ZkProofVerifier is { } zk
                ? await VerifyZkAsync(response, context, zk, ct).ConfigureAwait(false)
                : Failure(MdocErrorCodes.ZkPresentationUnsupported,
                    "The DeviceResponse carries zero knowledge presentations (zkDocuments) and no documents; zero knowledge presentations are not verified.");
        }

        if (response.Documents.Count != 1)
        {
            // SPEC: HAIP — one DeviceResponse per DCQL query; multi-document responses are a later milestone.
            return Failure(MdocErrorCodes.StructureInvalid,
                $"Expected exactly one document in the DeviceResponse, found {response.Documents.Count}.");
        }

        var document = response.Documents[0];

        // Structural: issuerAuth signature and Document Signer key (fails fast on error).
        var resolution = await IssuerAuthVerifier.VerifyAsync(document.IssuerAuth, _x5u, ct).ConfigureAwait(false);
        var mso = DeviceResponseParser.ParseMso(document.IssuerAuth);

        // Policy checks accumulate.
        List<VerificationError> errors = [];

        if (context.ExpectedDocType is { } expected && !string.Equals(document.DocType, expected, StringComparison.Ordinal))
        {
            errors.Add(new VerificationError
            {
                Code = MdocErrorCodes.DocTypeMismatch,
                Message = $"The document's docType '{document.DocType}' does not match the requested '{expected}'.",
            });
        }

        var now = _clock.GetUtcNow();
        if (now + _options.ClockSkew < mso.ValidFrom)
        {
            errors.Add(new VerificationError
            {
                Code = MdocErrorCodes.CredentialNotYetValid,
                Message = $"The MSO is not valid before {mso.ValidFrom:o}.",
            });
        }

        if (now - _options.ClockSkew >= mso.ValidUntil)
        {
            errors.Add(new VerificationError
            {
                Code = MdocErrorCodes.CredentialExpired,
                Message = $"The MSO expired at {mso.ValidUntil:o}.",
            });
        }

        errors.AddRange(DigestVerifier.Verify(document, mso));
        errors.AddRange(VerifyDeviceAuth(document, mso, context));

        var (trust, trustFailure) = await TrustSeam.ResolveAsync(
            _trustListResolver, resolution.Issuer, resolution.CertificateChain, ct).ConfigureAwait(false);
        if (!trust.Trusted)
        {
            errors.Add(trustFailure ?? TrustSeam.Refusal(trust, "The Document Signer does not chain to a trusted IACA root."));
        }

        // SPEC: draft-ietf-oauth-status-list-20 section 8.3, the status is evaluated only for a credential
        // that is otherwise valid, and its list is not fetched for one that is not, the use case requiring nothing more. Untrusted counts as not
        // valid: the uri is the credential's own, and an untrusted credential fails whatever its list says.
        if (_options.CheckStatus && errors.Count == 0 && mso.StatusEncoded is { } status)
        {
            errors.AddRange(await _revocation.CheckAsync(
                status, new MsoRevocationTrust.Credential(resolution.CertificateChain, trust), ct).ConfigureAwait(false));
        }

        var issuer = IssuerOf(resolution.Issuer, trust);

        // CredentialType on both branches. For mdoc it is the docType, which the document declares and
        // parsing has already established here, so unlike the SD-JWT VC path there is no case where an
        // issuer is known and the type is not.
        if (errors.Count > 0)
        {
            return VerificationResult.Invalid(errors, issuer) with { CredentialType = document.DocType };
        }

        // Verified in full, its chain trusted: only now is an x5u resource worth keeping.
        if (resolution.FetchedX5u is { } fetched)
        {
            _x5u?.Remember(fetched);
        }

        return new VerificationResult
        {
            IsValid = true,
            DisclosedClaims = BuildClaims(document),
            Issuer = issuer,
            Errors = [],
            CredentialType = document.DocType,
        };
    }

    private List<VerificationError> VerifyDeviceAuth(
        ParsedDocument document, MobileSecurityObject mso, MdocVerificationContext context)
    {
        if (!_options.RequireDeviceAuth && document.DeviceSigned is null)
        {
            return [];
        }

        if (context.SessionTranscript is { } externalTranscript)
        {
            return DeviceAuthVerifier.Verify(document, mso, externalTranscript);
        }

        if (context.ClientId is null || context.Nonce is null || context.ResponseUri is null)
        {
            return [new VerificationError
            {
                Code = MdocErrorCodes.DeviceAuthInvalid,
                Message = "The verification context lacks the session transcript inputs "
                    + "(ClientId, Nonce, ResponseUri); device authentication cannot be verified.",
            }];
        }

        var sessionTranscript = SessionTranscriptBuilder.Build(
            context.ClientId, context.Nonce, context.EncryptionKeyThumbprint, context.ResponseUri);
        return DeviceAuthVerifier.Verify(document, mso, sessionTranscript);
    }

    // The trust details are carried through on BOTH verdicts, not only the passing one. A refused
    // presentation is the one someone comes back to ask about, and the list that refused it is the answer.
    private static IssuerInfo IssuerOf(string identifier, IssuerTrustStatus trust) => new()
    {
        Identifier = identifier,
        Trusted = trust.Trusted,
        KeyResolutionMethod = "x5c",
        TrustListSource = trust.TrustListSource,
        TrustAnchorSubject = trust.TrustAnchorSubject,
        TrustAnchorThumbprint = trust.TrustAnchorThumbprint,
    };

    /// <summary>Disclosed claims keyed by namespace, each value a map of element name to value.</summary>
    private static Dictionary<string, object> BuildClaims(ParsedDocument document)
    {
        Dictionary<string, object> claims = new(StringComparer.Ordinal);
        foreach (var (ns, items) in document.NameSpaces)
        {
            Dictionary<string, object?> elements = new(StringComparer.Ordinal);
            foreach (var item in items)
            {
                elements[item.ElementIdentifier] = item.ElementValue;
            }

            claims[ns] = elements;
        }

        return claims;
    }

    private static VerificationResult Failure(string code, string message) => VerificationResult.Invalid(
        new VerificationError { Code = code, Message = message },
        new IssuerInfo { Identifier = "unknown", Trusted = false, KeyResolutionMethod = "x5c" });
}
