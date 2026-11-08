// What belongs in this file: verifying an OpenID4VP response returned through the Digital Credentials API.
// The credential checks are the redirect flow's own (VerifyAgainstAsync in WalletResponseVerifier.cs). What
// differs is where the expectations come from. This transport also adds two checks: the origin against a
// signed request's expected_origins and the response mode against the one asked for.
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Core;
using Tessio.Verifier.Core.Mdoc;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore;

public sealed partial class WalletResponseVerifier
{
    /// <summary>
    /// Whether a stored Digital Credentials API request still carries the DCQL query a response is checked
    /// against, by the same test as <see cref="CanVerify(PresentationRequest)"/>. Call it first and refuse a
    /// request that fails it, for the reasons that method gives.
    /// </summary>
    public static bool CanVerify(DcApiPresentationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return RequestParameters.AreRecoverable(request);
    }

    /// <summary>
    /// Verifies an OpenID4VP response returned through the Digital Credentials API against the request it
    /// answers.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The request is refused before anything is parsed when it can no longer be verified
    /// (<c>request_unverifiable</c>), when it has expired (<c>request_expired</c>) or when <paramref name="origin"/>
    /// is not one of its <see cref="DcApiPresentationRequest.ExpectedOrigins"/> (<c>audience_mismatch</c>).
    /// </para>
    /// <para>
    /// Verifying does not use the request up. The host accepts one answer per request, as the redirect flow's
    /// session store does: a response that verified once verifies again, so a host that does not mark the request
    /// answered accepts a replayed one.
    /// </para>
    /// </remarks>
    /// <param name="request">
    /// The request as it was built and sent, stored whole in the host's own store. It is trusted as given: its origins,
    /// expiry and nonce become the expectations. A signed request's JWS is read without checking its signature
    /// again. Never take it from the page.
    /// </param>
    /// <param name="origin">
    /// The origin of the page that called the API, as the browser serializes it (<c>window.location.origin</c>,
    /// no trailing slash). It must be one the request names; the wallet bound its answer to the origin the browser
    /// gave it, so a page origin reported wrongly fails verification rather than passing it.
    /// </param>
    /// <param name="responseDataJson">The JSON of the <c>data</c> member of the credential the page received.</param>
    /// <param name="responseDecryptionKey">
    /// The private key the request's encryption key pairs with, for a <c>dc_api.jwt</c> response; null for a request
    /// that asked for a cleartext one, which then cannot be answered encrypted.
    /// </param>
    /// <param name="ct">Cancellation.</param>
    /// <returns>The result. A malformed response is <c>response_invalid</c>, not an exception.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="responseDecryptionKey"/> is null for a request that asked for an encrypted response, or a
    /// required argument is null.
    /// </exception>
    public async Task<VerificationResult> VerifyDcApiAsync(
        DcApiPresentationRequest request,
        string origin,
        string responseDataJson,
        SecurityKey? responseDecryptionKey,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(origin);
        ArgumentNullException.ThrowIfNull(responseDataJson);

        // Without the query nothing returned can be checked against what was asked for, and the type checks would
        // be skipped rather than failed (see CanVerify(PresentationRequest)), so the request is refused instead.
        if (!RequestParameters.AreRecoverable(request))
        {
            return Invalid(ErrorCodes.RequestUnverifiable,
                "The stored request no longer states its DCQL query and credential type.");
        }

        // A caller's mistake, not the wallet's, so it is thrown rather than reported as an invalid response.
        if (responseDecryptionKey is null && RequestParameters.AsksForEncryptedResponse(request))
        {
            throw new ArgumentNullException(
                nameof(responseDecryptionKey),
                "The request asked for an encrypted (dc_api.jwt) response; pass the private key its encryption key pairs with.");
        }

        if (_clock.GetUtcNow() > request.ExpiresAt)
        {
            return Invalid(ErrorCodes.RequestExpired, "The response arrived after the request expired.");
        }

        // From the request record, not from the data: an unsigned request may not carry its origins (Appendix A.2),
        // so the record is the one place both kinds name them. SPEC: Appendix A.2, expected_origins: "If the Origin
        // does not match any of the entries in expected_origins, the Wallet MUST return an error." The wallet makes
        // that check for a signed request; making it here holds every request to its origins whatever a wallet did.
        if (!request.ExpectedOrigins.Contains(origin, StringComparer.Ordinal))
        {
            return Invalid(ErrorCodes.AudienceMismatch,
                "The response came through an origin the request does not name.");
        }

        ParsedWalletResponse parsed;
        try
        {
            // No resolver without a key, so an encrypted answer to a cleartext request is reported as having no key
            // configured, rather than as a kid matching no session.
            var parser = ParserFor(
                RequestParameters.TryGetRequestedFormat(request),
                responseDecryptionKey is { } key ? _ => key : null);
            parsed = await parser.ParseDcApiAsync(responseDataJson, ct).ConfigureAwait(false);
        }
        catch (WalletResponseException e)
        {
            return ResponseInvalid(e.Message);
        }

        // A cleartext presentation does not answer a request that asked for encryption, so it is refused, as the
        // redirect callback refuses one. An error response is exempt, as on the redirect path. SPEC: OpenID4VP 1.0
        // Appendix A.4: "Protocol error responses are returned as an object within the data property."
        var askedForEncryption = RequestParameters.AsksForEncryptedResponse(request);
        if (parsed.Error is null && parsed.Encrypted != askedForEncryption)
        {
            return ResponseInvalid(askedForEncryption
                ? "The request asked for an encrypted (dc_api.jwt) response and the wallet answered in the clear."
                : "The request asked for a cleartext (dc_api) response and the wallet answered encrypted.");
        }

        return await VerifyAgainstAsync(() => ExpectationsFor(request, origin, askedForEncryption), parsed, ct)
            .ConfigureAwait(false);
    }

    /// <summary>A Digital Credentials API request's expectations, bound to the origin rather than a client_id.</summary>
    private static Expectations ExpectationsFor(DcApiPresentationRequest request, string origin, bool encrypted) => new(
        request.Nonce,
        // SPEC: OpenID4VP 1.0 Appendix A.4: "The audience for the response (for example, the aud value in a Key
        // Binding JWT) MUST be the Origin, prefixed with origin: ... This is the case even for signed requests."
        // The origin carries no trailing slash, although A.4's example prints one. SPEC: OpenID4VP 1.0 Terminology,
        // Origin: "The web origin is https://verify.example.com".
        $"origin:{origin}",
        queryId => RequestParameters.TryGetExpectedVctValues(request, queryId),
        () => Expectations.TransactionDataOf(RequestParameters.TryGetTransactionData(request)),
        queryId => new MdocVerificationContext
        {
            ExpectedDocType = RequestParameters.TryGetExpectedDocType(request, queryId),
            // SPEC: OpenID4VP 1.0 Annex B.2.6.2: the transcript binds the origin, the nonce and, under
            // dc_api.jwt, the encryption key's thumbprint; under dc_api "the third element MUST be null".
            SessionTranscript = SessionTranscriptBuilder.BuildForDcApi(
                origin,
                request.Nonce,
                encrypted ? RequestParameters.TryGetEncryptionKeyThumbprint(request) : null),
        },
        () => RequestParameters.TryGetAnswerRules(request),
        () => RequestParameters.AsksForSeveralCredentials(request));
}
