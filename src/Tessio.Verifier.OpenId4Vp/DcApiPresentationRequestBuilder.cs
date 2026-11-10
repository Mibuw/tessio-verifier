using System.Text.Json.Nodes;
using Tessio.Verifier.Core;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// Builds OpenID4VP requests for the W3C Digital Credentials API, unsigned or signed.
/// </summary>
/// <remarks>
/// <para>
/// Constructed without signing options it builds unsigned requests only. Constructed with them it builds both,
/// and signs a request whose options name a <see cref="DcApiPresentationRequestOptions.ClientId"/>. Signing
/// shares the redirect flow's signer, so the header and the certificate chain rules are the same for both
/// transports.
/// </para>
/// <para>
/// The page sends what this returns and hands the verifier back the <c>data</c> of the credential it receives,
/// which <see cref="WalletResponseParser.ParseDcApiAsync"/> reads.
/// </para>
/// </remarks>
// SPEC: OpenID4VP 1.0 Appendix A.1 (protocol identifiers), A.2 (parameters), A.3 (signed and unsigned requests).
public sealed class DcApiPresentationRequestBuilder
{
    /// <summary>The protocol identifier of an unsigned request.</summary>
    public const string UnsignedProtocol = "openid4vp-v1-unsigned";

    /// <summary>The protocol identifier of a signed request in JWS Compact Serialization.</summary>
    public const string SignedProtocol = "openid4vp-v1-signed";

    private readonly RequestObjectSigner? _signer;
    private readonly TimeProvider _clock;
    private readonly TimeSpan _defaultLifetime;

    /// <summary>Creates a builder for unsigned requests only.</summary>
    /// <param name="clock">Time source for <see cref="DcApiPresentationRequest.ExpiresAt"/>; the system clock when null.</param>
    public DcApiPresentationRequestBuilder(TimeProvider? clock = null)
    {
        _clock = clock ?? TimeProvider.System;
        _defaultLifetime = PresentationRequestBuilderOptions.StandardRequestLifetime;
    }

    /// <summary>
    /// Creates a builder that signs with <paramref name="signing"/>. Only its signing credentials, certificate
    /// chain, default lifetime and clock are used; the redirect-only members are ignored.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="signing"/> or its credentials are null.</exception>
    /// <exception cref="ArgumentException">The certificate chain breaks a rule, as for <see cref="SignedPresentationRequestBuilder"/>.</exception>
    public DcApiPresentationRequestBuilder(PresentationRequestBuilderOptions signing)
    {
        ArgumentNullException.ThrowIfNull(signing);
        ArgumentNullException.ThrowIfNull(signing.SigningCredentials);
        _signer = new RequestObjectSigner(
            signing.SigningCredentials,
            signing.SigningCertificateChain,
            $"{nameof(signing)}.{nameof(signing.SigningCertificateChain)}",
            signing.AllowSelfSignedSigningCertificate);
        _clock = signing.Clock ?? TimeProvider.System;
        _defaultLifetime = signing.DefaultRequestLifetime;
    }

    /// <summary>Builds the request.</summary>
    /// <exception cref="ArgumentException">
    /// The options name no expected origin or one that is not a serialized origin, lack
    /// <c>vp_formats_supported</c>, ask for an encrypted response without exactly one key or sign under the
    /// <c>origin:</c> prefix.
    /// </exception>
    /// <exception cref="InvalidOperationException">A signed request was asked of a builder with no signing options.</exception>
    public DcApiPresentationRequest Build(DcApiPresentationRequestOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.Nonce, $"{nameof(options)}.{nameof(options.Nonce)}");
        ArgumentException.ThrowIfNullOrWhiteSpace(options.DcqlQueryJson, $"{nameof(options)}.{nameof(options.DcqlQueryJson)}");

        var parameters = new JsonObject
        {
            ["response_type"] = "vp_token",

            // SPEC: Appendix A.2: "The value of the response_mode parameter MUST be dc_api when the response is
            // not encrypted and dc_api.jwt when the response is encrypted".
            ["response_mode"] = options.EncryptedResponse ? "dc_api.jwt" : "dc_api",
            ["nonce"] = options.Nonce,
            ["dcql_query"] = JsonNode.Parse(options.DcqlQueryJson),
        };
        RequestObjectClaims.AddOptionalMembers(
            parameters, options.ClientMetadataJson, options.TransactionDataJson, options.VerifierInfoJson);

        // Each rule below refuses here, where the mistake is made, a request no wallet could answer or no verifier
        // could bind.
        var metadataName = $"{nameof(options)}.{nameof(options.ClientMetadataJson)}";

        // SPEC: OpenID4VP 1.0 §5.1, vp_formats_supported: "REQUIRED when not available to the Wallet via another
        // mechanism." Over this transport there is none: an unsigned request has no client_id, and under an x509
        // client identifier §5.9.3 says "All Verifier metadata other than the public key MUST be obtained from the
        // client_metadata parameter".
        if (parameters["client_metadata"]?["vp_formats_supported"] is not JsonObject)
        {
            throw new ArgumentException(
                "client_metadata with vp_formats_supported is required. Build it with ClientMetadata.Build.", metadataName);
        }

        // SPEC: §8.3: the wallet encrypts to a key from client_metadata.jwks, and "selects the public key to encrypt
        // the Authorization Response". Annex B.2.6.2 then binds the thumbprint "of the Verifier's public key used to
        // encrypt the response" into the transcript. With one key that is the key advertised; with several it is
        // whichever the wallet chose, which the verifier cannot tell, so exactly one is allowed.
        if (options.EncryptedResponse && parameters["client_metadata"]?["jwks"]?["keys"] is not JsonArray { Count: 1 })
        {
            throw new ArgumentException(
                "An encrypted (dc_api.jwt) response needs exactly one encryption key in client_metadata.jwks. Build the "
                + "metadata with one key, or set EncryptedResponse to false.",
                metadataName);
        }

        // The verifier refuses a response from any origin not named here, signed or not, so at least one is needed.
        // Each is checked by the rules the transcripts hold an origin to. A wallet compares expected_origins as strings
        // with the origin the browser hands it and so does the verifier, so one written in another form
        // (upper case, a trailing slash, a default port) would refuse every answer.
        if (options.ExpectedOrigins is not { Count: > 0 } origins)
        {
            throw new ArgumentException(
                "A request needs at least one expected origin: the page origins it may be made from.",
                $"{nameof(options)}.{nameof(options.ExpectedOrigins)}");
        }

        foreach (var origin in origins)
        {
            BrowserOrigin.RequireSerialized(origin);
        }

        var issuedAt = _clock.GetUtcNow();
        var expiresAt = issuedAt + (options.RequestLifetime ?? _defaultLifetime);

        // SPEC: Appendix A.3.1: "The Verifier MAY send all the OpenID4VP request parameters as members in the
        // request member passed to the API." The client_id is absent, as A.2 requires of an unsigned request, and
        // so are the origins: A.2 calls expected_origins "not for use in unsigned requests".
        var data = options.ClientId is null
            ? parameters
            : new JsonObject { ["request"] = Sign(options, options.ClientId, parameters, origins, issuedAt, expiresAt) };

        return new DcApiPresentationRequest
        {
            Protocol = options.ClientId is null ? UnsignedProtocol : SignedProtocol,
            DataJson = data.ToJsonString(JsonDefaults.Relaxed),
            Nonce = options.Nonce,
            ExpectedOrigins = [.. origins],
            ExpiresAt = expiresAt,
        };
    }

    /// <summary>The signed request object, as the value of the data object's <c>request</c> member.</summary>
    // SPEC: Appendix A.3.2.1: "the JWS object is used as the value of the request claim in the data element of the
    // API call".
    private string Sign(
        DcApiPresentationRequestOptions options,
        string clientId,
        JsonObject parameters,
        IReadOnlyList<string> origins,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt)
    {
        if (_signer is null)
        {
            throw new InvalidOperationException(
                "The options name a ClientId, which makes the request signed, but this builder has no signing options.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(clientId, $"{nameof(options)}.{nameof(options.ClientId)}");

        // SPEC: OpenID4VP 1.0 §5.9.3, the origin prefix: "The Wallet MUST NOT accept this Client Identifier Prefix in
        // requests."
        if (clientId.StartsWith("origin:", StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The origin: Client Identifier Prefix names the audience of a response; no wallet accepts it in a request.",
                $"{nameof(options)}.{nameof(options.ClientId)}");
        }

        // SPEC: Appendix A.2: client_id "MUST be present in signed requests", and expected_origins is "REQUIRED when
        // signed requests defined in Appendix A.3.2 are used". Appendix A.3.2: "The signed Request Object MAY
        // contain all the parameters listed in Appendix A.2, except request." iat and exp are RFC 9101 request
        // object claims a wallet that does not read them ignores (A.2: "The Wallet MUST ignore any unrecognized
        // parameters"); exp bounds how long a captured request can be replayed.
        parameters["client_id"] = clientId;
        parameters["expected_origins"] = new JsonArray([.. origins.Select(o => (JsonNode?)o)]);
        parameters["iat"] = issuedAt.ToUnixTimeSeconds();
        parameters["exp"] = expiresAt.ToUnixTimeSeconds();

        // SPEC: §5.8: "When the Verifier is sending a Request Object as defined in [RFC9101] ... the aud claim MUST be
        // "https://self-issued.me/v2", when Static Discovery metadata is used". A.3.2.1 encodes a signed request "in a
        // request object as defined in Section 5", so the rule reaches it. The redirect flow sets the same value
        // (RequestObjectClaims).
        parameters["aud"] = "https://self-issued.me/v2";

        return _signer.Sign(parameters, issuedAt);
    }
}
