namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// Inputs to <see cref="DcApiPresentationRequestBuilder"/>: one OpenID4VP request sent through the Digital
/// Credentials API rather than to a redirect wallet.
/// </summary>
/// <remarks>
/// <para>
/// Setting <see cref="ClientId"/> makes the request signed, because that is the rule the specification states:
/// the client_id "MUST be omitted in unsigned requests" and "MUST be present in signed requests".
/// </para>
/// <para>
/// There is no response_uri and no state: the response comes back through the browser, and the transport
/// defines no state. The wallet binds its answer to the page's origin and the nonce instead.
/// </para>
/// </remarks>
// SPEC: OpenID4VP 1.0 Appendix A.2.
public sealed record DcApiPresentationRequestOptions
{
    /// <summary>Per-request nonce, cryptographically random and one-time.</summary>
    public required string Nonce { get; init; }

    /// <summary>The DCQL query as a JSON string.</summary>
    public required string DcqlQueryJson { get; init; }

    /// <summary>
    /// The origins of the pages that may make this request, as a browser serializes them: lowercase scheme and
    /// host, no trailing slash, no path (<c>https://verifier.example</c>). At least one.
    /// </summary>
    /// <remarks>
    /// A signed request sends them to the wallet as <c>expected_origins</c>. An unsigned one may not (Appendix
    /// A.2), so they are kept with the built request instead. Either way the verifier refuses a response that
    /// came through any other origin, which is what binds an unsigned request to the pages that may make it.
    /// </remarks>
    public required IReadOnlyList<string> ExpectedOrigins { get; init; }

    /// <summary>
    /// Whether the wallet encrypts its response (<c>dc_api.jwt</c>) or returns it in the clear (<c>dc_api</c>).
    /// Defaults to encrypted. An encrypted response needs exactly one encryption key in
    /// <see cref="ClientMetadataJson"/>.
    /// </summary>
    public bool EncryptedResponse { get; init; } = true;

    /// <summary>
    /// The <c>client_metadata</c> object as a JSON string, from <see cref="ClientMetadata"/>. Required, because
    /// over this transport the wallet has no other source for <c>vp_formats_supported</c>.
    /// </summary>
    public required string ClientMetadataJson { get; init; }

    /// <summary>Optional <c>transaction_data</c> as a JSON string.</summary>
    public string? TransactionDataJson { get; init; }

    /// <summary>
    /// Optional <c>verifier_info</c> as a JSON string holding the array, as for
    /// <see cref="PresentationRequestOptions.VerifierInfoJson"/>.
    /// </summary>
    // SPEC: OpenID4VP 1.0 §5.11. Appendix A.3.2.2 confines verifier_info to a signature object's protected
    // header, and that is the multi-signature JSON serialization; this builder signs per A.3.2.1, where the
    // JWS is the data object's request claim and the parameters are its payload, so it belongs here.
    public string? VerifierInfoJson { get; init; }

    /// <summary>
    /// The client identifier, including its prefix (for example <c>x509_hash:...</c> from
    /// <see cref="ClientIdentifier.X509Hash"/>). Set for a signed request, null for an unsigned one.
    /// </summary>
    public string? ClientId { get; init; }

    /// <summary>
    /// How long the request may be answered, which sets <see cref="DcApiPresentationRequest.ExpiresAt"/> and, for a
    /// signed request, its <c>exp</c>. The builder's default when unset.
    /// </summary>
    public TimeSpan? RequestLifetime { get; init; }
}
