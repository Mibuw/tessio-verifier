namespace Tessio.Verifier.Core;

/// <summary>
/// A single credential extracted from a presentation, in its serialized wire form.
/// </summary>
/// <remarks>
/// FROZEN contract (contracts-v0). Extended additively with the optional <see cref="CredentialQueryId"/>; no
/// existing member changed.
/// </remarks>
public sealed record PresentedCredential
{
    /// <summary>
    /// Credential format identifier. For v0.1 this is <c>"dc+sd-jwt"</c>.
    /// </summary>
    // SPEC: dc+sd-jwt, not vc+sd-jwt (SD-JWT VC media-type change, late 2024).
    public required string Format { get; init; }

    /// <summary>
    /// The credential as received on the wire (e.g., the SD-JWT VC string including disclosures
    /// and the optional Key Binding JWT, tilde-separated).
    /// </summary>
    public required string RawValue { get; init; }

    /// <summary>
    /// The id of the DCQL Credential Query this presentation answers: the <c>vp_token</c> key it arrived under.
    /// Null when the <c>vp_token</c> was a bare presentation or array, not keyed at all, and the parser was given no
    /// query to read it against.
    /// </summary>
    /// <remarks>
    /// <para>
    /// SPEC: OpenID4VP 1.0 section 8.1: <c>vp_token</c> holds "entries where the key is the id value used for a
    /// Credential Query in the DCQL query and the value is an array of one or more Presentations that match the
    /// respective Credential Query". A query offering several credentials as alternatives is answered by one of
    /// them, and this says which.
    /// </para>
    /// <para>
    /// As the wallet sent it, unless the parser was given the request's query
    /// (<c>WalletResponseParserOptions.DcqlQueryJson</c>), in which case it names a Credential Query of that query
    /// and <see cref="Format"/> is that Credential Query's format.
    /// </para>
    /// <para>
    /// Init-only and optional, so every existing construction of this record still compiles and behaves as it did.
    /// </para>
    /// </remarks>
    public string? CredentialQueryId { get; init; }
}
