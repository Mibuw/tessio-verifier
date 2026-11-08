using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>Configuration for <see cref="WalletResponseParser"/>.</summary>
public sealed class WalletResponseParserOptions
{
    /// <summary>
    /// Private key used to decrypt <c>direct_post.jwt</c> (JWE) responses. The matching public key is
    /// advertised to wallets via <c>client_metadata.jwks</c>. Required to parse encrypted responses;
    /// plain <c>direct_post</c> responses need no key.
    /// </summary>
    public SecurityKey? ResponseDecryptionKey { get; set; }

    /// <summary>
    /// Resolves the decryption key from the JWE's <c>kid</c> header. Takes precedence over
    /// <see cref="ResponseDecryptionKey"/> when set.
    /// </summary>
    /// <remarks>
    /// Needed because response-encryption keys are ephemeral per authorization request (HAIP 1.0
    /// §5) and for <c>direct_post.jwt</c> the session correlation handle (<c>state</c>)
    /// is inside the encrypted payload, so the key cannot be picked by session. The <c>kid</c> the
    /// wallet echoes from our <c>client_metadata.jwks</c> is the way back to the right key.
    /// </remarks>
    public Func<string?, SecurityKey?>? ResponseDecryptionKeyResolver { get; set; }

    /// <summary>
    /// Credential format assigned to string presentations extracted from <c>vp_token</c>.
    /// Defaults to <c>dc+sd-jwt</c>, the SD-JWT VC format identifier.
    /// </summary>
    // SPEC: dc+sd-jwt presentations appear as strings in vp_token; mdoc (v0.2) would be
    // base64url-encoded and carry the mso_mdoc format identifier.
    public string PresentationFormat { get; set; } = "dc+sd-jwt";

    /// <summary>
    /// The DCQL query of the request the response answers, as the JSON sent in <c>dcql_query</c>. When set, each
    /// presentation is read in the format of the Credential Query its <c>vp_token</c> key names, and a response that
    /// does not answer the query is refused. Null by default, which reads every presentation in
    /// <see cref="PresentationFormat"/> as before.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Set it for a query offering several credentials, such as a PID as an mdoc or as an SD-JWT VC built by
    /// <see cref="Dcql.AnyOf"/>: one format for the whole response cannot read either answer correctly.
    /// <see cref="PresentationFormat"/> still applies when the query's only Credential Query names no format; a query
    /// asking for several credentials must name one on each.
    /// </para>
    /// <para>
    /// A response is refused, as a <see cref="WalletResponseException"/>, when a <c>vp_token</c> key names no
    /// Credential Query, when a Credential Query that does not allow <c>multiple</c> gets more than one presentation
    /// (OpenID4VP 1.0 section 8.1), or when the Credential Queries answered are not a combination the query requested
    /// (section 6.4.2): every one of them when the query has no <c>credential_sets</c>, otherwise an option of every
    /// required set, and nothing outside the options answered. A bare presentation, not keyed by id, is read as the
    /// answer to the only Credential Query of a query that has one, and refused for a query that has several.
    /// </para>
    /// <para>
    /// A value that is not a DCQL query with a non-empty <c>credentials</c> array, each entry carrying a well-formed id
    /// of its own (and a <c>format</c>, when there are several or there are credential sets), and well-formed
    /// <c>credential_sets</c> when present, is the caller's configuration, not the wallet's answer. The parser's
    /// constructor refuses it with <see cref="ArgumentException"/>. Changed on the options afterwards, it makes every
    /// parse throw <see cref="InvalidOperationException"/> before any of the response is read.
    /// </para>
    /// </remarks>
    public string? DcqlQueryJson { get; set; }

    /// <summary>
    /// Whether <see cref="WalletResponseParser.ParseDetailedAsync"/> returns an Authorization Error Response, in
    /// the clear or sealed in a <c>direct_post.jwt</c> <c>response</c>, with <see cref="ParsedWalletResponse.Error"/>
    /// set and no credentials, instead of throwing. Off by default.
    /// </summary>
    /// <remarks>
    /// Off by default because a caller written before this option existed expects an exception for a form with
    /// no presentation. Handed an empty credential list instead, a check over "every credential" would pass on
    /// nothing. Turn it on only where <see cref="ParsedWalletResponse.Error"/> is read before the credentials.
    /// The built-in callback and <c>WalletResponseVerifier</c> in the ASP.NET Core package do.
    /// </remarks>
    public bool ReadErrorResponses { get; set; }
}
