namespace Tessio.Verifier.Core;

/// <summary>Policy knobs for <see cref="SdJwtVcVerifier"/>.</summary>
public sealed class SdJwtVcVerifierOptions
{
    /// <summary>
    /// Whether a Key Binding JWT is required. Defaults to true — HAIP-profile EUDI presentations are
    /// holder-bound. When false, a KB-JWT is still verified if present.
    /// </summary>
    public bool RequireKeyBinding { get; set; } = true;

    /// <summary>
    /// Accepts the legacy <c>vc+sd-jwt</c> typ (pre-Nov-2024 credentials) in addition to the
    /// standard <c>dc+sd-jwt</c>. Off by default.
    /// </summary>
    // SPEC: draft-ietf-oauth-sd-jwt-vc-13 §3.2.1: typ MUST use dc+sd-jwt. The same section RECOMMENDS that
    // verifiers also accept vc+sd-jwt for a transitional period. This flag is how a caller opts in.
    public bool AcceptLegacyVcSdJwtTyp { get; set; }

    /// <summary>
    /// Tolerated clock skew for <c>exp</c> / <c>nbf</c> evaluation. Defaults to 5 minutes
    /// (the Microsoft.IdentityModel ecosystem default).
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// How far in the past a KB-JWT <c>iat</c> (the time the holder created the presentation) may be
    /// and still be accepted. Defaults to 5 minutes: a presentation is meant to be fresh, made in
    /// response to this verifier's live request, so an <c>iat</c> older than this is stale or replayed.
    /// <see cref="ClockSkew"/> is added on top for tolerance, and it also bounds how far in the future
    /// an <c>iat</c> may be. Set to <see cref="Timeout.InfiniteTimeSpan"/> to disable the past bound.
    /// </summary>
    // SPEC: RFC 9901 §4.3 requires iat; its freshness is verifier policy. The OpenID Foundation
    // conformance suite skews iat by a year in each direction and expects rejection.
    public TimeSpan MaxKeyBindingAge { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Whether to resolve and enforce the credential's <c>status</c> claim (Token Status List) when
    /// present. Defaults to true — a revoked or suspended credential fails verification. Turn off
    /// only for offline scenarios where the status host is unreachable by design.
    /// </summary>
    // SPEC: draft-ietf-oauth-status-list-20 §8.3: Relying Parties validate the referenced status.
    public bool CheckStatus { get; set; } = true;

    /// <summary>
    /// How long a validated status list may be served from cache before refetching. This is the
    /// ceiling: the token's own <c>ttl</c> claim shortens it and its <c>exp</c> caps it. Defaults to
    /// 5 minutes — the window in which a freshly revoked credential could still verify. Set to
    /// <see cref="TimeSpan.Zero"/> to fetch on every verification.
    /// </summary>
    // SPEC: draft-ietf-oauth-status-list-20 §8.3 step 4d and §13.7: ttl drives Relying Party caching.
    public TimeSpan StatusListCacheDuration { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Fetches the signing certificate an issuer JWT names by <c>x5u</c> when it carries no <c>x5c</c>. Off by
    /// default, and off the <c>x5u</c> is ignored as it was before it was read: a credential with an HTTPS <c>iss</c>
    /// resolves through JWT VC Issuer Metadata, and one without fails with
    /// <see cref="ErrorCodes.IssuerKeyUnresolvable"/>, with a message saying x5u resolution is off.
    /// </summary>
    /// <remarks>
    /// The fetch goes to a URL the presented credential chooses, and it happens before trust is known, because the
    /// trust seam judges the chain the URL returns. It is HTTPS only and bounded in size and time; the default HTTP
    /// client also refuses internal addresses, which a client passed to <see cref="SdJwtVcVerifier"/> must do itself.
    /// The <c>x5u</c> is used only when the header's <c>x5t#S256</c> binds it, and then in preference to issuer
    /// metadata, and the certificate must match that thumbprint. A resource is kept only for a credential that
    /// verified in full, keyed by URL and thumbprint, and reused for an hour from when it was fetched. An <c>x5u</c>
    /// with no <c>x5t#S256</c> is ignored, so the credential resolves by its <c>iss</c> as it would with this off, and
    /// is refused when it has none. The issuer whose URL it is learns when its credentials are verified, so turn this
    /// on only for a trust source whose issuers name their certificate this way. A status list token is never
    /// resolved by <c>x5u</c>, whatever this says: HAIP 1.0 section 6.1 has its key in <c>x5c</c>.
    /// </remarks>
    // SPEC: CIR (EU) 2026/1731 Annex I, replacing the annex of CIR (EU) 2024/2977, has a PID carry x5u and
    // x5t#S256 (RFC 7515). HAIP 1.0 section 6.1.1 has issuers send x5c, so most credentials need no fetch.
    public bool ResolveX5u { get; set; }
}
