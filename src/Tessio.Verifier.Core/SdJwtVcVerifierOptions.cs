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
}
