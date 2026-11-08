using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core;

/// <summary>
/// Outcome of credential verification. Carries the disclosed claims, issuer info, and any failure reasons.
/// </summary>
/// <remarks>
/// FROZEN contract (contracts-v0). Forward-compatible: new optional inputs may be added as init-only
/// properties, which is how <see cref="CredentialType"/>, <see cref="CredentialQueryId"/> and
/// <see cref="VerifiedPresentations"/> arrived. No existing member changes.
/// </remarks>
public sealed record VerificationResult
{
    /// <summary>True when signature, disclosures, key binding, and trust checks all pass.</summary>
    public required bool IsValid { get; init; }

    /// <summary>
    /// The claims the holder elected to disclose, keyed by claim name. Empty when <see cref="IsValid"/> is false.
    /// Values are dynamic JSON values represented as <see cref="object"/> (string, number, bool, list, dict, or null).
    /// </summary>
    public required IReadOnlyDictionary<string, object> DisclosedClaims { get; init; }

    /// <summary>Information about the credential issuer and how its key was resolved.</summary>
    public required IssuerInfo Issuer { get; init; }

    /// <summary>Verification failures; empty when <see cref="IsValid"/> is true.</summary>
    public required IReadOnlyList<VerificationError> Errors { get; init; }

    /// <summary>
    /// The credential type that was actually presented: the <c>vct</c> for SD-JWT VC, the
    /// <c>docType</c> for mdoc. Null when verification failed before the type could be read.
    /// </summary>
    /// <remarks>
    /// <para>
    /// What was PRESENTED, not what was requested. The caller already knows what it asked for. Once a
    /// request names several types, which one arrived is a fact only the verifier holds, and without
    /// this the only way to learn it is to read a mismatch message, which exists only when the type was
    /// wrong. A caller recording what a holder presented, or choosing which claim path to read an answer
    /// from, needs it on the passing path too.
    /// </para>
    /// <para>
    /// Null means "not established", never "the credential declared none". A signature that fails before
    /// the payload is parsed leaves nothing to report, and an empty string there would be the stronger
    /// and false claim.
    /// </para>
    /// <para>
    /// Init-only and optional, so every existing construction of this record still compiles and behaves
    /// as it did. Additive in the sense the frozen contract permits: no existing member changes.
    /// </para>
    /// </remarks>
    public string? CredentialType { get; init; }

    /// <summary>
    /// The id of the DCQL Credential Query the verified presentation answered, when the verifier knows the request:
    /// which alternative the wallet chose, for a query offering several. Null when it was not established.
    /// </summary>
    /// <remarks>
    /// <para>
    /// SPEC: OpenID4VP 1.0 section 6.4.3: "it is typically expected that the Wallet presents the End-User with a
    /// choice of which Credential(s) to present if multiple of the sets of Credentials in options can satisfy the
    /// request", so which one answered is known only from the response. Set by
    /// <c>WalletResponseVerifier</c> in the ASP.NET Core package, from <see cref="PresentedCredential.CredentialQueryId"/>.
    /// A credential verifier on its own does not set it, because it sees one presentation and not the request.
    /// </para>
    /// <para>
    /// A response answering several Credential Queries yields one result. When the response verifies, it is the
    /// presentation that verified whose Credential Query comes first in the query's <c>credentials</c> array, so the
    /// order the wallet put its keys in does not change it, and this names that Credential Query.
    /// <see cref="VerifiedPresentations"/> carries every presentation that verified. When what verified does not
    /// answer the query, the result is the first presentation that failed and this names its Credential Query.
    /// When the refusal concerns the request or the response as a whole rather than one presentation (a key naming no
    /// Credential Query, an unverifiable request, transaction data no verified presentation acknowledges), this is null.
    /// </para>
    /// <para>
    /// Init-only and optional, so every existing construction of this record still compiles and behaves as it did.
    /// </para>
    /// </remarks>
    public string? CredentialQueryId { get; init; }

    /// <summary>
    /// For a passing result over a DCQL query whose Credential Query ids the verifier could read: the result of every
    /// presentation that verified, in the order of the query's <c>credentials</c> array, each with its own
    /// <see cref="CredentialQueryId"/>, claims and issuer. Null otherwise, including on every failing result.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The top-level members describe the first of these. A credential set option may need two credentials together
    /// (OpenID4VP 1.0 section 6.2), and the second one's claims are reachable only here. A presentation that failed
    /// and was discarded (section 8.6) is not listed.
    /// </para>
    /// <para>
    /// The entries' own <see cref="VerifiedPresentations"/> are null, so the list is one level deep.
    /// </para>
    /// <para>
    /// Init-only and optional, so every existing construction of this record still compiles and behaves as it did.
    /// </para>
    /// </remarks>
    public IReadOnlyList<VerificationResult>? VerifiedPresentations { get; init; }

    /// <summary>
    /// A passing result carrying the disclosed claims and resolved issuer. Convenience for tests and
    /// self-driving hosts that synthesize results rather than fully initializing every required member.
    /// </summary>
    public static VerificationResult Valid(IReadOnlyDictionary<string, object> disclosedClaims, IssuerInfo issuer)
    {
        ArgumentNullException.ThrowIfNull(disclosedClaims);
        ArgumentNullException.ThrowIfNull(issuer);
        return new VerificationResult
        {
            IsValid = true,
            DisclosedClaims = disclosedClaims,
            Issuer = issuer,
            Errors = [],
        };
    }

    /// <summary>A failing result carrying one error and, optionally, the issuer that was resolved.</summary>
    public static VerificationResult Invalid(VerificationError error, IssuerInfo? issuer = null)
    {
        ArgumentNullException.ThrowIfNull(error);
        return Invalid([error], issuer);
    }

    /// <summary>
    /// A failing result carrying every accumulated error and, optionally, the resolved issuer. Falls back
    /// to <see cref="IssuerInfo.Unknown"/> when no issuer was reached.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every message is made one line here, because messages quote what the presenter sent and a caller
    /// may log them as they stand: each character that could break the line becomes U+FFFD. Every
    /// failing result this library builds goes through here, and a test holds the source to that, so no
    /// failure path can return a message that skipped it. The one other place that sets a result's
    /// errors, the session view, replaces every message with one fixed sentence.
    /// </para>
    /// <para>
    /// A caller passing its own messages here gets them made one line too.
    /// </para>
    /// </remarks>
    public static VerificationResult Invalid(IReadOnlyList<VerificationError> errors, IssuerInfo? issuer = null)
    {
        ArgumentNullException.ThrowIfNull(errors);
        return new VerificationResult
        {
            IsValid = false,
            DisclosedClaims = new Dictionary<string, object>(StringComparer.Ordinal),
            Issuer = issuer ?? IssuerInfo.Unknown,
            Errors = [.. errors.Select(e => e with { Message = MessageText.OneLine(e.Message) })],
        };
    }
}
