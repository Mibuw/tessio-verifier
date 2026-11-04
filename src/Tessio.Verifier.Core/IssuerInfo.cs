namespace Tessio.Verifier.Core;

/// <summary>
/// Information about the credential's issuer as observed during verification.
/// </summary>
/// <remarks>
/// FROZEN contract (contracts-v0). Forward-compatible: new optional inputs may be added as init-only
/// properties, which is how <see cref="TrustListSource"/>, <see cref="TrustAnchorSubject"/> and
/// <see cref="TrustAnchorThumbprint"/> arrived. No existing member changes.
/// </remarks>
public sealed record IssuerInfo
{
    /// <summary>The issuer identifier from the credential (e.g., HTTPS URI or X.509 subject).</summary>
    public required string Identifier { get; init; }

    /// <summary>
    /// The credential's <c>iss</c> claim when it is NOT the <see cref="Identifier"/>. Null otherwise.
    /// </summary>
    /// <remarks>
    /// Set on an SD-JWT VC carrying <c>x5c</c> whose end-entity certificate does not name its <c>iss</c>
    /// in a subjectAltName. The certificate is what the trust verdict rests on, so its subject is the
    /// <see cref="Identifier"/> (draft-ietf-oauth-sd-jwt-vc-13 section 3.5: "the Issuer of the Verifiable
    /// Credential is the subject of the end-entity certificate"). The <c>iss</c> value is the credential's
    /// own claim about itself, which nothing here verified. Show it, but do not identify an issuer by it.
    /// </remarks>
    public string? ClaimedIssuer { get; init; }

    /// <summary>
    /// Whether the issuer chains to a trusted root. See <see cref="VerificationResult.IsValid"/> for the overall verdict.
    /// </summary>
    public required bool Trusted { get; init; }

    /// <summary>
    /// How the issuer's signing key was resolved. Canonical values:
    /// <c>"jwt-vc-issuer-metadata"</c> (web resolution via the <c>iss</c> HTTPS URI) or
    /// <c>"x5c"</c> (the X.509 route: a chain carried in the credential header, or, with
    /// <see cref="SdJwtVcVerifierOptions.ResolveX5u"/> on, fetched from its <c>x5u</c>).
    /// </summary>
    // SPEC: SD-JWT VC issuer key resolution — two mechanisms (JWT VC Issuer Metadata + X.509).
    public required string KeyResolutionMethod { get; init; }

    /// <summary>
    /// Which trust list produced the verdict, on both a trusted and an untrusted one.
    /// </summary>
    /// <remarks>
    /// <b>Null carries two different meanings and cannot distinguish them.</b> Either the resolver in use
    /// reports no source, or the verdict carries no trust attribution: a malformed credential, a bad
    /// signature or a synthesised result all report none. A bad signature reports none even where the
    /// seam was asked first, which on the SD-JWT VC metadata route it is. So null is "no attribution
    /// available", never "no list accepted this". A caller storing an audit record should treat a null
    /// source as unevaluated rather than as a negative finding.
    /// </remarks>
    /// <remarks>
    /// <para>
    /// <b>Why these are here.</b> <see cref="Trusted"/> is a boolean, and a boolean is not evidence. A
    /// relying party asked months later which list and which anchor stood behind a presentation could
    /// not answer from this record, and the resolver held the answer and dropped it. Every field below
    /// is copied from the <c>IssuerTrustStatus</c> the resolver already returned.
    /// </para>
    /// <para>
    /// <b>They describe the verdict, not the configuration.</b> A deployment's anchors and lists change,
    /// so reading them back off today's configuration answers a different question from the one asked.
    /// These say what was true at the moment of verification.
    /// </para>
    /// <para>Init-only and optional, so every existing construction still compiles unchanged.</para>
    /// </remarks>
    public string? TrustListSource { get; init; }

    /// <summary>
    /// Subject of the trust anchor that vouched for this issuer's key, when a certificate did.
    /// </summary>
    /// <remarks>
    /// Null on the identifier route, where the list carried the identifier and no certificate was
    /// involved, and null on a refusal where nothing matched. Both are facts about the mechanism rather
    /// than missing values. A refusal that DOES know its anchor sets this, which is how "we trusted this
    /// exact certificate and its window had closed" stays distinguishable from "nothing matched".
    /// <b>A subject is not an identity</b>: compare
    /// <see cref="TrustAnchorThumbprint"/>, because distinguished names are not unique and a same-name
    /// impostor is what a subject comparison accepts. This is also the platform's rendering of the name
    /// rather than its DER, so it may not be string-equal across operating systems.
    /// </remarks>
    public string? TrustAnchorSubject { get; init; }

    /// <summary>
    /// SHA-256 over that anchor's DER bytes, uppercase hex. Null in the same cases as
    /// <see cref="TrustAnchorSubject"/>.
    /// </summary>
    /// <remarks>
    /// Not the platform's <c>Thumbprint</c> property, which is SHA-1. It identifies the certificate
    /// rather than the key, so a certificate authority that rotates its certificate produces a different
    /// value here, which is correct: a different artefact was relied on.
    /// </remarks>
    public string? TrustAnchorThumbprint { get; init; }

    /// <summary>
    /// Placeholder issuer for results produced before any issuer could be resolved (for example a
    /// structurally malformed credential). <see cref="Trusted"/> is false and
    /// <see cref="KeyResolutionMethod"/> is <c>"none"</c>.
    /// </summary>
    public static IssuerInfo Unknown { get; } = new()
    {
        Identifier = "unknown",
        Trusted = false,
        KeyResolutionMethod = "none",
    };
}
