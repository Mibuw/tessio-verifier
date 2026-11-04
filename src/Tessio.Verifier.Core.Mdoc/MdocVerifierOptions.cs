namespace Tessio.Verifier.Core.Mdoc;

/// <summary>Policy knobs for <see cref="MdocVerifier"/>.</summary>
public sealed class MdocVerifierOptions
{
    /// <summary>
    /// Tolerated clock skew for the MSO validity window. Defaults to 5 minutes, matching
    /// <see cref="SdJwtVcVerifierOptions.ClockSkew"/>.
    /// </summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Whether device authentication (the holder's signature over the session transcript) is
    /// required. Defaults to true, matching <see cref="SdJwtVcVerifierOptions.RequireKeyBinding"/>.
    /// When false, a present deviceSignature is still verified.
    /// </summary>
    public bool RequireDeviceAuth { get; set; } = true;

    /// <summary>
    /// Whether to enforce the MSO's <c>status</c> element when present: the credential's entry in the MSO
    /// revocation list it references, a status list or an identifier list. Defaults to true, matching
    /// <see cref="SdJwtVcVerifierOptions.CheckStatus"/>: a revoked credential fails verification, and so
    /// does one whose list cannot be fetched or validated. Turn off only where the list's host is
    /// unreachable by design.
    /// </summary>
    /// <remarks>
    /// A list is trusted only through the credential that referenced it: the certificate its MSO reference
    /// names, or else the certificate that signed the credential's own Document Signer, which the trust seam
    /// must vouch for on the same anchor as the Document Signer. A seam that reports no
    /// <see cref="Trust.IssuerTrustStatus.TrustAnchorThumbprint"/>, or that anchors on the Document Signer
    /// itself, cannot vouch for that certificate, so a credential whose MSO reference names no certificate
    /// fails with <see cref="ErrorCodes.StatusUnresolvable"/>. Anchor on IACA certificates, as for the
    /// Document Signer's own trust.
    /// </remarks>
    // SPEC: EAA-6.2.10.1-05 and -05.1 (Implementing Regulation (EU) 2024/2979, Annex II as replaced by
    // Implementing Regulation (EU) 2026/1731, adaptation (6)): verification is optional, but a relying party
    // that verifies revocation supports both mechanisms.
    public bool CheckStatus { get; set; } = true;

    /// <summary>
    /// How long a validated MSO revocation list may be served from cache before refetching. This is the
    /// ceiling: the list's own <c>ttl</c> shortens it and its <c>exp</c> caps it. Defaults to 5 minutes,
    /// matching <see cref="SdJwtVcVerifierOptions.StatusListCacheDuration"/>. Set to
    /// <see cref="TimeSpan.Zero"/> to fetch on every verification.
    /// </summary>
    // SPEC: draft-ietf-oauth-status-list-20 section 8.3 step 4d and section 13.7.
    public TimeSpan StatusListCacheDuration { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Fetches the Document Signer certificate an issuerAuth names by <c>x5u</c> when it carries no
    /// <c>x5chain</c>. Off by default: such an mdoc then fails with <see cref="MdocErrorCodes.IssuerKeyUnresolvable"/>,
    /// with a message saying x5u resolution is off.
    /// </summary>
    /// <remarks>
    /// The fetch goes to a URL the presented mdoc chooses, and it happens before trust is known, because the
    /// trust seam judges the chain the URL returns. It is HTTPS only and bounded in size and time; the default HTTP
    /// client also refuses internal addresses, which a client passed to <see cref="MdocVerifier"/> must do itself.
    /// Both the <c>x5u</c> and a SHA-256 <c>x5t</c> naming the certificate must be in the protected header, as CIR
    /// (EU) 2026/1731 Annex I has a PID carry them; otherwise the mdoc is refused. A resource is kept only for an mdoc
    /// that verified in full, keyed by URL and thumbprint, and reused for an hour from when it was fetched. The issuer
    /// whose URL it is learns when its credentials are verified, so turn this on only for a trust source whose issuers
    /// name their certificate this way.
    /// </remarks>
    // SPEC: CIR (EU) 2026/1731 Annex I, replacing the annex of CIR (EU) 2024/2977, has a PID's issuerAuth carry
    // x5u and x5t (RFC 9360). ISO/IEC 18013-5 section 9.3.1 has issuers carry x5chain, so most mdocs need no fetch.
    public bool ResolveX5u { get; set; }

    /// <summary>
    /// Checks the proofs of zero knowledge presentations. Off by default: without one, a response made only of
    /// zero knowledge presentations fails with <see cref="MdocErrorCodes.ZkPresentationUnsupported"/>. With one,
    /// such a presentation is verified. Its timestamp must then lie within <see cref="ClockSkew"/> of the
    /// verifier's clock, because the proof establishes the credential's validity at that timestamp.
    /// </summary>
    /// <remarks>
    /// Set <see cref="CheckStatus"/> to false beside it. A proof discloses no MSO, so its revocation status
    /// cannot be checked. While <see cref="CheckStatus"/> is true every zero knowledge presentation fails with
    /// <see cref="ErrorCodes.CredentialStatusUnknown"/>. That is stricter than for a plain presentation, which
    /// passes when its MSO names no status list: a proof cannot show whether its MSO names one. The age
    /// verification profile puts revocation out of scope (Annex A, A.3).
    /// To refuse a proof made with a circuit the request did not offer, set
    /// <see cref="MdocVerificationContext.ZkRequest"/> when verifying the answer.
    /// </remarks>
    // SPEC: age verification technical specification 1.1.0, section 4.4: a relying party SHALL implement the
    // zero knowledge proof verification of Annex A, A.8.
    public IZkProofVerifier? ZkProofVerifier { get; set; }
}
