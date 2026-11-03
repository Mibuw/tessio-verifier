namespace Tessio.Verifier.Core;

/// <summary>
/// The COSE algorithm identifiers the mdoc verifiers accept, and the ones a request advertises. One owner, so
/// what a request tells a wallet cannot drift from what the verifiers take.
/// </summary>
// SPEC: RFC 9053 section 2.1 registers -7, -35 and -36 as ES256, ES384 and ES512, each "ECDSA w/ SHA-256" (and
// so on) on any curve. RFC 9864 section 2 registers -9 as ESP256, "ECDSA using P-256 curve and SHA-256".
internal static class CoseAlgorithms
{
    public const int Es256 = -7;
    public const int Esp256 = -9;
    public const int Es384 = -35;
    public const int Es512 = -36;

    /// <summary>
    /// ECDSA on P-256 with SHA-256, under both of its identifiers. HAIP 1.0 section 7 has verifiers support
    /// "COSE algorithm identifier -7 or -9, as applicable" for the deviceSignature and status information.
    /// </summary>
    public static readonly IReadOnlyList<int> P256 = [Es256, Esp256];

    /// <summary>What a request advertises in <c>issuerauth_alg_values</c> and <c>deviceauth_alg_values</c>.</summary>
    /// <remarks>
    /// SPEC: OpenID4VP 1.0 Appendix B.2.2, a credential fulfils these if "The value in the array matches the 'alg'
    /// value in the IssuerAuth COSE header", or the value is fully specified and matches the header's algorithm
    /// and the signing key's curve. So -9 covers a -9 header and a -7 header on P-256, and -7 covers a -7 header
    /// for a wallet that compares values literally. Every value here must be one the verifiers accept.
    /// </remarks>
    public static readonly IReadOnlyList<int> Advertised = P256;

    /// <summary>What <c>issuerAuth</c> may be signed with: the P-256 pair, ES384 and ES512.</summary>
    /// <remarks>
    /// HAIP 1.0 section 7 requires -9 of a verifier only for the deviceSignature and status information, not for
    /// issuerAuth. It is accepted here because it is ES256 under the identifier that fixes its curve (RFC 9864),
    /// so it adds a name and no new cryptography, and because a request advertises it for issuerAuth too.
    /// </remarks>
    public static readonly IReadOnlyList<int> IssuerAuth = [.. P256, Es384, Es512];
}
