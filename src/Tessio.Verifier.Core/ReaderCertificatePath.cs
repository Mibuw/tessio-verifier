// What belongs in this file: the rules a reader's (relying party's) certificate path must meet before
// this library signs a request with it, shared by every request format that carries one.
using System.Security.Cryptography.X509Certificates;

namespace Tessio.Verifier.Core;

/// <summary>
/// Checks the certificate path a signed request carries to name its signer to the wallet: the reader
/// (access) certificate first, then any intermediates, never the trust anchor. mdoc carries it in
/// <c>x5chain</c>, a JAR in <c>x5c</c>.
/// </summary>
/// <remarks>
/// What is checked, in this order: the path is non-empty and holds no null entry, none of its
/// certificates is self-issued, each names the next as its issuer, and the reader certificate is not a
/// CA. A path that breaks two rules is refused for the first. Names are compared by their encoded
/// bytes, which is stricter than RFC 5280's name matching: a path whose names differ only in case,
/// spacing or string type is refused as unlinked, and a root whose own subject and issuer are encoded
/// differently is not recognised as self-issued. Nothing else is checked here, among others validity
/// periods, revocation, the signatures along the path, key usage and extended key usage, and whether
/// the intermediates are CAs: judging the path is the wallet's, against its own trust list. Whether the
/// reader certificate holds the signing key is the caller's to check, because only the caller knows the
/// key's type.
/// </remarks>
// SPEC: ETSI TS 119 472-2 V1.2.1 (2026-03), which CIR (EU) 2026/1731 applies with adaptations. Clause 6.4.2
// OIDFVP-HAIP-REDIRECTS_RO-02 (a JAR's x5c, redirect transport), which the regulation does not adapt, and clause
// 5.3.2 ISO/IEC 18013-REQ-03 (mdoc's x5chain) both say the RP access certificate "in its first element,
// and its certificate path up to, but excluding, the trust anchor". OpenID4VC HAIP 1.0 section 5: "The
// X.509 certificate of the trust anchor MUST NOT be included in the x5c JOSE header of the signed
// request. The X.509 certificate signing the request MUST NOT be self-signed."
internal static class ReaderCertificatePath
{
    /// <summary>
    /// Throws <see cref="ArgumentException"/> naming <paramref name="parameterName"/> when a rule in the
    /// remarks fails. A disposed or malformed certificate surfaces as whatever the platform throws, so a
    /// caller wraps this as it wraps its own key checks.
    /// </summary>
    /// <param name="path">The path, reader certificate first.</param>
    /// <param name="parameterName">The caller's parameter or option the path came from.</param>
    /// <param name="header">The header the path travels in, for the messages: <c>x5chain</c> or <c>x5c</c>.</param>
    /// <param name="allowSelfSignedSigner">
    /// Lets a path of exactly one certificate through the self-issued and CA rules, for a test environment whose
    /// wallet trusts one published self-signed signing certificate. A longer path keeps every rule.
    /// </param>
    internal static void Check(
        IReadOnlyList<X509Certificate2> path, string parameterName, string header, bool allowSelfSignedSigner = false)
    {
        if (path.Count == 0)
        {
            throw new ArgumentException("The certificate path must hold at least the reader certificate.", parameterName);
        }

        if (path.Any(c => c is null))
        {
            throw new ArgumentException("The certificate path must not hold a null entry.", parameterName);
        }

        // A self-issued certificate is nearly always the root. The rare one that is not, a CA's
        // key-rollover link certificate (RFC 5280 section 6.1), is refused too: this library does not
        // support a path through one. Anything above the reader certificate that is not self-issued
        // may still be the anchor a wallet holds, which no certificate can say about itself; that one
        // is the caller's to leave out.
        var selfSignedSigner = allowSelfSignedSigner && path.Count == 1;
        var selfIssued = path.FirstOrDefault(c => SameEncoding(c.SubjectName, c.IssuerName));
        if (selfIssued is not null && !selfSignedSigner)
        {
            throw new ArgumentException(
                $"The certificate path holds a self-issued certificate ({selfIssued.Subject}), one naming itself as its "
                + $"issuer as a root does. A trust anchor must never travel in {header}, and the reader certificate must "
                + "not be self-signed: pass the reader certificate and its intermediates only.",
                parameterName);
        }

        for (var i = 0; i + 1 < path.Count; i++)
        {
            if (!SameEncoding(path[i].IssuerName, path[i + 1].SubjectName))
            {
                throw new ArgumentException(
                    $"Certificate {i} in the path ({path[i].Subject}) is not issued by the one after it "
                    + $"({path[i + 1].Subject}). The path runs from the reader certificate up, each followed by its issuer.",
                    parameterName);
            }
        }

        if (!selfSignedSigner && path[0].Extensions.OfType<X509BasicConstraintsExtension>().Any(c => c.CertificateAuthority))
        {
            throw new ArgumentException(
                $"The reader certificate ({path[0].Subject}) is a CA certificate. A request is signed with an "
                + "end-entity access certificate, so the path is probably in the wrong order.",
                parameterName);
        }
    }

    /// <summary>
    /// Whether two names are encoded identically. This checks the caller's own configuration before
    /// signing, not an adversary's input, and the wallet judges the path itself. Byte equality is what
    /// a path issued the usual way meets, and it needs no Unicode tables, globalization mode or
    /// platform name rendering to decide.
    /// </summary>
    // SPEC: RFC 5280 section 4.1.2.6 (a): "When the subject of the certificate is a CA, the subject
    // field MUST be encoded in the same way as it is encoded in the issuer field (Section 4.1.2.4) in
    // all certificates issued by the subject CA." Section 7.1's matching is looser (case, insignificant
    // space), so a conforming path with names that differ only that way is refused here.
    private static bool SameEncoding(X500DistinguishedName a, X500DistinguishedName b) =>
        a.RawData.AsSpan().SequenceEqual(b.RawData);
}
