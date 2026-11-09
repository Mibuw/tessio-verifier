using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Decides whether an MSO revocation list's signing chain speaks for THIS credential. A list is not trusted
/// because some trusted party signed it. Its trust comes from the credential that referenced it.
/// </summary>
/// <remarks>
/// SPEC: EAA-6.2.10.1-06 (Implementing Regulation (EU) 2024/2979, Annex II as replaced by Implementing Regulation
/// (EU) 2026/1731, adaptation (6)):
/// <list type="bullet">
/// <item>-06.1 and -06.1.1: where the MSO's reference carries the <c>certificate</c> element, "The
/// wallet-relying party instance shall use that certificate as a trust anchor for the verification of the
/// x5chain element in the MSO revocation list structure."</item>
/// <item>-06.2 and -06.2.1: where it does not, "the top-level certificate in the x5chain element in the MSO
/// revocation list structure shall be signed or sealed by the certificate used to sign the certificate in
/// the x5chain element of the MSO", and that certificate is the trust anchor. For an mDL that is the IACA, as
/// the ISO/IEC 18013-5 second edition working draft puts it; the regulation does not say so.</item>
/// </list>
/// <para>
/// Either way the list's x5chain must first be ONE signing path, every certificate in it signed by the next,
/// as the platform verifies it. Only the top of that path is then held to the rule, because that is the
/// certificate the rule names; a certificate merely present in the x5chain proves nothing.
/// </para>
/// <para>
/// -06.1: the certificate the reference names rides in the issuer-signed MSO, so it anchors as it is.
/// </para>
/// <para>
/// -06.2: "the certificate in the x5chain element of the MSO" is read as the Document Signer, the certificate
/// whose key signed the MSO; the sentence assumes the x5chain holds that one certificate. The certificate that
/// signed it is looked for where the presentation carries it, as the top of the list's path or in the MSO's
/// own x5chain, which the presenter can add to. Finding a certificate with the right key proves only the key,
/// so it counts only once the trust seam vouches for that very certificate on the anchor it placed the
/// Document Signer on; the list's path must then reach it. Where neither carries it, the path's top must name
/// the Document Signer's issuer, by name and authority key identifier, both present, and the seam must place
/// the list's own chain on that same anchor. A seam that anchors the Document Signer itself can do neither.
/// </para>
/// </remarks>
internal static class MsoRevocationTrust
{
    /// <summary>The credential-side facts a list's trust is judged against.</summary>
    /// <param name="DocumentSignerChain">The MSO's x5chain, DER, the Document Signer first.</param>
    /// <param name="Trust">The trust seam's verdict on that chain.</param>
    public sealed record Credential(ReadOnlyMemory<byte>[] DocumentSignerChain, IssuerTrustStatus Trust);

    /// <summary>Null when the list's chain is trusted for this credential, else why not.</summary>
    public static async Task<VerificationError?> CheckAsync(
        MsoRevocationListToken token, RevocationListReference reference, Credential credential,
        ITrustListResolver resolver, TimeProvider clock, CancellationToken ct)
    {
        // Loaded inside the try: only the list's leaf was parsed to check the signature, so any other certificate
        // here, the list's or one the presenter added to the MSO's x5chain, may still be malformed, and the
        // revocation status cannot then be established.
        List<X509Certificate2> chain = [], credentialChain = [];
        try
        {
            chain.AddRange(token.CertificateChain.Select(der => DerCertificate.Load(der.ToArray())));
            using (var path = BuildWithNothingTrusted(chain[0], chain.Skip(1), clock))
            {
                if (!PathHolds(path, chain))
                {
                    return Error(ErrorCodes.StatusInvalid,
                        "The MSO revocation list's x5chain is not a single valid signing path from its signer upward.");
                }
            }

            if (reference.Certificate is { } certificate)
            {
                using var named = DerCertificate.Load(certificate);
                return ExtendsTo(chain, named, clock)
                    ? null
                    : Error(ErrorCodes.StatusInvalid,
                        "The MSO revocation list's chain does not anchor on the certificate its MSO reference names.");
            }

            credentialChain.AddRange(credential.DocumentSignerChain.Select(der => DerCertificate.Load(der.ToArray())));
            return await AnchorsOnDocumentSignerIssuerAsync(token, chain, credentialChain, credential.Trust, resolver, clock, ct)
                .ConfigureAwait(false);
        }
        catch (CryptographicException e)
        {
            return Error(ErrorCodes.StatusInvalid, $"The MSO revocation list's certificate chain is unusable: {e.Message}");
        }
        finally
        {
            foreach (var certificate in chain.Concat(credentialChain))
            {
                certificate.Dispose();
            }
        }
    }

    // SPEC: EAA-6.2.10.1-06.2 and -06.2.1, as the remarks above set out.
    private static async Task<VerificationError?> AnchorsOnDocumentSignerIssuerAsync(
        MsoRevocationListToken token, List<X509Certificate2> chain, List<X509Certificate2> credentialChain,
        IssuerTrustStatus documentSignerTrust, ITrustListResolver resolver, TimeProvider clock, CancellationToken ct)
    {
        var documentSigner = credentialChain[0];

        // Every route below is held to the anchor the seam placed the Document Signer on, so there must be one.
        if (documentSignerTrust.TrustAnchorThumbprint is not { } anchor)
        {
            return Error(ErrorCodes.StatusUnresolvable,
                "The trust seam names no anchor for the Document Signer, so there is nothing to hold the MSO revocation list to.");
        }

        // A seam that anchored the Document Signer on itself knows nothing above it, so it cannot place the list.
        // That is a limit of this deployment's trust configuration, not a fault in the list.
        if (string.Equals(anchor, Convert.ToHexString(SHA256.HashData(documentSigner.RawData)), StringComparison.OrdinalIgnoreCase))
        {
            return Error(ErrorCodes.StatusUnresolvable,
                "The trust seam anchors the Document Signer itself, so it cannot vouch for the certificate that signed it, which the MSO revocation list must anchor on.");
        }

        // The certificate that signed the Document Signer, where the presentation carries it: as the top of the
        // list's path, or in the MSO's x5chain. Holding the right key proves only the key: anyone can wrap that key
        // in a certificate of their own making, with none of the real one's limits. So it counts only once the
        // seam vouches for THAT certificate, on the Document Signer's own anchor.
        var issuer = SignedBy(documentSigner, chain[^1], clock)
            ? chain[^1]
            : credentialChain.Skip(1).FirstOrDefault(c => SignedBy(documentSigner, c, clock));
        if (issuer is not null)
        {
            if (await SeamRefusesAsync(resolver, issuer.Subject, [issuer.RawData], anchor, ct).ConfigureAwait(false) is { } refused)
            {
                return refused;
            }

            return ExtendsTo(chain, issuer, clock)
                ? null
                : Error(ErrorCodes.StatusInvalid,
                    "The top of the MSO revocation list's chain was not signed by the certificate that signed the credential's Document Signer.");
        }

        // Neither carries it, so the seam must vouch for the list's own chain. Name AND key identifier, both required
        // here: without the signing certificate in hand, the key identifier is what tells two same-named issuers
        // apart, so a certificate lacking one cannot be placed.
        if (!SameIssuer(chain[^1], documentSigner))
        {
            return Error(ErrorCodes.StatusInvalid,
                "The top of the MSO revocation list's chain was not issued by the credential's Document Signer's issuer, by name and authority key identifier.");
        }

        return await SeamRefusesAsync(resolver, chain[0].Subject, token.CertificateChain, anchor, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Null when the seam trusts <paramref name="x5c"/> on exactly <paramref name="anchor"/>, the anchor it placed
    /// the Document Signer on; else why not.
    /// </summary>
    private static async Task<VerificationError?> SeamRefusesAsync(
        ITrustListResolver resolver, string subject, ReadOnlyMemory<byte>[] x5c, string anchor, CancellationToken ct)
    {
        var (trust, failure) = await TrustSeam.ResolveAsync(resolver, subject, x5c, ct).ConfigureAwait(false);
        if (failure is not null)
        {
            return Error(ErrorCodes.StatusUnresolvable, $"The MSO revocation list's trust could not be resolved: {failure.Message}");
        }

        if (!trust.Trusted)
        {
            return Error(TrustSeam.RefusalCode(trust, ErrorCodes.StatusInvalid), $"The MSO revocation list's chain is not trusted: {trust.Reason}");
        }

        return string.Equals(trust.TrustAnchorThumbprint, anchor, StringComparison.OrdinalIgnoreCase)
            ? null
            : Error(ErrorCodes.StatusInvalid,
                "The MSO revocation list's chain anchors on a different trust anchor than the credential's Document Signer.");
    }

    /// <summary>
    /// Whether <paramref name="chain"/>, already one valid path, continues to <paramref name="anchor"/>: its top
    /// is the anchor itself, or the platform builds the whole path through to the anchor, so every constraint on
    /// the way, the anchor's path length included, applies to it.
    /// </summary>
    // SPEC: EAA-6.2.10.1-06.1 and -06.1.1, and -06.2.1 for the certificate that signed the Document Signer. The
    // anchor need not be self-signed (-06.1 asks only for the certificate whose key "signed or sealed" the top),
    // and platforms do not agree on anchoring at a non-self-signed certificate placed in a trust store, so it is
    // never placed in one: the build is held to ending at it, by bytes, instead.
    private static bool ExtendsTo(List<X509Certificate2> chain, X509Certificate2 anchor, TimeProvider clock)
    {
        if (chain[^1].RawData.AsSpan().SequenceEqual(anchor.RawData))
        {
            return true;
        }

        List<X509Certificate2> path = [.. chain, anchor];
        using var build = BuildWithNothingTrusted(chain[0], path.Skip(1), clock);
        return PathHolds(build, path);
    }

    /// <summary>
    /// Whether <paramref name="issuer"/> is the certificate that signed <paramref name="certificate"/>: the
    /// platform's own chain from one to the other, ending at THAT certificate by bytes, with nothing wrong. The
    /// bytes matter: the platform also searches the account's own certificate stores for issuers, so a chain of
    /// two may end at a same-named certificate found there rather than at the one handed in. Both validity
    /// windows are read.
    /// </summary>
    private static bool SignedBy(X509Certificate2 certificate, X509Certificate2 issuer, TimeProvider clock)
    {
        using var build = BuildWithNothingTrusted(certificate, [issuer], clock);
        return PathHolds(build, [certificate, issuer]);
    }

    /// <summary>
    /// The platform's chain for <paramref name="leaf"/>, built from <paramref name="extra"/> alone with nothing
    /// trusted, so its statuses say whether each link verifies and each window is open, and nothing more.
    /// </summary>
    internal static X509Chain BuildWithNothingTrusted(X509Certificate2 leaf, IEnumerable<X509Certificate2> extra, TimeProvider clock)
    {
        var build = new X509Chain();
        build.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        build.ChainPolicy.VerificationTime = clock.GetUtcNow().UtcDateTime;
        // No certificate revocation check here: this library leaves certificate revocation to the trust seam.
        build.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        // Built from what the list and the MSO carry, and nothing a certificate points at.
        build.ChainPolicy.DisableCertificateDownloads = true;
        foreach (var certificate in extra)
        {
            build.ChainPolicy.ExtraStore.Add(certificate);
        }

        build.Build(leaf);
        return build;
    }

    /// <summary>
    /// Whether the build runs through every certificate of <paramref name="expected"/>, in its order, from the
    /// leaf, and nothing is wrong with any of them except that the last is not a configured root. Judged per
    /// element: the platform also searches the account's own certificate stores and may extend the chain past the
    /// last expected certificate, and what it finds there neither counts for nor against the list.
    /// </summary>
    internal static bool PathHolds(X509Chain build, List<X509Certificate2> expected)
    {
        var elements = build.ChainElements;
        // A bounds guard as much as a rule: a chain that stopped short also shows a status on the element it
        // stopped at, which the loop below refuses.
        if (elements.Count < expected.Count)
        {
            return false;
        }

        for (var i = 0; i < expected.Count; i++)
        {
            if (!elements[i].Certificate.RawData.AsSpan().SequenceEqual(expected[i].RawData))
            {
                return false;
            }

            var top = i == expected.Count - 1;
            if (!elements[i].ChainElementStatus.All(s => top && s.Status is X509ChainStatusFlags.PartialChain or X509ChainStatusFlags.UntrustedRoot))
            {
                return false;
            }
        }

        return true;
    }

    private static bool SameIssuer(X509Certificate2 candidate, X509Certificate2 documentSigner)
    {
        if (!candidate.IssuerName.RawData.AsSpan().SequenceEqual(documentSigner.IssuerName.RawData))
        {
            return false;
        }

        return AuthorityKeyIdentifier(candidate) is { } candidateKey
            && AuthorityKeyIdentifier(documentSigner) is { } signerKey
            && candidateKey.AsSpan().SequenceEqual(signerKey);
    }

    // By OID and decoded here, rather than by asking the collection for the typed extension, so the answer does
    // not depend on which extension types a platform version materialises on its own.
    private static byte[]? AuthorityKeyIdentifier(X509Certificate2 certificate) =>
        certificate.Extensions["2.5.29.35"] is { } extension
            ? new X509AuthorityKeyIdentifierExtension(extension.RawData, extension.Critical).KeyIdentifier?.ToArray()
            : null;

    private static VerificationError Error(string code, string message) => new() { Code = code, Message = message };
}
