using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Tessio.Verifier.Trust;

/// <summary>
/// Trust resolver backed by a fixed set of trusted issuer identifiers, plus optional trust-anchor
/// certificates for issuers that present an X.509 chain. Suitable for development, tests and small
/// deployments. Load the identifier set from a JSON file or URL with <see cref="TrustListLoader"/>.
/// </summary>
/// <remarks>
/// <para>
/// The trust mechanism depends on how the key was resolved. A key resolved from issuer metadata is
/// trusted exactly when its issuer identifier is on the configured list, proven by control of the
/// issuer's HTTPS origin. A key resolved from an <c>x5c</c> (or <c>x5chain</c>) header is trusted when
/// its chain anchors on one of <c>trustAnchors</c> (or the leaf itself is a pinned anchor); the
/// identifier is <em>not</em> required to be on the list, because anyone can put any name in a
/// certificate, so the X.509 chain is the proof. This is the only mechanism ISO mdoc has, where the
/// issuer identifier is a Document Signer subject DN that no list enumerates. Binding the certificate
/// to a claimed issuer, where that applies, is the caller's concern: SD-JWT VC ties <c>iss</c> to a
/// certificate SAN before this point, but ONLY where the leaf asserts a name. A leaf that asserts none
/// cannot contradict <c>iss</c>, and the specification makes its subject the issuer, so for that leaf
/// anchoring is the whole of the proof. Without configured anchors, x5c credentials are rejected.
/// </para>
/// <para>
/// Either way the certificate must be inside its own validity window, read at <c>clock</c>. Anchoring
/// is not the whole answer: a pinned certificate whose window has closed is refused, exactly as the
/// chain check refuses an expired one on the path that builds a chain.
/// </para>
/// <para>
/// <b>What a trusted issuer is trusted FOR.</b> This resolver answers one question, "is this signer
/// trusted", and callers ask it about more than credential issuance: a Token Status List token's
/// signer is judged here too. So adding an entry to <c>trustedIssuers</c> or to <c>trustAnchors</c>
/// authorises that party for every purpose the deployment asks about, including signing revocation
/// status for credentials issued by somebody else. That is the cost of a flat list, and it is worth
/// knowing before adding an entry to clear a rejection.
/// </para>
/// <para>
/// This is the open-source end of the trust seam. Production EU trust (LOTL, national lists, WRPAC)
/// is a separate concern behind the same <see cref="ITrustListResolver"/> interface.
/// </para>
/// </remarks>
public sealed class StaticTrustListResolver : ITrustListResolver
{
    /// <summary>
    /// Set to <c>1</c> to add this resolver's own configuration to a refusal reason: every configured
    /// anchor's subject and subject key identifier.
    /// </summary>
    /// <remarks>
    /// <para>
    /// OFF BY DEFAULT BECAUSE A REASON REACHES THE CALLER. The reason becomes a
    /// <c>VerificationResult.Errors[].Message</c>. Where the ASP.NET Core package's endpoints are
    /// mapped, the session status resource and its SSE stream serialise that to whoever holds a session
    /// id, and the start endpoint hands one to anybody. So a refusal used to give an anonymous caller
    /// the full list of parties a deployment anchors on, which is its own fact about a deployment
    /// regardless of each certificate being public. Nothing about the caller's own credential needed it.
    /// </para>
    /// <para>
    /// The inventory is still what an operator wants when the names look right and the chain will not
    /// build, so it is one environment variable away rather than deleted. Turn it on, read the reason,
    /// turn it off.
    /// </para>
    /// </remarks>
    private const string DumpConfiguredAnchorsVariable = "TESSIO_TRUST_DUMP_ANCHORS";

    /// <summary>
    /// Set to <c>1</c> to add the offending leaf certificate, base64 DER, to a refusal reason.
    /// </summary>
    /// <remarks>
    /// Separate from <see cref="DumpConfiguredAnchorsVariable"/> because the two disclose different
    /// things. This one echoes the certificate that arrived in the presentation, which is the issuer's
    /// document signer rather than anything this deployment chose. Still off by default, because it is
    /// long and because a reason travels.
    /// </remarks>
    private const string DumpLeafVariable = "TESSIO_TRUST_DUMP_LEAF";

    private readonly HashSet<string> _trustedIssuers;
    private readonly List<X509Certificate2> _trustAnchors;
    private readonly string _source;
    private readonly TimeProvider _clock;

    /// <summary>Creates a resolver trusting exactly the given issuer identifiers.</summary>
    /// <param name="trustedIssuers">Issuer identifiers (iss values or certificate subjects).</param>
    /// <param name="source">Optional label reported as <see cref="IssuerTrustStatus.TrustListSource"/>.</param>
    /// <param name="trustAnchors">
    /// Root or pinned certificates that x5c chains must anchor on. Credentials presenting an x5c
    /// chain are rejected when this is empty, and an anchor is only usable inside its own validity
    /// window.
    /// </param>
    /// <param name="clock">
    /// Time source for every certificate validity decision here, on both the pinned-leaf and the
    /// chain-building path; system clock when null. Pass the same one given to the verifier, or a
    /// presentation verified at a chosen instant is judged against wall-clock time instead, and the
    /// two disagree for exactly the certificates whose window has since closed.
    /// </param>
    public StaticTrustListResolver(
        IEnumerable<string> trustedIssuers,
        string source = "static",
        IEnumerable<X509Certificate2>? trustAnchors = null,
        TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(trustedIssuers);
        _trustedIssuers = new HashSet<string>(trustedIssuers, StringComparer.Ordinal);
        _trustAnchors = trustAnchors?.ToList() ?? [];
        _source = source;
        _clock = clock ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public Task<IssuerTrustStatus> ResolveAsync(string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(x5c);

        // The trust mechanism is chosen by how the issuer key was resolved, not by the credential
        // format. A key resolved from issuer metadata (no x5c) is trusted exactly when its identifier
        // is on the list: control of the iss HTTPS origin is what proved that identifier.
        if (x5c.Length == 0)
        {
            return _trustedIssuers.Contains(issuer)
                ? Trusted()
                : NotTrusted($"Issuer '{issuer}' is not on the configured trust list.", null);
        }

        // A key resolved from an x5c chain is trusted by anchoring, not by identifier membership: the
        // identifier is only as good as the certificate carrying it, and anyone can put any name in a
        // certificate. This is the only mechanism ISO mdoc has, where the identifier is a Document
        // Signer subject DN that no list enumerates. The caller binds the certificate to a claimed
        // issuer where that applies (SD-JWT VC ties iss to a certificate SAN before this point).
        if (_trustAnchors.Count == 0)
        {
            // STATE THE CAPABILITY, NOT THE CONFIGURATION. This used to report that the list held no
            // anchors and tell the reader to configure some: an instruction meant for an operator,
            // delivered to whoever presented the credential, describing what the deployment does and
            // does not hold. What the presenter needs is that this route is closed here. The operator's
            // half of the answer is behind the dump, where the empty list says it plainly.
            return NotTrusted(
                $"Issuer '{issuer}' presented an X.509 chain. This trust list does not accept an issuer "
                + "key carried in a certificate, which is trusted by anchoring rather than by identifier."
                + ConfiguredAnchorsDump(),
                null);
        }

        var (anchored, because, anchor) = ChainAnchorsOnConfiguredRoot(x5c);
        if (anchored)
        {
            return Trusted(anchor);
        }

        // DO NOT SAY "does not anchor" WHEN IT DID. A pinned certificate that matched by bytes and then
        // failed its own validity window comes back with an anchor named, and reporting that as a
        // non-anchoring failure sends the reader hunting for a missing or wrong certificate instead of an
        // expired one. Two different causes deserve two different sentences, and the anchor is the tell.
        return anchor is null
            ? NotTrusted(
                $"The certificate chain presented by '{issuer}' does not anchor on a configured trust anchor. "
                + $"Chain status: {because}",
                null)
            : NotTrusted(
                $"The certificate chain presented by '{issuer}' anchors on a configured trust anchor that "
                + $"cannot be relied on. {because}",
                anchor);
    }

    /// <summary>
    /// The anchor a verdict rested on, as two strings rather than a certificate.
    /// </summary>
    /// <remarks>
    /// Strings, deliberately. The certificates this is derived from are disposed when
    /// <see cref="ChainAnchorsOnConfiguredRoot"/> returns, so handing back an
    /// <see cref="X509Certificate2"/> would hand back a disposed object, and the failure would appear
    /// only at the caller. Reading both values while the certificate is alive makes that impossible.
    /// </remarks>
    private readonly record struct MatchedAnchor(string Subject, string Thumbprint)
    {
        /// <summary>SHA-256 over the DER, uppercase hex.</summary>
        /// <remarks>
        /// <para>
        /// <b>Not <see cref="X509Certificate2.Thumbprint"/>, which is SHA-1.</b> This value exists so a
        /// record read years later can say which anchor, exactly. SHA-1 has practical chosen-prefix
        /// collisions, and certificates are the historical target for exactly that, so a recorded SHA-1
        /// digest is a weaker statement than the record implies. Nothing here depends on the digest for
        /// a trust decision, and that is the reason to get it right rather than a reason not to.
        /// </para>
        /// <para>
        /// <b>Why a digest and not a Subject Key Identifier.</b> A digest identifies the certificate, an
        /// SKI follows the key, and they answer different questions. The question here is which artefact
        /// was relied on, so a CA that rotates its certificate while keeping its key SHOULD produce a
        /// different value: we relied on a different certificate. An SKI would be the right field for
        /// "which authority, across rotations", and it is deliberately not added, because no caller asks
        /// that yet.
        /// </para>
        /// </remarks>
        internal static MatchedAnchor From(X509Certificate2 anchor) =>
            new(anchor.Subject, anchor.GetCertHashString(HashAlgorithmName.SHA256));
    }

    /// <summary>
    /// Whether the chain anchors, and when it does not, what the platform said. "Does not anchor" on
    /// its own sends the reader hunting for a wrong certificate when the real cause is often a
    /// validity window, a missing basic-constraints flag or an unsupported critical extension.
    /// </summary>
    private (bool Anchored, string? Because, MatchedAnchor? Anchor) ChainAnchorsOnConfiguredRoot(
        ReadOnlyMemory<byte>[] x5c)
    {
        var certificates = x5c.Select(der => DerCertificate.Load(der.ToArray())).ToList();
        try
        {
            var leaf = certificates[0];

            // Pinned leaf: the exact end-entity certificate was configured as an anchor. Its own bytes
            // are the proof, so there is no chain to build and no signature to verify.
            //
            // ITS VALIDITY WINDOW IS STILL READ. Pinning says "this exact certificate", not "this
            // certificate forever", and the window is what bounds how long a key stays trusted after
            // anyone stops looking after it. Without this, a document signer pinned two years ago goes
            // on verifying credentials, and there is no way to withdraw it except by editing the anchor
            // list, which is the one thing expiry exists to avoid depending on.
            //
            // Read here rather than by sending this case through the X509Chain below, because a pinned
            // leaf is frequently not self-signed, and platforms do not agree on how to treat a
            // non-self-signed certificate placed in a trust store. The answer must not depend on the
            // operating system underneath.
            // The CONFIGURED anchor rather than the leaf. Byte equality is the branch predicate, so both
            // report the same two strings, and naming the anchor is what the field means: the leaf only
            // happens to equal it. The configured list also outlives this method, where the leaf does
            // not, so the choice stays correct if this ever returns the certificate itself.
            var pinned = _trustAnchors.Find(anchor => anchor.RawData.AsSpan().SequenceEqual(leaf.RawData));
            if (pinned is not null)
            {
                // NAMED ON THE REFUSAL TOO. This is the one rejection where the configured anchor IS
                // known: it matched by bytes and then failed its own validity window. "We trusted this
                // exact certificate and its window had closed" is a different fact from "nothing
                // matched", and a record that cannot tell them apart loses the more useful one.
                // READ THE CLOCK ONCE. This test reads _clock, so calling it twice, once for the verdict
                // and once to pick the reason, lets the two disagree across a validity boundary: trusted
                // with an expiry reason, or refused with no reason at all. The odds are tiny and the
                // record is the whole point of the field, so a self-contradicting one is not acceptable.
                var withinWindow = IsWithinItsValidityWindow(leaf);
                return (
                    withinWindow,
                    withinWindow
                        ? null
                        : $"The pinned certificate '{leaf.Subject}' is outside its own validity window "
                          + $"({leaf.NotBefore.ToUniversalTime():u} to {leaf.NotAfter.ToUniversalTime():u}).",
                    MatchedAnchor.From(pinned));
            }

            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            // THE SAME INSTANT THE PINNED BRANCH ABOVE USES. X509Chain reads the system clock unless
            // it is told otherwise, so leaving this unset would judge one question at two different
            // times: a caller replaying a stored presentation would get their chosen instant when the
            // operator pinned a leaf, and wall-clock time when the operator pinned a root. Which
            // branch runs is a configuration detail, and it must not decide what "expired" means.
            chain.ChainPolicy.VerificationTime = _clock.GetUtcNow().UtcDateTime;
            // Certificate revocation is the production trust layer's concern; credential revocation
            // is checked separately via Token Status Lists.
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            // The chain is built from what was presented and what is configured, and nothing else. A
            // certificate can name a URL for its issuer's certificate, and the platform follows it
            // unless told not to, so the answer would depend on a host the certificate chose. For an
            // SD-JWT VC, HAIP 1.0 Final section 6.1.1 requires the x5c header to carry the trust chain
            // without the anchor, so nothing is missing. A Token Status List signer may send its own
            // certificate alone (section 6.1), and it anchors when the certificate that issued it is
            // configured alongside its root.
            chain.ChainPolicy.DisableCertificateDownloads = true;
            foreach (var anchor in _trustAnchors)
            {
                chain.ChainPolicy.CustomTrustStore.Add(anchor);
            }

            foreach (var intermediate in certificates.Skip(1))
            {
                chain.ChainPolicy.ExtraStore.Add(intermediate);
            }

            if (chain.Build(leaf))
            {
                // The LAST element is the anchor the platform settled on. Taking it from the built chain
                // rather than guessing from _trustAnchors matters when two configured anchors could each
                // have validated this leaf: this names the one that did. Ordering is documented: the
                // collection runs leaf-first to trust anchor last, consistently across platforms.
                var root = chain.ChainElements[^1].Certificate;

                // AND IT MUST BE ONE OF OURS, BY BYTES. The presented chain is caller-supplied, and a
                // record naming a certificate the deployment never configured would be worse than one
                // naming none, because it would be believed.
                //
                // THIS IS AN ASSERTION ON A PLATFORM CONTRACT, NOT A RECOVERABLE CASE, and it has no
                // test for that reason: under CustomRootTrust a build succeeds only by terminating in
                // CustomTrustStore, so reaching the throw means the platform did something its contract
                // rules out, and every anchor this process attributes is then suspect. Returning the
                // verdict with the attribution quietly dropped was the first shape, and it is the
                // error-masking fallback this repository forbids: null would have read as "no certificate
                // was involved", which is the identifier route, so the record would have been wrong in a
                // way nothing could detect. Loud beats a believable wrong record in an audit trail.
                var configured = _trustAnchors.Find(a => a.RawData.AsSpan().SequenceEqual(root.RawData))
                    ?? throw new InvalidOperationException(
                        "A certificate chain was built against a custom trust store and terminated on a "
                        + "certificate that is not in it. Trust anchor attribution cannot be relied on in "
                        + "this process.");
                return (true, null, MatchedAnchor.From(configured));
            }

            var status = string.Join("; ", chain.ChainStatus
                .Select(s => $"{s.Status}: {s.StatusInformation.Trim()}")
                .DefaultIfEmpty("no status reported by the platform"));

            // Key identifiers, not just names. When the names match and the chain still fails, the
            // cause is almost always a certificate authority that was regenerated under the same
            // distinguished name with a new key: the leaf points at the old key, the anchor holds the
            // new one, and comparing subjects alone makes that look like it should have worked.
            var wantedKey = leaf.Extensions
                .OfType<X509AuthorityKeyIdentifierExtension>()
                .FirstOrDefault()?.KeyIdentifier;

            // EVERYTHING BELOW IS ABOUT THE CALLER'S OWN CERTIFICATE. What this deployment holds is
            // added only on request, because the reason travels to the caller.
            // WHERE THE PRESENTED CHAIN STOPS. A signer may legitimately send its own certificate alone
            // (a Token Status List signer under HAIP 1.0 Final section 6.1), and then the certificate that
            // issued it has to be one this resolver holds. Saying where the chain ends, and what it names
            // above that, is what points an operator at the certificate to install.
            // Only when the platform says the chain is incomplete, so a chain refused for another reason,
            // an expired leaf say, does not send the reader looking for a certificate that is not missing.
            var top = certificates[^1];
            var endsBelowARoot = chain.ChainStatus.Any(s => s.Status.HasFlag(X509ChainStatusFlags.PartialChain))
                && !top.SubjectName.RawData.AsSpan().SequenceEqual(top.IssuerName.RawData);
            return (false,
                $"{status} The chain's leaf names its issuer as '{leaf.Issuer}'. "
                + $"Leaf's authority key id: {(wantedKey is null ? "none" : Convert.ToHexString(wantedKey.Value.Span))}."
                + (endsBelowARoot
                    ? $" The chain carries no certificate above '{top.Subject}', whose issuer is '{top.Issuer}'."
                    : string.Empty)
                + ConfiguredAnchorsDump()
                + LeafDump(leaf),
                null);
        }
        finally
        {
            foreach (var certificate in certificates)
            {
                certificate.Dispose();
            }
        }
    }

    /// <summary>
    /// The anchors this resolver holds, subject and subject key identifier each, when
    /// <see cref="DumpConfiguredAnchorsVariable"/> asks for them. Empty otherwise.
    /// </summary>
    /// <remarks>
    /// Both together, because the pair is what resolves the case this exists for: matching subjects with
    /// differing key identifiers is a certificate authority regenerated under its old name, and either
    /// value alone leaves that looking like it should have worked.
    /// </remarks>
    private string ConfiguredAnchorsDump()
    {
        if (Environment.GetEnvironmentVariable(DumpConfiguredAnchorsVariable) != "1")
        {
            return string.Empty;
        }

        // "none" rather than an empty tail, because an empty list is the whole answer on the branch that
        // refuses every x5c chain, and a reader who asked for the inventory deserves to be told there is
        // not one instead of reading a sentence that trails off.
        var anchors = _trustAnchors.Count == 0
            ? "none"
            : string.Join(" | ", _trustAnchors.Select(a =>
            {
                var ski = a.Extensions.OfType<X509SubjectKeyIdentifierExtension>()
                    .FirstOrDefault()?.SubjectKeyIdentifier ?? "none";
                return $"{a.Subject} (subject key id {ski})";
            }));
        return $" Configured anchors: {anchors}.";
    }

    /// <summary>
    /// The presented leaf as base64 DER, when <see cref="DumpLeafVariable"/> asks for it. Empty
    /// otherwise.
    /// </summary>
    private static string LeafDump(X509Certificate2 leaf) =>
        Environment.GetEnvironmentVariable(DumpLeafVariable) == "1"
            ? $" Leaf (base64 DER): {Convert.ToBase64String(leaf.RawData)}"
            : string.Empty;

    /// <summary>
    /// Whether the certificate may be relied on at the verification time, by the window it states.
    /// </summary>
    /// <remarks>
    /// Both sides are compared in UTC, and that conversion is the whole point of the method.
    /// <see cref="X509Certificate2.NotBefore"/> and <see cref="X509Certificate2.NotAfter"/> are
    /// reported in LOCAL time. A <see cref="DateTime"/> comparison ignores
    /// <see cref="DateTime.Kind"/> and compares ticks, so comparing them raw against a UTC clock is
    /// wrong by the machine's offset: east of Greenwich it keeps accepting a certificate for hours
    /// after it expired. The error is invisible on a server set to UTC, which is most of them, and
    /// appears only on someone's laptop.
    /// </remarks>
    private bool IsWithinItsValidityWindow(X509Certificate2 certificate)
    {
        var nowUtc = _clock.GetUtcNow().UtcDateTime;
        return nowUtc >= certificate.NotBefore.ToUniversalTime()
            && nowUtc <= certificate.NotAfter.ToUniversalTime();
    }

    /// <param name="anchor">
    /// The anchor that vouched for the key, or null on the identifier route, where the list carried the
    /// identifier and no certificate was involved. Null here is a fact about the mechanism, not a
    /// missing value.
    /// </param>
    private Task<IssuerTrustStatus> Trusted(MatchedAnchor? anchor = null) =>
        Task.FromResult(new IssuerTrustStatus
        {
            Trusted = true,
            TrustListSource = _source,
            TrustAnchorSubject = anchor?.Subject,
            TrustAnchorThumbprint = anchor?.Thumbprint,
        });

    /// <remarks>
    /// <b>A refusal names the list that refused.</b> A rejected presentation is the verdict a relying
    /// party has most reason to question, so "not trusted" without naming the list that was asked
    /// answers nothing. <see cref="IssuerTrustStatus.TrustListSource"/> is documented as the list "that
    /// produced the verdict" rather than the list that accepted, and <c>ContractSmokeTests</c> constructs
    /// an untrusted status carrying one. Instance rather than static for that single reason.
    /// </remarks>
    /// <param name="reason">Why the verdict is false, in a sentence a reader can act on.</param>
    /// <param name="anchor">
    /// The configured anchor this refusal DID match, where one was matched and then rejected for its own
    /// validity window. Null where nothing matched, which is every other refusal. Required rather than
    /// defaulted, so a future refusal path has to state which case it is instead of silently reporting
    /// the weaker one.
    /// </param>
    private Task<IssuerTrustStatus> NotTrusted(string reason, MatchedAnchor? anchor) =>
        Task.FromResult(new IssuerTrustStatus
        {
            Trusted = false,
            TrustListSource = _source,
            TrustAnchorSubject = anchor?.Subject,
            TrustAnchorThumbprint = anchor?.Thumbprint,
            // A reason quotes the presented chain's certificate names, which the presenter chose.
            Reason = MessageText.OneLine(reason),
        });
}
