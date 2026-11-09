using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Tessio.Verifier.Trust.Tests;

/// <summary>
/// x5c-resolved credentials must anchor on configured certificates. Identifier membership alone is
/// spoofable: anyone can put a trusted issuer's name in a self-signed certificate's SAN.
/// </summary>
public sealed class X5cAnchoringTests : IDisposable
{
    private const string Issuer = "https://issuer.example";

    private readonly ECDsa _legitKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _spoofKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly X509Certificate2 _legitCert;
    private readonly X509Certificate2 _spoofCert;

    public X5cAnchoringTests()
    {
        _legitCert = SelfSigned("CN=Legit Issuer", _legitKey);
        _spoofCert = SelfSigned("CN=Spoofed Issuer", _spoofKey); // same SAN, different key
    }

    /// <summary>
    /// The certificate request every certificate in this file starts from: the subject, the fixture's
    /// SAN, and basic constraints when it is to be a CA.
    /// </summary>
    /// <remarks>
    /// One owner for the SAN. It was written out three times before this existed, and a test whose
    /// certificate silently stops carrying the fixture host fails for a reason that has nothing to do
    /// with what the test is about.
    /// </remarks>
    private static CertificateRequest RequestFor(string subject, ECDsa key, bool isCa = false)
    {
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(new Uri(Issuer).Host);
        request.CertificateExtensions.Add(san.Build());
        if (isCa)
        {
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        }

        return request;
    }

    // The window is a parameter on both builders rather than a second builder next door, so a test
    // about expiry differs from a test about anchoring by the one value it is actually about.
    private static X509Certificate2 SelfSigned(
        string subject,
        ECDsa key,
        bool isCa = false,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null) =>
        RequestFor(subject, key, isCa).CreateSelfSigned(
            notBefore ?? DateTimeOffset.UtcNow.AddMinutes(-5),
            notAfter ?? DateTimeOffset.UtcNow.AddYears(1));

    /// <summary>An end-entity certificate issued by <paramref name="issuer"/>, not self-signed.</summary>
    private static X509Certificate2 SignedBy(
        X509Certificate2 issuer,
        string subject,
        ECDsa key,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null) =>
        RequestFor(subject, key).Create(
            issuer,
            notBefore ?? DateTimeOffset.UtcNow.AddMinutes(-5),
            notAfter ?? DateTimeOffset.UtcNow.AddMonths(6),
            Guid.NewGuid().ToByteArray());

    private static ReadOnlyMemory<byte>[] Chain(params X509Certificate2[] certificates) =>
        certificates.Select(c => new ReadOnlyMemory<byte>(c.RawData)).ToArray();

    /// <summary>
    /// SHA-256 over the DER as uppercase hex, computed independently of the implementation.
    /// </summary>
    /// <remarks>
    /// The resolver calls <c>GetCertHashString(HashAlgorithmName.SHA256)</c>, which reduces to the same
    /// two framework calls this does, so treat it as a near-copy rather than an independent oracle. What
    /// it genuinely pins is the three things the contract promises and the platform does not document:
    /// the input is the DER, the algorithm is SHA-256, and the case is upper.
    /// </remarks>
    private static string Sha256Hex(X509Certificate2 certificate) =>
        Convert.ToHexString(SHA256.HashData(certificate.RawData));

    [Fact]
    public async Task X5c_WithoutAnchors_IsRejected_EvenForListedIssuer()
    {
        var resolver = new StaticTrustListResolver([Issuer]);

        var status = await resolver.ResolveAsync(Issuer, Chain(_legitCert));

        Assert.False(status.Trusted);
        // Asserts the CAPABILITY the reason now states. It read "trust anchors" while the message said
        // the list held none and told the reader to configure some, which is a fact about the deployment
        // on a reason that travels to the caller. See RefusalDisclosureTests for that rule.
        Assert.Contains("does not accept an issuer key carried in a certificate", status.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task X5c_PinnedLeaf_IsTrusted()
    {
        var resolver = new StaticTrustListResolver([Issuer], trustAnchors: [_legitCert]);

        var status = await resolver.ResolveAsync(Issuer, Chain(_legitCert));

        Assert.True(status.Trusted);
    }

    /// <summary>
    /// The chain is "DER-encoded, leaf first" (ITrustListResolver), so an entry that is anything else is not
    /// read as one. A bundle around the pinned leaf is the case that matters: a laxer loader takes the leaf
    /// out of it and trusts the bundle.
    /// </summary>
    [Theory]
    [InlineData(X509ContentType.Pkcs12)]
    [InlineData(X509ContentType.Pkcs7)]
    public async Task X5c_EntryThatIsABundleAroundThePinnedLeaf_IsNotReadAsACertificate(X509ContentType type)
    {
        var resolver = new StaticTrustListResolver([Issuer], trustAnchors: [_legitCert]);
        var bundle = new X509Certificate2Collection(_legitCert).Export(type)!;

        await Assert.ThrowsAsync<CryptographicException>(
            () => resolver.ResolveAsync(Issuer, [new ReadOnlyMemory<byte>(bundle)]));
    }

    /// <summary>
    /// A trusted verdict has to say WHICH anchor produced it, by bytes, not only that one did.
    /// </summary>
    /// <remarks>
    /// The subject is asserted too, because it is what a human reads in a record, but the thumbprint is
    /// the identity: this ecosystem already carries two anchors differing only by country, and a
    /// same-name impostor is exactly what a subject comparison accepts.
    /// </remarks>
    [Fact]
    public async Task X5c_PinnedLeaf_NamesTheAnchorItMatched()
    {
        var resolver = new StaticTrustListResolver([Issuer], trustAnchors: [_legitCert]);

        var status = await resolver.ResolveAsync(Issuer, Chain(_legitCert));

        Assert.True(status.Trusted);
        Assert.Equal(_legitCert.Subject, status.TrustAnchorSubject);
        Assert.Equal(Sha256Hex(_legitCert), status.TrustAnchorThumbprint);
    }

    /// <summary>
    /// With two anchors configured that could each have been asked, the verdict names the one that
    /// actually validated the chain rather than the first one held.
    /// </summary>
    /// <remarks>
    /// THIS IS THE TEST THAT CAN FAIL. Asserting a non-null thumbprint would pass against an
    /// implementation that reported any configured anchor, or the first, which is the plausible wrong
    /// implementation and the one that would make an audit record say the wrong thing. The decoy is
    /// listed FIRST so "report _trustAnchors[0]" is red.
    /// </remarks>
    [Fact]
    public async Task X5c_TwoAnchorsConfigured_NamesTheOneThatValidated()
    {
        using var decoyKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var decoyRoot = SelfSigned("CN=Decoy Root", decoyKey, isCa: true);
        using var realKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var realRoot = SelfSigned("CN=Real Root", realKey, isCa: true);
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leaf = SignedBy(realRoot, "CN=Document Signer", leafKey);

        var resolver = new StaticTrustListResolver([Issuer], trustAnchors: [decoyRoot, realRoot]);

        var status = await resolver.ResolveAsync(Issuer, Chain(leaf));

        Assert.True(status.Trusted);
        Assert.Equal(Sha256Hex(realRoot), status.TrustAnchorThumbprint);
        Assert.NotEqual(Sha256Hex(decoyRoot), status.TrustAnchorThumbprint);
    }

    /// <summary>
    /// The identifier route names no anchor even when anchors ARE configured, because no certificate
    /// vouched for the key.
    /// </summary>
    /// <remarks>
    /// <b>The configured anchors are what give this test teeth.</b> Without them, the plausible wrong
    /// implementation, reporting an anchor the deployment happens to hold, has nothing to report and the
    /// null assertions pass against it. A mixed resolver is also the ordinary mdoc shape: anchors for the
    /// chain route and identifiers for the metadata route, in one instance. So a record that named an
    /// anchor here would assert that a certificate validated a key no certificate ever touched, which is
    /// worse than saying nothing.
    /// </remarks>
    [Fact]
    public async Task IdentifierRoute_NamesNoAnchor_EvenWithAnchorsConfigured()
    {
        var resolver = new StaticTrustListResolver([Issuer], source: "unit-test", trustAnchors: [_legitCert]);

        var status = await resolver.ResolveAsync(Issuer, []);

        Assert.True(status.Trusted);
        Assert.Equal("unit-test", status.TrustListSource);
        Assert.Null(status.TrustAnchorSubject);
        Assert.Null(status.TrustAnchorThumbprint);
    }

    /// <summary>
    /// A pinned anchor rejected for its own expiry still NAMES itself, because it matched.
    /// </summary>
    /// <remarks>
    /// The one refusal where the configured anchor is known: it matched by bytes and then failed its own
    /// validity window. "We trusted this exact certificate and its window had closed" is a different fact
    /// from "nothing matched", and a record collapsing the two loses the more useful one. Reverting that
    /// branch to report null reddens this.
    /// </remarks>
    [Fact]
    public async Task X5c_PinnedLeaf_RejectedForExpiry_StillNamesTheAnchorItMatched()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var expired = SelfSigned(
            "CN=Expired Pinned",
            key,
            notBefore: DateTimeOffset.UtcNow.AddYears(-2),
            notAfter: DateTimeOffset.UtcNow.AddYears(-1));
        var resolver = new StaticTrustListResolver([Issuer], source: "unit-test", trustAnchors: [expired]);

        var status = await resolver.ResolveAsync(Issuer, Chain(expired));

        Assert.False(status.Trusted);
        Assert.Contains("validity window", status.Reason, StringComparison.Ordinal);
        Assert.Equal("unit-test", status.TrustListSource);
        Assert.Equal(expired.Subject, status.TrustAnchorSubject);
        Assert.Equal(Sha256Hex(expired), status.TrustAnchorThumbprint);
    }

    /// <summary>
    /// A refusal where nothing matched names the list and no anchor.
    /// </summary>
    /// <remarks>
    /// The source assertion is the half with content, and it is the verdict a relying party has most
    /// reason to question. Asserting only that the anchor fields are null proves nothing here, because
    /// <c>NotTrusted</c> takes no anchor argument and so cannot set them either way.
    /// </remarks>
    [Fact]
    public async Task X5c_ThatDoesNotAnchor_NamesTheListButNoAnchor()
    {
        var resolver = new StaticTrustListResolver([Issuer], source: "unit-test", trustAnchors: [_legitCert]);

        var status = await resolver.ResolveAsync(Issuer, Chain(_spoofCert));

        Assert.False(status.Trusted);
        Assert.Equal("unit-test", status.TrustListSource);
        Assert.Null(status.TrustAnchorSubject);
        Assert.Null(status.TrustAnchorThumbprint);
    }

    [Fact]
    public async Task X5c_PinnedLeaf_OutsideItsOwnValidityWindow_IsRejected()
    {
        // A certificate states the period it may be relied on, and expiry is the control that bounds
        // how long a key stays trusted after it stops being looked after. Pinning says "this exact
        // certificate", not "this certificate forever": an operator who pinned a document signer two
        // years ago has no way to withdraw it if the window is not read.
        //
        // Both directions, because they fail differently. Expired is the one that happens on its own,
        // simply by time passing and nobody noticing. Not-yet-valid is the one that happens when a
        // certificate is rolled out early, and accepting it starts the trust before the issuer meant
        // it to.
        // THE WINDOWS ARE DELIBERATELY NARROW, an hour either side rather than a year. A year-wide
        // window makes this test pass whatever the implementation does about time zones, because no
        // offset on earth is twelve months. NotBefore and NotAfter are reported in LOCAL time, so an
        // implementation that compares them against a UTC clock is wrong by the machine's offset, and
        // an hour-wide window is what turns that into a failure on any machine not set to UTC.
        //
        // An hour is still far longer than a test run, so nothing here is a race.
        using var expiredKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var expired = SelfSigned(
            "CN=Expired Issuer", expiredKey,
            notBefore: DateTimeOffset.UtcNow.AddHours(-2), notAfter: DateTimeOffset.UtcNow.AddHours(-1));

        using var futureKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var future = SelfSigned(
            "CN=Future Issuer", futureKey,
            notBefore: DateTimeOffset.UtcNow.AddHours(1), notAfter: DateTimeOffset.UtcNow.AddHours(2));

        var expiredStatus = await new StaticTrustListResolver([Issuer], trustAnchors: [expired])
            .ResolveAsync(Issuer, Chain(expired));
        var futureStatus = await new StaticTrustListResolver([Issuer], trustAnchors: [future])
            .ResolveAsync(Issuer, Chain(future));

        Assert.False(expiredStatus.Trusted);
        Assert.Contains("validity", expiredStatus.Reason, StringComparison.OrdinalIgnoreCase);
        Assert.False(futureStatus.Trusted);
        Assert.Contains("validity", futureStatus.Reason, StringComparison.OrdinalIgnoreCase);

        // THE CONTROL, and it does two jobs.
        //
        // First, without a live pinned leaf still passing, a resolver that rejected every pinned
        // certificate would satisfy both assertions above.
        //
        // Second, its window is narrow ON PURPOSE, half an hour either side of now. A comparison that
        // forgets local time shifts both bounds together, and a shift moves a narrow window that
        // straddles now completely off it, in EITHER direction. The two rejections above only catch
        // that shift from one side, because a window already in the past stays in the past when it
        // moves further back. This one catches it from both.
        using var narrowKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var narrow = SelfSigned(
            "CN=Barely Valid Issuer", narrowKey,
            notBefore: DateTimeOffset.UtcNow.AddMinutes(-30), notAfter: DateTimeOffset.UtcNow.AddMinutes(30));

        Assert.True((await new StaticTrustListResolver([Issuer], trustAnchors: [narrow])
            .ResolveAsync(Issuer, Chain(narrow))).Trusted);
        Assert.True((await new StaticTrustListResolver([Issuer], trustAnchors: [_legitCert])
            .ResolveAsync(Issuer, Chain(_legitCert))).Trusted);
    }

    /// <summary>A clock stopped at one instant, matching the shape the other suites use.</summary>
    private sealed class StoppedClock(DateTimeOffset at) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => at;
    }

    [Fact]
    public async Task X5c_PinnedLeaf_IsJudgedAtTheVerificationTime_NotTheWallClock()
    {
        // Frozen artifacts are verified at a chosen instant rather than at now: a published
        // conformance vector, a replayed presentation, a stored record being re-checked. Their
        // certificates have long since expired in wall-clock terms, and the answer has to come from
        // the clock the caller supplied, or the trust half of a verification contradicts every other
        // half of the same verification.
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var vintage = SelfSigned(
            "CN=Vintage Issuer", key,
            notBefore: new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero),
            notAfter: new DateTimeOffset(2021, 1, 1, 0, 0, 0, TimeSpan.Zero));

        var duringItsLife = new StoppedClock(new DateTimeOffset(2020, 6, 1, 0, 0, 0, TimeSpan.Zero));
        var trustedThen = await new StaticTrustListResolver(
                [Issuer], trustAnchors: [vintage], clock: duringItsLife)
            .ResolveAsync(Issuer, Chain(vintage));

        // THE CONTROL, and it is what makes the line above mean anything. The same certificate on the
        // default clock is refused, so the acceptance is the supplied clock doing the work rather
        // than the validity check quietly not running.
        var trustedNow = await new StaticTrustListResolver([Issuer], trustAnchors: [vintage])
            .ResolveAsync(Issuer, Chain(vintage));

        Assert.True(trustedThen.Trusted);
        Assert.False(trustedNow.Trusted);
    }

    [Fact]
    public async Task X5c_AnchoredChain_IsJudgedAtTheSameInstantAsAPinnedLeaf()
    {
        // The two branches answer one question, so they must answer it at one instant. X509Chain reads
        // the system clock unless told otherwise, so a resolver whose pinned branch honours the caller's
        // clock and whose chain branch does not gives an answer that depends on whether the operator
        // happened to pin a leaf or a root. That is not a policy anyone chose.
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ca = SelfSigned(
            "CN=Vintage CA", caKey, isCa: true,
            notBefore: new DateTimeOffset(2019, 1, 1, 0, 0, 0, TimeSpan.Zero),
            notAfter: new DateTimeOffset(2022, 1, 1, 0, 0, 0, TimeSpan.Zero));

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leaf = SignedBy(
            ca, "CN=Vintage Leaf", leafKey,
            notBefore: new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero),
            notAfter: new DateTimeOffset(2021, 1, 1, 0, 0, 0, TimeSpan.Zero));

        var duringItsLife = new StoppedClock(new DateTimeOffset(2020, 6, 1, 0, 0, 0, TimeSpan.Zero));
        var thenStatus = await new StaticTrustListResolver(
                [Issuer], trustAnchors: [ca], clock: duringItsLife)
            .ResolveAsync(Issuer, Chain(leaf, ca));

        // THE CONTROL. On the default clock the same chain is long expired and must be refused, so the
        // acceptance above is the clock being honoured rather than expiry going unchecked on this path.
        var nowStatus = await new StaticTrustListResolver([Issuer], trustAnchors: [ca])
            .ResolveAsync(Issuer, Chain(leaf, ca));

        Assert.True(thenStatus.Trusted);
        Assert.False(nowStatus.Trusted);
    }

    [Fact]
    public async Task X5c_SelfSignedSpoof_WithSameName_IsRejected()
    {
        var resolver = new StaticTrustListResolver([Issuer], trustAnchors: [_legitCert]);

        // The attack from the assessment: a listed issuer identifier presented with a
        // self-signed certificate the attacker controls.
        var status = await resolver.ResolveAsync(Issuer, Chain(_spoofCert));

        Assert.False(status.Trusted);
        Assert.Contains("does not anchor", status.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task X5c_LeafSignedByCaAnchor_IsTrusted()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ca = SelfSigned("CN=Test CA", caKey, isCa: true);

        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leaf = SignedBy(ca, "CN=CA-Issued Issuer", leafKey);

        var resolver = new StaticTrustListResolver([Issuer], trustAnchors: [ca]);

        Assert.True((await resolver.ResolveAsync(Issuer, Chain(leaf, ca))).Trusted);
        Assert.False((await resolver.ResolveAsync(Issuer, Chain(_spoofCert))).Trusted);
    }

    [Fact]
    public async Task MetadataPath_EmptyX5c_StillTrustsByIdentifier()
    {
        var resolver = new StaticTrustListResolver([Issuer], trustAnchors: [_legitCert]);

        Assert.True((await resolver.ResolveAsync(Issuer, [])).Trusted);
    }

    [Fact]
    public async Task X5c_AnchoredChain_IsTrusted_EvenWhenIssuerIdentifierIsNotListed()
    {
        // The ISO mdoc trust model: the issuer identifier is a Document Signer subject DN that no
        // identifier list enumerates, and trust is the X.509 chain. A pinned leaf (or an anchored
        // chain) must be trusted regardless of whether its identifier appears in the list. Before this
        // was fixed, the identifier gate rejected every mdoc before the anchor check could run.
        var resolver = new StaticTrustListResolver(["https://unrelated.example"], trustAnchors: [_legitCert]);

        var status = await resolver.ResolveAsync("CN=Legit Issuer", Chain(_legitCert));

        Assert.True(status.Trusted);
    }

    [Fact]
    public async Task X5c_UnanchoredChain_IsRejected_EvenWhenIssuerIdentifierIsNotListed()
    {
        // Dropping the identifier gate for x5c must not degrade into "trust any certificate": an
        // unlisted issuer whose chain does not anchor is still rejected.
        var resolver = new StaticTrustListResolver(["https://unrelated.example"], trustAnchors: [_legitCert]);

        var status = await resolver.ResolveAsync("CN=Spoofed Issuer", Chain(_spoofCert));

        Assert.False(status.Trusted);
        Assert.Contains("does not anchor", status.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MetadataPath_UnlistedIssuer_IsRejected()
    {
        // The identifier gate still governs metadata-resolved (empty-x5c) credentials.
        var resolver = new StaticTrustListResolver([Issuer], trustAnchors: [_legitCert]);

        var status = await resolver.ResolveAsync("https://not-listed.example", []);

        Assert.False(status.Trusted);
        Assert.Contains("not on the configured trust list", status.Reason, StringComparison.Ordinal);
    }

    public void Dispose()
    {
        _legitCert.Dispose();
        _spoofCert.Dispose();
        _legitKey.Dispose();
        _spoofKey.Dispose();
    }
}
