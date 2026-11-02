using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Tessio.Verifier.Core;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// MSO revocation, both mechanisms, as Implementing Regulation (EU) 2024/2979, Annex II (as replaced by 2026/1731), clause
/// EAA-6.2.10.1 requires them: the credential's entry decides, and a list is trusted only through the
/// credential that referenced it.
/// </summary>
public sealed partial class MsoRevocationTests : IDisposable
{
    private const string ListUri = "https://issuer.example/lists/1";
    private static readonly byte[] OurId = [0x01, 0x02, 0x03, 0x04];

    private readonly MdocTestBuilder _builder = new();
    private readonly RevocationListBuilder _list;
    private readonly RevocationListHttp _http = new();

    public MsoRevocationTests()
    {
        _list = new RevocationListBuilder(_builder.IacaCertificate, _builder.IacaKey);
    }

    private MdocVerifier Verifier(
        ITrustListResolver? trust = null, MdocVerifierOptions? options = null, params X509Certificate2[] extraAnchors) => new(
        trust ?? new StaticTrustListResolver([], source: "mdoc-test", trustAnchors: [_builder.IacaCertificate, .. extraAnchors]),
        options, clock: null, httpClient: new HttpClient(_http));

    private static PresentedCredential Credential(MdocTestBuilder builder) =>
        new() { Format = MdocVerifier.Format, RawValue = builder.BuildBase64Url() };

    private static MdocVerificationContext Context(MdocTestBuilder builder) => new()
    {
        ExpectedDocType = MdocTestBuilder.DefaultDocType,
        ClientId = builder.ClientId,
        Nonce = builder.Nonce,
        EncryptionKeyThumbprint = builder.EncryptionKeyThumbprint,
        ResponseUri = builder.ResponseUri,
    };

    private Task<VerificationResult> VerifyAsync(MdocVerifier? verifier = null) =>
        (verifier ?? Verifier()).VerifyAsync(Credential(_builder), Context(_builder));

    private static string Codes(VerificationResult result) => string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}"));

    private static void AssertRefused(VerificationResult result, string code)
    {
        Assert.False(result.IsValid);
        Assert.True(result.Errors.Any(e => e.Code == code), Codes(result));
    }

    // ---- The status list mechanism ----

    [Fact]
    public async Task StatusList_ValidEntry_Passes_AndAsksForTheCwtType()
    {
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(1, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 1, 0, 1));

        var result = await VerifyAsync();

        Assert.True(result.IsValid, Codes(result));
        var (url, accept) = Assert.Single(_http.Requested);
        Assert.Equal(ListUri, url);
        Assert.Equal("application/statuslist+cwt", accept);
    }

    [Fact]
    public async Task AListSignedUnderEsp256_IsRead()
    {
        // SPEC: HAIP 1.0 section 7 names COSE -9 beside -7 for status information.
        _list.Esp256Signature = true;
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(2, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0, 0, 1));

        // Read, not merely accepted: entry 2 is revoked, which is only known once the signature verified.
        AssertRefused(await VerifyAsync(), ErrorCodes.CredentialRevoked);
    }

    [Fact]
    public async Task AListSignedUnderEsp256_ByAnotherKey_IsRefused()
    {
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _list.Esp256Signature = true;
        _list.SignWith = other;
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
    }

    [Fact]
    public async Task StatusList_RevokedEntry_Fails()
    {
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(2, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0, 0, 1));

        AssertRefused(await VerifyAsync(), ErrorCodes.CredentialRevoked);
    }

    [Fact]
    public async Task StatusList_IndexOutsideTheList_Fails()
    {
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(64, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0, 0, 0));

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
    }

    [Theory]
    [InlineData(long.MaxValue)]
    [InlineData(2305843009213693952)] // 2^61: times 8 bits wraps to exactly 0, the first entry
    public async Task StatusList_AnIndexWhoseBitOffsetOverflows_IsOutsideTheList(long idx)
    {
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(idx, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 8, 0, 0));

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
    }

    // ---- The identifier list mechanism ----

    [Fact]
    public async Task IdentifierList_Listed_Fails_AndAsksForTheIdentifierListType()
    {
        _builder.MsoStatus = RevocationListBuilder.IdentifierListReference(OurId, ListUri);
        _http.Serve(ListUri, _list.IdentifierList(ListUri, [0x09], OurId));

        AssertRefused(await VerifyAsync(), ErrorCodes.CredentialRevoked);
        Assert.Equal("application/identifierlist+cwt", Assert.Single(_http.Requested).Accept);
    }

    [Fact]
    public async Task IdentifierList_NotListed_Passes()
    {
        _builder.MsoStatus = RevocationListBuilder.IdentifierListReference(OurId, ListUri);
        _http.Serve(ListUri, _list.IdentifierList(ListUri, [0x09], [0x01, 0x02, 0x03]));

        var result = await VerifyAsync();

        Assert.True(result.IsValid, Codes(result));
    }

    [Fact]
    public async Task IdentifierList_UnderTheStatusListClaimKey_IsRefused()
    {
        // The shape one public producer emits: the identifiers under 65533. EAA-6.2.10.1-09 puts them under
        // 65530, and a list read from the wrong key would answer "not revoked" for everyone.
        _list.IdentifierListClaim = 65533;
        _builder.MsoStatus = RevocationListBuilder.IdentifierListReference(OurId, ListUri);
        _http.Serve(ListUri, _list.IdentifierList(ListUri, OurId));

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
    }

    [Fact]
    public async Task IdentifierList_AlsoCarryingAStatusList_IsRefused()
    {
        _list.AddStatusListClaimToIdentifierList = true;
        _builder.MsoStatus = RevocationListBuilder.IdentifierListReference(OurId, ListUri);
        _http.Serve(ListUri, _list.IdentifierList(ListUri, [0x09]));

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
    }

    // ---- When nothing is fetched ----

    [Fact]
    public async Task NoStatusElement_FetchesNothing()
    {
        var result = await VerifyAsync();

        Assert.True(result.IsValid, Codes(result));
        Assert.Empty(_http.Requested);
    }

    [Fact]
    public async Task CheckStatusOff_IgnoresEvenAMalformedStatus()
    {
        _builder.MsoStatus = [0xA1, 0x63, (byte)'f', (byte)'o', (byte)'o', 0x01];

        var result = await VerifyAsync(Verifier(options: new MdocVerifierOptions { CheckStatus = false }));

        Assert.True(result.IsValid, Codes(result));
        Assert.Empty(_http.Requested);
    }

    [Fact]
    public async Task AnOtherwiseInvalidCredential_FetchesNoList()
    {
        // SPEC: draft-ietf-oauth-status-list-20 section 8.3, no list procedures for an invalid Referenced Token.
        _builder.ValidUntil = DateTimeOffset.UtcNow.AddDays(-1);
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));

        AssertRefused(await VerifyAsync(), ErrorCodes.CredentialExpired);
        Assert.Empty(_http.Requested);
    }

    [Fact]
    public async Task ACleartextUri_IsRefusedWithoutFetching()
    {
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, "http://issuer.example/lists/1");

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
        Assert.Empty(_http.Requested);
    }

    [Fact]
    public async Task AnUnreachableList_FailsClosed()
    {
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusUnresolvable);
    }

    [Fact]
    public async Task AListPastTheSizeBound_FailsClosed()
    {
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, new byte[(4 << 20) + 1]);

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusUnresolvable);
    }

    [Theory]
    [InlineData(new byte[] { 0xA1, 0x63, (byte)'f', (byte)'o', (byte)'o', 0x01 })] // only an RFU mechanism
    [InlineData(new byte[] { 0xA1, 0x6B, (byte)'s', (byte)'t', (byte)'a', (byte)'t', (byte)'u', (byte)'s', (byte)'_', (byte)'l', (byte)'i', (byte)'s', (byte)'t', 0xA0 })] // status_list with no idx or uri
    [InlineData(new byte[] { 0x01 })] // not a map
    public async Task AnUnusableStatusElement_IsRefused(byte[] status)
    {
        _builder.MsoStatus = status;

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
        Assert.Empty(_http.Requested);
    }

    [Fact]
    public async Task TheCallersCancellation_Propagates_RatherThanFailingTheCredential()
    {
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        using var cancelled = new CancellationTokenSource();
        var verifier = new MdocVerifier(
            new StaticTrustListResolver([], source: "mdoc-test", trustAnchors: [_builder.IacaCertificate]),
            clock: null, httpClient: new HttpClient(new CancelsOnSend(cancelled)));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => verifier.VerifyAsync(Credential(_builder), Context(_builder), cancelled.Token));
    }

    [Fact]
    public async Task AMalformedCertificateInTheListsChain_IsTheListsFailure()
    {
        _list.ExtraChainCertificate = [0x30, 0x03, 0x02, 0x01, 0x00];
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
    }

    [Fact]
    public async Task TheReferencedCertificate_MayBeAnIntermediate()
    {
        // -06.1 names "a certificate containing the public key that signed the top-level certificate"; it
        // need not be self-signed. Platforms differ on anchoring at a non-self-signed certificate, so this
        // pins what this one does.
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root = CertificateAuthority("CN=Test Revocation Root", rootKey, issuer: null, issuerKey: null);
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ca = CertificateAuthority("CN=Test Revocation Intermediate", caKey, root, rootKey);
        using var list = new RevocationListBuilder(ca, caKey);
        _http.Serve(ListUri, list.StatusList(ListUri, bits: 1, 0));
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri, certificate: ca.RawData);

        var result = await VerifyAsync();

        Assert.True(result.IsValid, Codes(result));
    }

    [Fact]
    public async Task AStatusElementNamingAMechanismTwice_IsRefused()
    {
        // Two status_list entries, one valid index and one revoked: which one counts must not depend on order.
        var w = new System.Formats.Cbor.CborWriter(System.Formats.Cbor.CborConformanceMode.Lax);
        w.WriteStartMap(2);
        foreach (var idx in new[] { 0, 1 })
        {
            w.WriteTextString("status_list");
            w.WriteStartMap(2);
            w.WriteTextString("idx");
            w.WriteInt32(idx);
            w.WriteTextString("uri");
            w.WriteTextString(ListUri);
            w.WriteEndMap();
        }

        w.WriteEndMap();
        _builder.MsoStatus = w.Encode();
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0, 1));

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
        Assert.Empty(_http.Requested);
    }

    // ---- The token ----

    [Fact]
    public async Task AListRepeatingAClaim_IsRefused()
    {
        // The first copy revokes, the second clears: which one counts must not depend on order.
        _list.RepeatStatusListClaim = true;
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 1));

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
    }

    [Fact]
    public async Task AStatusListTypedByItsCoapNumber_Passes()
    {
        // SPEC: draft-ietf-oauth-status-list-20 section 5.2 allows "the registered CoAP Content-Format ID"; the IANA
        // registry assigns 279.
        _list.TypeNumber = 279;
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));

        var result = await VerifyAsync();

        Assert.True(result.IsValid, Codes(result));
    }

    [Fact]
    public async Task AnIdentifierListTypedByTheStatusListsCoapNumber_IsRefused()
    {
        _list.TypeNumber = 279;
        _builder.MsoStatus = RevocationListBuilder.IdentifierListReference(OurId, ListUri);
        _http.Serve(ListUri, _list.IdentifierList(ListUri, [0x09]));

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
    }

    [Theory]
    [InlineData("brainpoolP256r1")]
    [InlineData("nistP384")]
    public async Task AKeyOffTheCurveItsAlgorithmNames_IsRefused(string curve)
    {
        // The signer's hash makes the algorithm ES256, which EAA-6.2.10.1-08 defines on P-256 only.
        using var list = new RevocationListBuilder(_builder.IacaCertificate, _builder.IacaKey,
            curve: curve == "nistP384" ? ECCurve.NamedCurves.nistP384 : ECCurve.NamedCurves.brainpoolP256r1);
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, list.StatusList(ListUri, bits: 1, 0));

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
    }

    [Theory]
    [InlineData(new[] { 16 }, true)]
    [InlineData(new[] { 16, 99 }, false)]
    public async Task ACriticalHeader_IsHonoured(int[] critical, bool accepted)
    {
        _list.Critical = critical;
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));

        var result = await VerifyAsync();

        if (accepted)
        {
            Assert.True(result.IsValid, Codes(result));
        }
        else
        {
            AssertRefused(result, ErrorCodes.StatusInvalid);
        }
    }

    [Fact]
    public async Task AListNotValidYet_FailsClosed()
    {
        _list.NotBefore = DateTimeOffset.UtcNow.AddHours(1);
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusUnresolvable);
    }

    [Fact]
    public async Task AListWithDetachedClaims_IsRefused()
    {
        _list.Detached = true;
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));

        var result = await VerifyAsync();

        AssertRefused(result, ErrorCodes.StatusInvalid);
        Assert.Contains(result.Errors, e => e.Message.Contains("no embedded claims", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnExpiredList_FailsClosed()
    {
        _list.ExpiresAt = DateTimeOffset.UtcNow.AddHours(-1);
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusUnresolvable);
    }

    [Fact]
    public async Task AListWithoutExp_IsRefused_NamingExp()
    {
        // SPEC: EAA-6.2.10.1-08, "the exp claim shall be present", which the draft only RECOMMENDS.
        _list.ExpiresAt = null;

        await AssertMissingClaimsNamed("The MSO revocation list lacks the required exp claim.");
    }

    [Fact]
    public async Task AListWithoutIat_IsRefused_NamingIat()
    {
        _list.IssuedAt = null;

        await AssertMissingClaimsNamed("The MSO revocation list lacks the required iat claim.");
    }

    [Fact]
    public async Task AListWithoutSub_IsRefused_NamingSub()
    {
        _list.OmitSubject = true;

        await AssertMissingClaimsNamed("The MSO revocation list lacks the required sub claim.");
    }

    [Fact]
    public async Task AListWithoutTwoClaims_IsRefused_NamingBoth()
    {
        _list.OmitSubject = true;
        _list.ExpiresAt = null;

        await AssertMissingClaimsNamed("The MSO revocation list lacks the required sub and exp claims.");
    }

    [Fact]
    public async Task AListWithoutAllThree_IsRefused_NamingEach()
    {
        _list.OmitSubject = true;
        _list.IssuedAt = null;
        _list.ExpiresAt = null;

        await AssertMissingClaimsNamed("The MSO revocation list lacks the required sub, iat and exp claims.");
    }

    private async Task AssertMissingClaimsNamed(string message)
    {
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));

        var result = await VerifyAsync();

        Assert.False(result.IsValid);
        Assert.True(result.Errors.Any(e => e.Code == ErrorCodes.StatusInvalid && e.Message == message), Codes(result));
    }

    [Fact]
    public async Task ASubjectOtherThanTheReferencedUri_IsRefused()
    {
        _list.Subject = "https://issuer.example/lists/2";
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
    }

    [Fact]
    public async Task TheOtherKindsType_IsRefused()
    {
        _list.Type = "application/statuslist+cwt";
        _builder.MsoStatus = RevocationListBuilder.IdentifierListReference(OurId, ListUri);
        _http.Serve(ListUri, _list.IdentifierList(ListUri, [0x09]));

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
    }

    [Fact]
    public async Task AnUnprotectedX5Chain_IsRefused()
    {
        _list.X5ChainUnprotected = true;
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
    }

    [Fact]
    public async Task ASignatureByAnotherKey_IsRefused()
    {
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _list.SignWith = other;
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
    }

    [Theory]
    [InlineData("untagged")]
    [InlineData("cwt-tag")]
    public async Task AnythingButTheTaggedCoseSign1_IsRefused(string shape)
    {
        var tagged = _list.StatusList(ListUri, bits: 1, 0);
        Assert.Equal(0xD2, tagged[0]); // tag 18, as the builder emits it
        byte[] body = shape == "untagged" ? tagged[1..] : [0xD8, 0x3D, .. tagged]; // tag 61 around it
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, body);

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
    }

    [Theory]
    [InlineData(ulong.MaxValue >> 1)] // long.MaxValue
    [InlineData(ulong.MaxValue)] // a valid unsigned integer past long, which used to be refused as not positive
    public async Task AHugeTtl_IsCappedNotThrown(ulong ttl)
    {
        // A ttl past what a TimeSpan holds neither throws nor outlives the configured five minutes.
        var clock = new MovableClock(DateTimeOffset.UtcNow);
        _list.Ttl = ttl;
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));
        var verifier = new MdocVerifier(
            new StaticTrustListResolver([], source: "mdoc-test", trustAnchors: [_builder.IacaCertificate], clock: clock),
            new MdocVerifierOptions { ClockSkew = TimeSpan.Zero }, clock, new HttpClient(_http));

        var first = await VerifyAsync(verifier);
        clock.Advance(TimeSpan.FromMinutes(6));
        await VerifyAsync(verifier);

        Assert.True(first.IsValid, Codes(first));
        Assert.Equal(2, _http.Requested.Count);
    }

    private static X509Certificate2 CertificateAuthority(
        string subject, ECDsa key, X509Certificate2? issuer, ECDsa? issuerKey, bool withKeyId = false)
    {
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        if (withKeyId)
        {
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        }

        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
        var notAfter = DateTimeOffset.UtcNow.AddYears(5);
        return issuer is null
            ? request.CreateSelfSigned(notBefore, notAfter)
            : request.Create(issuer.SubjectName, X509SignatureGenerator.CreateForECDsa(issuerKey!), notBefore, notAfter, Guid.NewGuid().ToByteArray());
    }

    /// <summary>Trusts every chain, naming one anchor for the Document Signer and another for anything else.</summary>
    private sealed class AnchorPerLeaf(X509Certificate2 documentSigner) : ITrustListResolver
    {
        public Task<IssuerTrustStatus> ResolveAsync(string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default) =>
            Task.FromResult(new IssuerTrustStatus
            {
                Trusted = true,
                TrustListSource = "test",
                TrustAnchorThumbprint = x5c[0].Span.SequenceEqual(documentSigner.RawData) ? "AA" : "BB",
            });
    }

    /// <summary>Cancels the caller's token as the list is requested, then reports the cancellation.</summary>
    private sealed class CancelsOnSend(CancellationTokenSource source) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            source.Cancel();
            ct.ThrowIfCancellationRequested();
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK));
        }
    }

    public void Dispose()
    {
        _list.Dispose();
        _builder.Dispose();
        _http.Dispose();
    }
}
