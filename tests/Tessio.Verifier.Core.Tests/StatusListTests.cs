using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Tests;

/// <summary>
/// Token Status List enforcement (draft-ietf-oauth-status-list-20): revoked and suspended credentials
/// fail verification, unreachable or forged status lists fail closed, and the bit packing follows
/// the spec's LSB-first layout.
/// </summary>
public class StatusListTests
{
    private const string StatusUri = "https://issuer.example/statuslists/1";

    private static VerificationContext Context() => new()
    {
        Nonce = TestCredentialBuilder.DefaultNonce,
        Audience = TestCredentialBuilder.DefaultAudience,
    };

    private static (SdJwtVcVerifier Verifier, FakeHttpHandler Http) VerifierFor(
        TestCredentialBuilder builder,
        string? statusListJwt,
        SdJwtVcVerifierOptions? options = null,
        FakeTrustListResolver? trust = null)
    {
        var http = new FakeHttpHandler().Map(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""");
        if (statusListJwt is not null)
        {
            http.Map(StatusUri, statusListJwt);
        }

        return (new SdJwtVcVerifier(trust ?? new FakeTrustListResolver(), options, new HttpClient(http)), http);
    }

    private static TestCredentialBuilder CredentialWithStatus(long idx)
    {
        var builder = new TestCredentialBuilder();
        builder.Status = (idx, StatusUri);
        return builder;
    }

    [Fact]
    public async Task ValidStatus_Passes()
    {
        using var builder = CredentialWithStatus(idx: 1);
        var statusList = builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0, 0, 1, 0]);
        var (verifier, _) = VerifierFor(builder, statusList);

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
    }

    [Fact]
    public async Task RevokedCredential_Fails()
    {
        using var builder = CredentialWithStatus(idx: 2);
        var statusList = builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0, 0, 1, 0]);
        var (verifier, _) = VerifierFor(builder, statusList);

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "credential_revoked");
    }

    [Fact]
    public async Task SuspendedCredential_Fails_WithTwoBitPacking()
    {
        // bits=2, idx=5 → byte 1, shift 2. Value 2 = SUSPENDED.
        using var builder = CredentialWithStatus(idx: 5);
        var statusList = builder.BuildStatusListToken(StatusUri, bits: 2, statuses: [0, 0, 0, 0, 0, 2, 0, 0]);
        var (verifier, _) = VerifierFor(builder, statusList);

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "credential_suspended");
    }

    [Fact]
    public async Task UnreachableStatusList_FailsClosed()
    {
        using var builder = CredentialWithStatus(idx: 0);
        var (verifier, _) = VerifierFor(builder, statusListJwt: null); // status uri → 404

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "status_unresolvable");
    }

    [Fact]
    public async Task SubMismatch_IsRejected()
    {
        using var builder = CredentialWithStatus(idx: 0);
        var statusList = builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0], sub: "https://issuer.example/other-list");
        var (verifier, _) = VerifierFor(builder, statusList);

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "status_invalid");
    }

    [Fact]
    public async Task IndexOutsideTheList_IsRejected()
    {
        // SPEC: draft-ietf-oauth-status-list-20 section 8.3 step 6: an index out of bounds of the list
        // "MUST be rejected". Draft -14 said SHOULD. Four 1-bit entries pack into one byte, which holds
        // indices 0 to 7, so 8 is the first index outside it.
        using var builder = CredentialWithStatus(idx: 8);
        var statusList = builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0, 0, 0, 0]);
        var (verifier, _) = VerifierFor(builder, statusList);

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "status_invalid");
    }

    [Fact]
    public async Task StatusListTokenOverTheLimit_FailsClosed()
    {
        using var builder = CredentialWithStatus(idx: 0);
        var (verifier, http) = VerifierFor(builder, statusListJwt: null);
        http.MapBytes(StatusUri, new byte[OutboundFetch.MaxStatusListTokenBytes + 1]);

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors, e => e.Code == "status_unresolvable");
        Assert.Contains("limit", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task StatusListThatInflatesPastTheLimit_IsRejected()
    {
        // A list of zeros compresses about 1000:1, so this token is small and its list is not. One
        // byte per entry at bits=8, so one entry more than the limit is one byte more.
        using var builder = CredentialWithStatus(idx: 0);
        var statusList = builder.BuildStatusListToken(
            StatusUri, bits: 8, statuses: new byte[OutboundFetch.MaxDecompressedStatusListBytes + 1]);
        var (verifier, _) = VerifierFor(builder, statusList);

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors, e => e.Code == "status_invalid");
        Assert.Contains("limit", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WrongTyp_IsRejected()
    {
        using var builder = CredentialWithStatus(idx: 0);
        var statusList = builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0], typ: "JWT");
        var (verifier, _) = VerifierFor(builder, statusList);

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "status_invalid");
    }

    [Fact]
    public async Task ExpiredStatusList_FailsClosed()
    {
        using var builder = CredentialWithStatus(idx: 0);
        var statusList = builder.BuildStatusListToken(
            StatusUri, bits: 1, statuses: [0], exp: DateTimeOffset.UtcNow.AddHours(-2).ToUnixTimeSeconds());
        var (verifier, _) = VerifierFor(builder, statusList);

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "status_unresolvable");
    }

    // An exp outside the calendar reads as its nearer end, so far behind is expired and far ahead is not.
    // Both used to throw out of the verifier.
    [Theory]
    [InlineData(-99999999999999, false)]
    [InlineData(99999999999999, true)]
    public async Task StatusListExpBeyondTheCalendar_ReadsAsTheNearerEnd(long exp, bool valid)
    {
        using var builder = CredentialWithStatus(idx: 0);
        var statusList = builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0], exp: exp);
        var (verifier, _) = VerifierFor(builder, statusList);

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.Equal(valid, result.IsValid);
    }

    // A status list token is believed for TWO independent reasons, so each gets its own test and they
    // are broken one at a time. SubMismatch_IsRejected above breaks the BINDING: a token that does not
    // name the uri the issuer put inside the credential it signed. The pair below breaks, and then does
    // not break, AUTHENTICITY: whether the signer of a correctly bound token is trusted.
    //
    // These REPLACED ForeignIssuerStatusList_IsRejected, which pinned a different rule: that the status
    // token's issuer must equal the credential's. That rule was not in the specification and could not
    // be satisfied by a conformant token, because a token omitting iss resolves to its leaf subject DN
    // and a DN never equals an HTTPS URI. It refused the EUDI Wallet Reference Implementation's own PID.
    [Fact]
    public async Task UntrustedStatusListSigner_IsRejected()
    {
        using var builder = CredentialWithStatus(idx: 0);
        using var otherSigner = new TestCredentialBuilder { Issuer = "https://someone-else.example" };
        var forged = otherSigner.BuildStatusListToken(StatusUri, bits: 1, statuses: [0]);

        // The credential's own issuer stays trusted, so a failure here can only come from the status
        // list signer. A resolver that refused everything would prove nothing about which check fired.
        var trust = new FakeTrustListResolver();
        trust.Untrusted.Add("https://someone-else.example");

        var (verifier, http) = VerifierFor(builder, forged, trust: trust);
        http.Map(
            "https://someone-else.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"https://someone-else.example","jwks":{{otherSigner.BuildJwksJson()}}}""");

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "status_invalid");
        // Refused on its identifier, before its metadata was fetched from the host the token names.
        Assert.DoesNotContain("https://someone-else.example/.well-known/jwt-vc-issuer", http.Requested);
    }

    // The status list signer is a party of its own with its own chain, so its list can lapse while the
    // credential's issuer stays trusted. The refusal then names the list, as it does for the issuer.
    [Fact]
    public async Task AStatusListSigner_RefusedBecauseItsListLapsed_IsReportedAsTheList()
    {
        using var builder = CredentialWithStatus(idx: 0);
        using var otherSigner = new TestCredentialBuilder { Issuer = "https://someone-else.example" };
        var token = otherSigner.BuildStatusListToken(StatusUri, bits: 1, statuses: [0]);
        var trust = new FakeTrustListResolver { ListExpired = true };
        trust.Untrusted.Add("https://someone-else.example");

        var (verifier, _) = VerifierFor(builder, token, trust: trust);

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        var codes = result.Errors.Select(e => e.Code).ToList();
        Assert.Contains(ErrorCodes.TrustListExpired, codes);
        Assert.DoesNotContain(ErrorCodes.StatusInvalid, codes);
    }

    // SPEC: draft-ietf-oauth-status-list-20 section 1: "The Status Issuer can be either the Issuer or an
    // entity that has been authorized by the Issuer to issue Status List Tokens." The issuer authorises
    // by putting that uri inside the credential it signs, so a different BUT TRUSTED signer serving that
    // uri is the delegation the specification describes, not an attack.
    [Fact]
    public async Task DelegatedTrustedStatusListSigner_IsAccepted()
    {
        using var builder = CredentialWithStatus(idx: 0);
        using var statusIssuer = new TestCredentialBuilder { Issuer = "https://status.example" };
        var delegated = statusIssuer.BuildStatusListToken(StatusUri, bits: 1, statuses: [0]);

        var (verifier, http) = VerifierFor(builder, delegated);
        http.Map(
            "https://status.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"https://status.example","jwks":{{statusIssuer.BuildJwksJson()}}}""");

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
    }

    // ---- The anchoring path, judged by the REAL resolver -------------------------------------------
    //
    // Every other status list test here signs without an x5c, so the trust seam sees an empty chain and
    // answers by identifier membership. The status list tokens this code actually meets carry x5c and
    // are answered by ANCHORING, which no test reached until 2026-09-20. `FakeTrustListResolver` cannot
    // stand in either: it ignores the chain, which is the opposite of what `StaticTrustListResolver`
    // does when one is present. So these two use the shipped resolver rather than a double, and they
    // are the only thing pinning the claim that a self-signed status token served from the issuer's own
    // uri is refused.

    /// <summary>
    /// The trust seam failing for the STATUS SIGNER, while the credential's own issuer is decided, is
    /// reported as the status being unresolvable, with the cause, and as nothing else. The credential is
    /// otherwise valid, because draft-20 §8.3 fetches no status list for one that is not.
    /// </summary>
    [Theory]
    [InlineData("http")]
    [InlineData("not ready")]
    public async Task StatusSignerTrust_Failing_IsStatusUnresolvable(string kind)
    {
        using var builder = CredentialWithStatus(idx: 0);
        using var signer = SelfSignedStatusSigner("status-signer");
        var token = builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0], signWith: signer);
        Exception failure = kind == "http"
            ? new HttpRequestException("trust list unreachable")
            : new InvalidOperationException("trust list unreachable");
        var trust = new ChainFailingResolver(failure);

        var http = new FakeHttpHandler()
            .Map("https://issuer.example/.well-known/jwt-vc-issuer",
                $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""")
            .Map(StatusUri, token);
        var result = await new SdJwtVcVerifier(trust, options: null, new HttpClient(http)).VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors);
        Assert.Equal("status_unresolvable", error.Code);
        Assert.Contains("trust list unreachable", error.Message, StringComparison.Ordinal);
    }

    /// <summary>Trusts any identifier asked about with no chain, and fails for any chain.</summary>
    private sealed class ChainFailingResolver(Exception failure) : ITrustListResolver
    {
        public Task<IssuerTrustStatus> ResolveAsync(string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default) =>
            x5c.Length == 0
                ? Task.FromResult(new IssuerTrustStatus { Trusted = true, TrustListSource = "test" })
                : throw failure;
    }

    private static X509Certificate2 SelfSignedStatusSigner(string commonName)
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={commonName}", ec, HashAlgorithmName.SHA256);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
    }

    [Fact]
    public async Task SelfSignedStatusListToken_DoesNotAnchor_IsRejected()
    {
        using var builder = CredentialWithStatus(idx: 0);
        using var attacker = SelfSignedStatusSigner("attacker-who-serves-the-status-uri");
        var forged = builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0], signWith: attacker);

        // A real resolver holding one unrelated anchor. The attacker's chain reaches none of it.
        using var unrelated = SelfSignedStatusSigner("some-configured-anchor");
        var trust = new StaticTrustListResolver([TestCredentialBuilder.DefaultIssuer], "test", [unrelated]);

        var http = new FakeHttpHandler()
            .Map("https://issuer.example/.well-known/jwt-vc-issuer",
                $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""")
            .Map(StatusUri, forged);
        var verifier = new SdJwtVcVerifier(trust, options: null, new HttpClient(http));

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        // The MESSAGE, not only the code. `status_invalid` covers typ, algorithm, sub and trust, so
        // asserting the code alone would keep passing if this token started failing for some other
        // reason and the anchoring check silently stopped running.
        var error = Assert.Single(result.Errors, e => e.Code == "status_invalid");
        Assert.Contains("not trusted", error.Message, StringComparison.Ordinal);
        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task AnchoredStatusListToken_IsAccepted()
    {
        using var builder = CredentialWithStatus(idx: 0);
        using var statusSigner = SelfSignedStatusSigner("delegated-status-issuer");
        var token = builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0], signWith: statusSigner);

        // Same certificate, this time pinned as an anchor. Only the deployment's trust changed.
        var trust = new StaticTrustListResolver([TestCredentialBuilder.DefaultIssuer], "test", [statusSigner]);

        var http = new FakeHttpHandler()
            .Map("https://issuer.example/.well-known/jwt-vc-issuer",
                $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""")
            .Map(StatusUri, token);
        var verifier = new SdJwtVcVerifier(trust, options: null, new HttpClient(http));

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
    }

    // A cleartext status list is answerable by anyone on the path, and the failure is silent: the fetch
    // succeeds and the verdict is whatever the network said. Asserting the list was never REQUESTED is
    // the discriminating part, because a check placed after the fetch would still return an error while
    // having already trusted the connection.
    [Fact]
    public async Task PlaintextHttpStatusListUri_IsRejected_AndNeverFetched()
    {
        const string InsecureUri = "http://issuer.example/statuslists/1";
        using var builder = new TestCredentialBuilder { Status = (0, InsecureUri) };
        var statusList = builder.BuildStatusListToken(InsecureUri, bits: 1, statuses: [0]);

        var http = new FakeHttpHandler()
            .Map("https://issuer.example/.well-known/jwt-vc-issuer",
                $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""")
            .Map(InsecureUri, statusList);
        var verifier = new SdJwtVcVerifier(new FakeTrustListResolver(), options: null, new HttpClient(http));

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "status_invalid" && e.Message.Contains("HTTPS", StringComparison.Ordinal));
        Assert.DoesNotContain(InsecureUri, http.Requested);
    }

    [Fact]
    public async Task CheckStatusDisabled_SkipsFetchEntirely()
    {
        using var builder = CredentialWithStatus(idx: 0);
        var (verifier, http) = VerifierFor(builder, statusListJwt: null, new SdJwtVcVerifierOptions { CheckStatus = false });

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
        Assert.DoesNotContain(StatusUri, http.Requested);
    }

    [Fact]
    public async Task NoStatusClaim_NoCheck_NoFetch()
    {
        using var builder = new TestCredentialBuilder(); // no Status
        var (verifier, http) = VerifierFor(builder, statusListJwt: null);

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.True(result.IsValid);
        Assert.DoesNotContain(StatusUri, http.Requested);
    }

    [Fact]
    public async Task TheCallersCancellationDuringTheFetch_Propagates()
    {
        using var builder = CredentialWithStatus(idx: 0);
        var fake = new FakeHttpHandler().Map(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""");
        using var cancelled = new CancellationTokenSource();
        var verifier = new SdJwtVcVerifier(
            new FakeTrustListResolver(), options: null,
            new HttpClient(new CancelsAt(StatusUri, cancelled) { InnerHandler = fake }));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context(), cancelled.Token));
    }

    // ---- -20 §8.3: no status list for a credential already found invalid ----

    [Fact]
    public async Task AValidCredential_FetchesItsStatusList()
    {
        // The control for the two below: without it, a status list never fetched at all would pass them.
        using var builder = CredentialWithStatus(idx: 0);
        var (verifier, http) = VerifierFor(builder, builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0]));

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
        Assert.Contains(StatusUri, http.Requested);
    }

    [Fact]
    public async Task AnExpiredCredential_IsRefused_WithoutFetchingItsStatusList()
    {
        // SPEC: draft-ietf-oauth-status-list-20 §8.3, "further procedures regarding Status List MUST NOT be
        // performed, e.g. fetching a Status List Token".
        using var builder = CredentialWithStatus(idx: 0);
        builder.Exp = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds();
        var (verifier, http) = VerifierFor(builder, builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0]));

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.DoesNotContain(StatusUri, http.Requested);
    }

    [Fact]
    public async Task APresentationForAnotherNonce_IsRefused_WithoutFetchingItsStatusList()
    {
        // A replayed presentation must not make us contact the Status Provider.
        using var builder = CredentialWithStatus(idx: 0);
        builder.KbNonce = "another-nonce";
        var (verifier, http) = VerifierFor(builder, builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0]));

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.DoesNotContain(StatusUri, http.Requested);
    }

    // ---- -20 §5.1: the status list token's own claims ----

    [Fact]
    public async Task AStatusListWithoutIat_IsRefused()
    {
        using var builder = CredentialWithStatus(idx: 0);
        var (verifier, _) = VerifierFor(
            builder, builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0], includeIat: false));

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        // The message says the claim is MISSING, which is what an operator tells the list's issuer.
        Assert.Contains(result.Errors, e => e.Code == "status_invalid" && e.Message.Contains("lacks the required iat", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AStatusListNotValidYet_FailsClosed()
    {
        using var builder = CredentialWithStatus(idx: 0);
        var (verifier, _) = VerifierFor(
            builder,
            builder.BuildStatusListToken(
                StatusUri, bits: 1, statuses: [0], nbf: DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()));

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "status_unresolvable" && e.Message.Contains("not valid yet", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(-1)] // a minute ago: no reason to refuse, and inside the skew, so "now - skew < nbf" would wrongly refuse it
    [InlineData(1)] // a minute ahead: inside the default five-minute skew, so "now < nbf" would wrongly refuse it
    public async Task AStatusListWhoseNbfIsWithinTheClockSkew_Passes(int minutes)
    {
        using var builder = CredentialWithStatus(idx: 0);
        var (verifier, _) = VerifierFor(
            builder,
            builder.BuildStatusListToken(
                StatusUri, bits: 1, statuses: [0], nbf: DateTimeOffset.UtcNow.AddMinutes(minutes).ToUnixTimeSeconds()));

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
    }

    [Fact]
    public async Task AStatusListWhoseIatIsAString_IsRefused()
    {
        // SPEC: draft-ietf-oauth-status-list-20 §5.1, iat is a NumericDate, a JSON number. The handler would read
        // "1700000000" and 1700000000 alike, so the type is checked on the JSON itself.
        using var builder = CredentialWithStatus(idx: 0);
        var (verifier, _) = VerifierFor(
            builder,
            builder.BuildStatusListToken(
                StatusUri, bits: 1, statuses: [0], iat: DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)));

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "status_invalid" && e.Message.Contains("iat", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("exp")]
    [InlineData("nbf")]
    public async Task AStatusListWhoseExpOrNbfIsAString_IsRefused(string claim)
    {
        // A NumericDate is a JSON number (RFC 7519 section 2). The handler would read "4102444800" as a date.
        using var builder = CredentialWithStatus(idx: 0);
        var asText = DateTimeOffset.UtcNow.AddHours(claim == "exp" ? 1 : -1).ToUnixTimeSeconds()
            .ToString(System.Globalization.CultureInfo.InvariantCulture);
        var token = claim == "exp"
            ? builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0], exp: asText)
            : builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0], nbf: asText);
        var (verifier, _) = VerifierFor(builder, token);

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "status_invalid" && e.Message.Contains("not a number", StringComparison.Ordinal));
    }

    public static TheoryData<string> RepeatedMembers => ["bits", "status_list"];

    [Theory]
    [MemberData(nameof(RepeatedMembers))]
    public async Task AStatusListTokenRepeatingAMember_IsRefused(string member)
    {
        // RFC 8259 §4: parsers disagree on a repeated name, so a token carrying two bits or two status_list
        // claims has no single meaning. It is parsed as the issuer-signed payload is, and refused.
        using var builder = CredentialWithStatus(idx: 0);
        var token = builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0], rewritePayloadJson: json => member switch
        {
            "bits" => json.Replace("\"bits\":1", "\"bits\":8,\"bits\":1", StringComparison.Ordinal),
            _ => "{\"status_list\":{\"bits\":1,\"lst\":\"eNoDAAAAAAE\"}," + json[1..],
        });
        var (verifier, _) = VerifierFor(builder, token);

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "status_invalid" && e.Message.Contains("payload is not JSON", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AStatusListTokenWithContentAfterItsJson_IsAStatusFailure_NotAThrow()
    {
        // The JWT handler accepts a payload with something after its one JSON value. Read by a parser that refuses
        // it with an exception, it used to throw out of VerifyAsync; it is now an answer like any other bad token.
        using var builder = CredentialWithStatus(idx: 0);
        var token = builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0], rewritePayloadJson: json => json + "x");
        var (verifier, _) = VerifierFor(builder, token);

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "status_invalid" && e.Message.Contains("payload is not JSON", StringComparison.Ordinal));
    }

    public static TheoryData<string> MisshapenStatusLists => ["bits as a string", "status_list as a string"];

    [Theory]
    [MemberData(nameof(MisshapenStatusLists))]
    public async Task AStatusListClaimOfTheWrongShape_IsAStatusFailure_NotAStructureOne(string shape)
    {
        // JsonElement throws when asked for a number of a string or a property of a non-object. Thrown, it reached
        // the verifier's outer net and read as structure_invalid for the credential, which says nothing of status.
        using var builder = CredentialWithStatus(idx: 0);
        var token = builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0], statusList: lst => shape switch
        {
            "bits as a string" => new Dictionary<string, object> { ["bits"] = "1", ["lst"] = lst },
            _ => "1",
        });
        var (verifier, _) = VerifierFor(builder, token);

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "status_invalid" && e.Message.Contains("status_list", StringComparison.Ordinal));
        Assert.DoesNotContain(result.Errors, e => e.Code == ErrorCodes.StructureInvalid);
    }

    [Fact]
    public async Task AnUntrustedCredential_IsRefused_WithoutFetchingItsStatusList()
    {
        // On the x5c route trust is asked after the other checks, so this is the case the gate's trust half
        // decides: everything else passes, and only the issuer is untrusted.
        using var builder = CredentialWithStatus(idx: 0);
        builder.UseCertificate();
        var (verifier, http) = VerifierFor(
            builder, builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0]),
            trust: new FakeTrustListResolver(trusted: false));

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "issuer_untrusted");
        Assert.DoesNotContain(StatusUri, http.Requested);
    }

    /// <summary>Cancels the caller's token when <paramref name="url"/> is requested, and reports it.</summary>
    private sealed class CancelsAt(string url, CancellationTokenSource source) : DelegatingHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (request.RequestUri!.ToString() == url)
            {
                source.Cancel();
                ct.ThrowIfCancellationRequested();
            }

            return base.SendAsync(request, ct);
        }
    }
}
