namespace Tessio.Verifier.Core.Tests;

/// <summary>
/// Status list caching (draft-ietf-oauth-status-list-20 §8.3 step 4d and §13.7): validated lists
/// are reused within the cache window, the token's ttl shortens the window, failures are never cached and revocation
/// verdicts stay per-index correct when served from cache.
/// </summary>
public class StatusListCacheTests
{
    private const string StatusUri = "https://issuer.example/statuslists/1";

    private static VerificationContext Context() => new()
    {
        Nonce = TestCredentialBuilder.DefaultNonce,
        Audience = TestCredentialBuilder.DefaultAudience,
    };

    private static (SdJwtVcVerifier Verifier, FakeHttpHandler Http) VerifierFor(
        TestCredentialBuilder builder, string statusListJwt, SdJwtVcVerifierOptions? options = null, TimeProvider? clock = null)
    {
        var http = new FakeHttpHandler()
            .Map("https://issuer.example/.well-known/jwt-vc-issuer",
                $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""")
            .Map(StatusUri, statusListJwt);

        return (new SdJwtVcVerifier(new FakeTrustListResolver(), options, new HttpClient(http), clock), http);
    }

    private sealed class MovableClock(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }

    /// <summary>A JSON number written as given, for values a double cannot carry.</summary>
    private static System.Text.Json.JsonElement RawNumber(string text) => System.Text.Json.JsonDocument.Parse(text).RootElement;

    [Fact]
    public async Task AWholeTtl_ShortensTheCacheDuration()
    {
        // ttl 30 against the default five minutes: still cached ten seconds on, fetched again a minute on.
        var clock = new MovableClock(DateTimeOffset.UtcNow);
        var builder = new TestCredentialBuilder { Status = (0, StatusUri) };
        var (verifier, http) = VerifierFor(
            builder, builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0], ttl: 30), clock: clock);
        var credential = new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() };

        Assert.True((await verifier.VerifyAsync(credential, Context(), CancellationToken.None)).IsValid);
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.True((await verifier.VerifyAsync(credential, Context(), CancellationToken.None)).IsValid);
        Assert.Equal(1, StatusFetches(http));

        clock.Advance(TimeSpan.FromSeconds(50));
        Assert.True((await verifier.VerifyAsync(credential, Context(), CancellationToken.None)).IsValid);
        Assert.Equal(2, StatusFetches(http));
    }

    [Theory]
    [InlineData("1e-400")] // positive, though a double reads it as 0: caches nothing
    [InlineData("1e400")] // a valid number, though a double reads it as infinity: saturates
    public async Task ATtlPastWhatADoubleHolds_IsStillAPositiveNumber(string ttl)
    {
        var builder = new TestCredentialBuilder { Status = (0, StatusUri) };
        var (verifier, _) = VerifierFor(
            builder, builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0], ttl: RawNumber(ttl)));
        var credential = new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() };

        var result = await verifier.VerifyAsync(credential, Context(), CancellationToken.None);

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
    }

    private static int StatusFetches(FakeHttpHandler http) =>
        http.Requested.Count(url => url == StatusUri);

    [Fact]
    public async Task SecondVerification_ServesTheListFromCache()
    {
        var builder = new TestCredentialBuilder { Status = (0, StatusUri) };
        var (verifier, http) = VerifierFor(builder, builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0, 1]));
        var credential = new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() };

        Assert.True((await verifier.VerifyAsync(credential, Context(), CancellationToken.None)).IsValid);
        Assert.True((await verifier.VerifyAsync(credential, Context(), CancellationToken.None)).IsValid);

        Assert.Equal(1, StatusFetches(http));
    }

    [Fact]
    public async Task CachedList_StillRevokes_PerIndex()
    {
        // Two credentials referencing the same list at different indices; the second verdict comes
        // from the cached bitstring and must still be evaluated per index.
        var valid = new TestCredentialBuilder { Status = (0, StatusUri) };
        var statusList = valid.BuildStatusListToken(StatusUri, bits: 1, statuses: [0, 1]);
        var (verifier, http) = VerifierFor(valid, statusList);

        var validResult = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = valid.Build() }, Context(), CancellationToken.None);
        Assert.True(validResult.IsValid);

        valid.Status = (1, StatusUri);
        var revokedResult = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = valid.Build() }, Context(), CancellationToken.None);

        Assert.False(revokedResult.IsValid);
        Assert.Contains(revokedResult.Errors, e => e.Code == "credential_revoked");
        Assert.Equal(1, StatusFetches(http));
    }

    [Fact]
    public async Task ZeroCacheDuration_FetchesEveryTime()
    {
        var builder = new TestCredentialBuilder { Status = (0, StatusUri) };
        var (verifier, http) = VerifierFor(
            builder,
            builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0]),
            new SdJwtVcVerifierOptions { StatusListCacheDuration = TimeSpan.Zero });
        var credential = new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() };

        await verifier.VerifyAsync(credential, Context(), CancellationToken.None);
        await verifier.VerifyAsync(credential, Context(), CancellationToken.None);

        Assert.Equal(2, StatusFetches(http));
    }

    public static TheoryData<object> TtlsThatAreNotPositiveNumbers => new() { 0, -5, long.MinValue, "300" };

    [Theory]
    [MemberData(nameof(TtlsThatAreNotPositiveNumbers))]
    public async Task ATtlThatIsNotAPositiveNumber_IsRefused(object ttl)
    {
        // SPEC: draft-ietf-oauth-status-list-20 §5.1, ttl "MUST be a positive number encoded in JSON as a number",
        // and §8.3 step 4 checks every existing claim against §5.1. The mdoc path refuses a non-positive one too.
        var builder = new TestCredentialBuilder { Status = (0, StatusUri) };
        var (verifier, _) = VerifierFor(
            builder, builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0], ttl: ttl));
        var credential = new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() };

        var result = await verifier.VerifyAsync(credential, Context(), CancellationToken.None);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "status_invalid" && e.Message.Contains("ttl", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AFractionalTtl_StillShortensTheCacheDuration()
    {
        // SPEC: draft-ietf-oauth-status-list-20 §5.1, ttl is "a positive number". 0.5 seconds reads as 0, so
        // the list is not cached. Ignoring the claim instead would cache it for the whole configured duration.
        var builder = new TestCredentialBuilder { Status = (0, StatusUri) };
        var (verifier, http) = VerifierFor(
            builder, builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0], ttl: 0.5));
        var credential = new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() };

        Assert.True((await verifier.VerifyAsync(credential, Context(), CancellationToken.None)).IsValid);
        Assert.True((await verifier.VerifyAsync(credential, Context(), CancellationToken.None)).IsValid);
        Assert.Equal(2, StatusFetches(http));
    }

    [Fact]
    public async Task ATtlTooLargeForATimeSpan_LeavesTheCacheDurationInCharge()
    {
        // The token chooses its ttl. One past what a TimeSpan holds must neither throw out of verification
        // nor lengthen the cache past the configured ceiling.
        var builder = new TestCredentialBuilder { Status = (0, StatusUri) };
        var (verifier, http) = VerifierFor(
            builder, builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0], ttl: long.MaxValue),
            new SdJwtVcVerifierOptions { StatusListCacheDuration = TimeSpan.Zero });
        var credential = new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() };

        Assert.True((await verifier.VerifyAsync(credential, Context(), CancellationToken.None)).IsValid);
        Assert.True((await verifier.VerifyAsync(credential, Context(), CancellationToken.None)).IsValid);
        Assert.Equal(2, StatusFetches(http));
    }

    [Fact]
    public async Task ACacheDurationPastTheCalendarsEnd_Saturates()
    {
        var builder = new TestCredentialBuilder { Status = (0, StatusUri) };
        var (verifier, http) = VerifierFor(
            builder, builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0]),
            new SdJwtVcVerifierOptions { StatusListCacheDuration = TimeSpan.MaxValue });
        var credential = new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() };

        Assert.True((await verifier.VerifyAsync(credential, Context(), CancellationToken.None)).IsValid);
        Assert.True((await verifier.VerifyAsync(credential, Context(), CancellationToken.None)).IsValid);
        Assert.Equal(1, StatusFetches(http));
    }

    [Fact]
    public async Task ANegativeCacheDuration_MeansNoCaching()
    {
        var builder = new TestCredentialBuilder { Status = (0, StatusUri) };
        var (verifier, http) = VerifierFor(
            builder, builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0]),
            new SdJwtVcVerifierOptions { StatusListCacheDuration = TimeSpan.MinValue });
        var credential = new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() };

        Assert.True((await verifier.VerifyAsync(credential, Context(), CancellationToken.None)).IsValid);
        Assert.True((await verifier.VerifyAsync(credential, Context(), CancellationToken.None)).IsValid);
        Assert.Equal(2, StatusFetches(http));
    }

    [Fact]
    public async Task FailedResolution_IsNotCached_AndStaysFailClosed()
    {
        // No mapping for the status uri: both verifications must attempt the fetch and fail closed.
        var builder = new TestCredentialBuilder { Status = (0, StatusUri) };
        var http = new FakeHttpHandler().Map(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""");
        var verifier = new SdJwtVcVerifier(new FakeTrustListResolver(), httpClient: new HttpClient(http));
        var credential = new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() };

        var first = await verifier.VerifyAsync(credential, Context(), CancellationToken.None);
        var second = await verifier.VerifyAsync(credential, Context(), CancellationToken.None);

        Assert.False(first.IsValid);
        Assert.False(second.IsValid);
        Assert.Contains(second.Errors, e => e.Code == "status_unresolvable");
        Assert.Equal(2, StatusFetches(http));
    }
}
