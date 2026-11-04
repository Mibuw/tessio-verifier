namespace Tessio.Verifier.Core.Tests;

/// <summary>The x5u cache: what it keeps, for how long, and how much.</summary>
public sealed class CertificateUrlFetcherTests : IDisposable
{
    private static readonly byte[] Body = [0x30, 0x00];
    private static readonly byte[] Thumbprint = new byte[32];

    private readonly FakeHttpHandler _http = new();
    private readonly MovableClock _clock = new(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));

    private static string Url(int i) => $"https://pid-provider.test/{i}.pem";

    private CertificateUrlResource Resource(int i) => new(Url(i), Thumbprint, Body, _clock.Now);

    private sealed class MovableClock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;

        public override DateTimeOffset GetUtcNow() => Now;
    }

    private CertificateUrlFetcher Fetcher() => new(new HttpClient(_http), _clock);

    [Fact]
    public async Task AKeptResource_IsServedFromTheCache_UntilAnHourAfterItWasFetched()
    {
        _http.MapBytes(Url(0), Body);
        var fetcher = Fetcher();
        fetcher.Remember(await fetcher.FetchAsync(Url(0), Thumbprint, CancellationToken.None));

        await fetcher.FetchAsync(Url(0), Thumbprint, CancellationToken.None);
        Assert.Single(_http.Requested);

        _clock.Now += CertificateUrlFetcher.CacheDuration;
        await fetcher.FetchAsync(Url(0), Thumbprint, CancellationToken.None);
        Assert.Equal(2, _http.Requested.Count);
    }

    [Fact]
    public async Task KeepingACachedResourceAgain_DoesNotExtendItsLife()
    {
        // Every verified presentation keeps its resource again, including one served from the cache and kept just
        // after the entry expired. If either extended its life, a URL in steady use would never be fetched again.
        _http.MapBytes(Url(0), Body);
        var fetcher = Fetcher();
        fetcher.Remember(await fetcher.FetchAsync(Url(0), Thumbprint, CancellationToken.None));

        _clock.Now += CertificateUrlFetcher.CacheDuration - TimeSpan.FromSeconds(1);
        var cached = await fetcher.FetchAsync(Url(0), Thumbprint, CancellationToken.None);
        fetcher.Remember(cached);
        _clock.Now += TimeSpan.FromSeconds(2);
        fetcher.Remember(cached);

        await fetcher.FetchAsync(Url(0), Thumbprint, CancellationToken.None);
        Assert.Equal(2, _http.Requested.Count);
    }

    [Fact]
    public async Task ANewThumbprintAtTheSameUrl_IsFetched()
    {
        // An issuer that replaces the certificate at its URL: credentials naming the new one must not be served
        // the old body for the rest of the hour.
        _http.MapBytes(Url(0), Body);
        var fetcher = Fetcher();
        fetcher.Remember(Resource(0));

        await fetcher.FetchAsync(Url(0), Enumerable.Range(0, 32).Select(i => (byte)i).ToArray(), CancellationToken.None);

        Assert.Single(_http.Requested);
    }

    [Theory]
    [InlineData("https://pid-provider.test/0.pem#2")]
    [InlineData("https://someone@pid-provider.test/0.pem")]
    [InlineData("https://PID-provider.test:443/0.pem")]
    public async Task AUrlMakingTheSameRequest_NamesTheSameEntry(string variant)
    {
        // A fragment and userinfo are never sent, and the host's case and the default port change nothing on the
        // wire, so none may turn one resource into many cache entries.
        var fetcher = Fetcher();
        fetcher.Remember(Resource(0) with { Url = Url(0) + "#1" });

        await fetcher.FetchAsync(variant, Thumbprint, CancellationToken.None);

        Assert.Empty(_http.Requested);
    }

    [Fact]
    public async Task AUnicodeHost_NamesTheSameEntryAsItsPunycode()
    {
        var fetcher = Fetcher();
        fetcher.Remember(new CertificateUrlResource("https://xn--exmple-cua.test/ds.pem", Thumbprint, Body, _clock.Now));

        await fetcher.FetchAsync("https://exämple.test/ds.pem", Thumbprint, CancellationToken.None);

        Assert.Empty(_http.Requested);
    }

    [Fact]
    public async Task PastTheEntryCap_ANewResourceIsNotKept()
    {
        var fetcher = Fetcher();
        for (var i = 0; i <= CertificateUrlFetcher.MaxEntries; i++)
        {
            _http.MapBytes(Url(i), Body);
            fetcher.Remember(Resource(i));
        }

        await fetcher.FetchAsync(Url(0), Thumbprint, CancellationToken.None);
        await fetcher.FetchAsync(Url(CertificateUrlFetcher.MaxEntries), Thumbprint, CancellationToken.None);

        Assert.Equal([Url(CertificateUrlFetcher.MaxEntries)], _http.Requested);
    }

    [Fact]
    public async Task ConcurrentKeeping_NeverPassesTheCap()
    {
        var fetcher = Fetcher();
        var count = CertificateUrlFetcher.MaxEntries * 8;
        for (var i = 0; i < count; i++)
        {
            _http.MapBytes(Url(i), Body);
        }

        Parallel.For(0, count, new ParallelOptions { MaxDegreeOfParallelism = 32 }, i => fetcher.Remember(Resource(i)));

        for (var i = 0; i < count; i++)
        {
            await fetcher.FetchAsync(Url(i), Thumbprint, CancellationToken.None);
        }

        Assert.Equal(count - CertificateUrlFetcher.MaxEntries, _http.Requested.Count);
    }

    [Fact]
    public async Task ExpiredEntries_MakeRoomForNewOnes()
    {
        var fetcher = Fetcher();
        for (var i = 0; i < CertificateUrlFetcher.MaxEntries; i++)
        {
            fetcher.Remember(Resource(i));
        }

        _clock.Now += CertificateUrlFetcher.CacheDuration;
        _http.MapBytes(Url(CertificateUrlFetcher.MaxEntries), Body);
        fetcher.Remember(Resource(CertificateUrlFetcher.MaxEntries));

        await fetcher.FetchAsync(Url(CertificateUrlFetcher.MaxEntries), Thumbprint, CancellationToken.None);
        Assert.Empty(_http.Requested);
    }

    public void Dispose() => _http.Dispose();
}
