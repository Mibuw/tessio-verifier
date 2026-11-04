using System.Collections.Concurrent;

namespace Tessio.Verifier.Core;

/// <summary>
/// Fetches the certificate resource an <c>x5u</c> header names, for SD-JWT VC (RFC 7515) and mdoc (RFC 9360)
/// alike. It returns the bytes; each format reads its own body (PEM for JOSE, DER or COSE_X509 for COSE), binds
/// the end-entity certificate to the signature with its thumbprint, and leaves trust to the trust seam.
/// </summary>
/// <remarks>
/// A resource is reused for <see cref="CacheDuration"/> from when it was fetched, so a credential's issuer is not
/// contacted for every presentation it signed. It is keyed by the request the URL makes and the thumbprint together, so
/// a credential naming a new certificate at the same URL misses the cache and is fetched. The verifier keeps a
/// resource (<see cref="Remember"/>) only for a credential that verified in full, its chain trusted, and never more
/// than <see cref="MaxEntries"/>. Until then the URL and the thumbprint are only what the presenter chose.
/// </remarks>
internal sealed class CertificateUrlFetcher(HttpClient httpClient, TimeProvider clock)
{
    /// <summary>How long a resource is reused, from when it was fetched, before it is fetched again.</summary>
    internal static readonly TimeSpan CacheDuration = TimeSpan.FromHours(1);

    /// <summary>The largest resource read: a chain of a few certificates, with room to spare.</summary>
    internal const long MaxBytes = 256L << 10;

    /// <summary>The most resources kept at once. Past it, a verified resource is used but not kept.</summary>
    internal const int MaxEntries = 64;

    private readonly ConcurrentDictionary<string, CertificateUrlResource> _cache = new(StringComparer.Ordinal);
    // Count and add as one step, so concurrent verifications cannot push the cache past MaxEntries.
    private readonly object _keeping = new();

    /// <summary>The resource at <paramref name="url"/>, from the cache when a kept copy for this thumbprint is fresh.</summary>
    /// <exception cref="CertificateUrlException">The URL is not HTTPS, or could not be fetched.</exception>
    public async Task<CertificateUrlResource> FetchAsync(string url, byte[] thumbprint, CancellationToken ct)
    {
        // SPEC: RFC 7515 section 4.1.5, "an HTTP GET request to retrieve the certificate MUST use TLS". RFC 9360
        // section 2 has TLS "SHOULD be used". HTTPS is required for both, as for every fetch a credential names.
        var uri = Parse(url);
        var now = clock.GetUtcNow();
        if (_cache.TryGetValue(Key(uri, thumbprint), out var kept) && kept.FetchedAt + CacheDuration > now)
        {
            return kept;
        }

        try
        {
            var body = await OutboundFetch.GetBoundedAsync(
                httpClient, uri, accept: null, "x5u certificate resource", MaxBytes, ct).ConfigureAwait(false);
            return new CertificateUrlResource(url, thumbprint, body, now);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or InvalidOperationException)
        {
            // The caller's own cancellation propagates; anything else is a certificate that could not be fetched.
            ct.ThrowIfCancellationRequested();
            throw new CertificateUrlException($"The certificate at the x5u could not be retrieved: {e.Message}");
        }
    }

    /// <summary>
    /// Keeps <paramref name="resource"/>, once the credential it came with verified in full. It expires
    /// <see cref="CacheDuration"/> after it was fetched, however often it is kept again, and one already expired is
    /// not kept. Expired entries are dropped first; when the cache is still full, nothing is kept.
    /// </summary>
    public void Remember(CertificateUrlResource resource)
    {
        var now = clock.GetUtcNow();
        if (resource.FetchedAt + CacheDuration <= now)
        {
            return;
        }

        lock (_keeping)
        {
            foreach (var (key, entry) in _cache)
            {
                if (entry.FetchedAt + CacheDuration <= now)
                {
                    _cache.TryRemove(key, out _);
                }
            }

            if (_cache.Count < MaxEntries)
            {
                _cache.TryAdd(Key(Parse(resource.Url), resource.Thumbprint), resource);
            }
        }
    }

    // Built from what the request sends: the host as its IDN (punycode) form, the port, the path and the query. Userinfo
    // and a fragment are never sent, so URLs differing only there name the same resource.
    private static string Key(Uri uri, byte[] thumbprint) =>
        $"{Convert.ToHexString(thumbprint)} {uri.IdnHost}:{uri.Port}{uri.PathAndQuery}";

    private static Uri Parse(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps
            ? uri
            : throw new CertificateUrlException("The x5u is not an HTTPS URL.");
}

/// <summary>An <c>x5u</c> resource as fetched, with the thumbprint its first certificate must match.</summary>
internal sealed record CertificateUrlResource(string Url, byte[] Thumbprint, byte[] Body, DateTimeOffset FetchedAt);

/// <summary>Why an <c>x5u</c> resource could not be fetched. Each caller answers it with its own error code.</summary>
internal sealed class CertificateUrlException(string message) : Exception(message);
