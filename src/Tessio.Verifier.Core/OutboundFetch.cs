// What belongs here: the rules every HTTP request a credential can cause must follow, and the default
// client that enforces them. A credential names the hosts we fetch from (its iss, the jwks_uri its
// metadata names, its status list uri), so each of those is a request an attacker may have aimed.

using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.Core;

/// <summary>
/// Outbound fetches for issuer metadata, issuer key sets and status lists.
/// </summary>
/// <remarks>
/// SPEC: draft-ietf-oauth-sd-jwt-vc-13 §10.1 requires the verifier to "validate the URL to ensure that it
/// is a valid HTTPS URL and that it does not point to internal resources", including after DNS
/// resolution, and to make the request "in a time-bound and size-bound manner". Token Status List -20
/// says nothing equivalent. The same rules apply there because the uri comes from the same credential.
/// <para>
/// The address check runs inside the connection, on the addresses the socket then connects to, not on
/// the URL. Checking a name and then connecting by name is a race: the name can resolve to a public
/// address when checked and a private one when connected. The deadline and the size bounds are
/// enforced by the readers here, so they hold for a client a caller supplies. The address check, the
/// redirect refusal and the proxy refusal live in the handler, so they hold only for the default client.
/// </para>
/// </remarks>
internal static class OutboundFetch
{
    /// <summary>
    /// The largest metadata document or key set read. Both are small JSON documents, so 1 MiB leaves
    /// wide headroom while making a hostile body cost nothing.
    /// </summary>
    internal const long MaxMetadataBytes = 1L << 20;

    /// <summary>
    /// The largest status list token read: the size the JWT handler that validates it will accept.
    /// The draft sets no limit (-20 §13.4), but a larger token would be read whole only to be refused
    /// by that handler, with a message about the signature rather than the size.
    /// </summary>
    internal const long MaxStatusListTokenBytes = TokenValidationParameters.DefaultMaximumTokenSizeInBytes;

    /// <summary>
    /// The largest MSO revocation list read. No token handler bounds a CWT, and the draft sets no limit
    /// (-20 section 13.4 leaves size to the issuer, who may split a list), so this is ours: large enough for an
    /// identifier list of well over a hundred thousand 16-byte identifiers, small enough to read in one go.
    /// </summary>
    internal const long MaxMsoRevocationListBytes = 4L << 20;

    /// <summary>
    /// The largest decompressed status list, 2^29 1-bit entries. zlib inflates up to about 1000:1, so a
    /// token inside the limit above could otherwise expand to gigabytes.
    /// </summary>
    internal const long MaxDecompressedStatusListBytes = 64L << 20;

    /// <summary>
    /// One request, from sending it to the last byte of the body. A verifier fetches while a wallet
    /// waits on its response POST, so a host that accepts the connection and then stalls, or sends its
    /// headers and then trickles the body, must not hold the request for long.
    /// </summary>
    internal static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Bounded so a pooled connection cannot outlive a DNS change indefinitely. The connect check runs
    /// on every new connection, and this decides how often a new one is made.
    /// </summary>
    private static readonly TimeSpan PooledConnectionLifetime = TimeSpan.FromMinutes(2);

    /// <summary>The guard refused the address, before any byte of the request was sent.</summary>
    internal sealed class BlockedAddressException(string host)
        : HttpRequestException($"Refused to connect to {host}: it resolves outside the public internet.");

    /// <summary>A response body, or a decompressed list, exceeded its bound.</summary>
    internal sealed class TooLargeException(string what, long limit)
        : HttpRequestException($"The {what} exceeds the {limit}-byte limit.");

    /// <summary>The fetch did not finish inside <see cref="RequestTimeout"/>.</summary>
    internal sealed class TimedOutException(string what)
        : HttpRequestException($"The {what} did not arrive within {RequestTimeout.TotalSeconds} seconds.");

    /// <summary>
    /// The client a verifier uses when its caller supplies none. Its own timeout is off because
    /// <see cref="GetBoundedAsync"/> owns the deadline: the client's timeout stops at the headers once
    /// the body is streamed, so it could not bound a body that trickles.
    /// </summary>
    internal static HttpClient CreateClient() => new(CreateHandler()) { Timeout = Timeout.InfiniteTimeSpan };

    /// <summary>
    /// Redirects are refused, not followed: following one hands the destination to whoever answered.
    /// A redirect therefore surfaces as a non-success status, and the fetch fails closed.
    /// </summary>
    /// <remarks>
    /// The process proxy is ignored. Through a proxy the connect check sees only the proxy's address,
    /// and the proxy then connects wherever the URL says, so honouring HTTPS_PROXY would switch the
    /// address check off without a word. A deployment that must use a proxy supplies its own client.
    /// </remarks>
    internal static SocketsHttpHandler CreateHandler() => new()
    {
        PooledConnectionLifetime = PooledConnectionLifetime,
        ConnectCallback = ConnectCheckedAsync,
        AllowAutoRedirect = false,
        UseProxy = false,
    };

    /// <summary>
    /// Sends a GET and reads at most <paramref name="limit"/> bytes of the body, all inside
    /// <see cref="RequestTimeout"/>. The headers are read first and the body streamed, because the
    /// default buffers a whole body before anyone can count it. The deadline and the limit are enforced
    /// here rather than by the client, so they hold for a client a caller supplies.
    /// </summary>
    internal static async Task<byte[]> GetBoundedAsync(
        HttpClient client, Uri uri, string? accept, string what, long limit, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(RequestTimeout);
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            if (accept is not null)
            {
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(accept));
            }

            using var response = await client
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            if (response.Content.Headers.ContentLength > limit)
            {
                throw new TooLargeException(what, limit);
            }

            await using var body = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
            return WithoutUtf8Bom(await ReadBoundedAsync(body, what, limit, deadline.Token).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // Not the caller cancelling, so a deadline: ours, or a shorter one on a supplied client.
            throw new TimedOutException(what);
        }
        catch (IOException e)
        {
            // A body read from the stream fails as IOException (a dropped connection, a short body, a
            // bad chunk), where a buffered read would have wrapped it. Wrapped here so every caller's
            // HttpRequestException handling still fails the credential closed.
            throw new HttpRequestException($"The {what} could not be read: {e.Message}", e);
        }
    }

    /// <summary>
    /// The body without a leading UTF-8 byte order mark. RFC 8259 section 8.1 forbids sending one in
    /// JSON but lets a parser ignore it, and a buffered string read used to.
    /// </summary>
    private static byte[] WithoutUtf8Bom(byte[] body) =>
        body.AsSpan().StartsWith(Utf8Bom) ? body[Utf8Bom.Length..] : body;

    private static ReadOnlySpan<byte> Utf8Bom => [0xEF, 0xBB, 0xBF];

    /// <summary>
    /// Reads a stream to its end, failing as soon as it passes <paramref name="limit"/> bytes. Used for
    /// response bodies and for decompression, where the declared length cannot be trusted at all.
    /// </summary>
    internal static async Task<byte[]> ReadBoundedAsync(Stream source, string what, long limit, CancellationToken ct)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = await source.ReadAsync(chunk, ct).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > limit)
            {
                throw new TooLargeException(what, limit);
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    private static async ValueTask<Stream> ConnectCheckedAsync(SocketsHttpConnectionContext context, CancellationToken ct)
    {
        var host = context.DnsEndPoint.Host;
        var addresses = IPAddress.TryParse(host, out var literal)
            ? [literal]
            : await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);

        // Every candidate must be public. Connecting to the acceptable ones would still leave the socket
        // free to pick one we rejected, so a mixed answer is refused outright.
        if (addresses.Length == 0 || !addresses.All(PublicAddress.IsPublic))
        {
            throw new BlockedAddressException(host);
        }

        // What closes the DNS race: the socket connects to exactly the addresses just checked, never to
        // the name, so nothing is resolved again between the check and the connection.
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(addresses, context.DnsEndPoint.Port, ct).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
