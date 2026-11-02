using System.IO.Compression;

namespace Tessio.Verifier.Core;

/// <summary>
/// What a Token Status List says once its token has been validated, whichever format carried it: the
/// decompressed bitstring, the status at an index, and how long the answer may be cached. Shared by the
/// SD-JWT VC checker (JWT tokens) and the mdoc revocation checker (CWT tokens), so the two read a list
/// the same way.
/// </summary>
// SPEC: draft-ietf-oauth-status-list-20, section 4.1 (bit packing), section
// 7.1 (registered values), section 8.3 steps 4d, 5 and 6 (ttl, decompression, an out-of-range index rejects)
// and section 13.7 (caching).
internal static class StatusListValues
{
    /// <summary>The bit widths section 4.1 allows.</summary>
    public static bool IsAllowedBits(long bits) => bits is 1 or 2 or 4 or 8;

    /// <summary>
    /// The decompressed list, or an error naming why there is none. Bounded, because the compressed form
    /// says nothing trustworthy about the size it expands to.
    /// </summary>
    public static async Task<(byte[]? List, VerificationError? Error)> DecompressAsync(byte[] compressed, CancellationToken ct)
    {
        try
        {
            using var source = new MemoryStream(compressed);
            await using var zlib = new ZLibStream(source, CompressionMode.Decompress);
            var list = await OutboundFetch.ReadBoundedAsync(
                zlib, "decompressed status list", OutboundFetch.MaxDecompressedStatusListBytes, ct).ConfigureAwait(false);
            return (list, null);
        }
        catch (InvalidDataException)
        {
            return (null, Error(ErrorCodes.StatusInvalid, "The status list bitstring could not be decompressed."));
        }
        catch (OutboundFetch.TooLargeException e)
        {
            return (null, Error(ErrorCodes.StatusInvalid, e.Message));
        }
    }

    /// <summary>The verdict for the credential at <paramref name="idx"/>; empty means valid.</summary>
    public static List<VerificationError> Evaluate(int bits, byte[] list, long idx)
    {
        // SPEC: section 8.3 step 6, an index outside the list MUST be rejected. Bounded BEFORE multiplying: the
        // credential chooses the index, and idx * bits past a long wraps round to an index inside the list.
        if (idx < 0 || idx >= (long)list.Length * 8 / bits)
        {
            return [Error(ErrorCodes.StatusInvalid, $"Status index {idx} is outside the status list.")];
        }

        // SPEC: section 4.1, blocks are packed into bytes starting at the least significant bit.
        var byteIndex = idx * bits / 8;

        var shift = (int)(idx * bits % 8);
        var value = (list[byteIndex] >> shift) & ((1 << bits) - 1);

        // SPEC: section 7.1, registered status values.
        return value switch
        {
            0x00 => [],
            0x01 => [Error(ErrorCodes.CredentialRevoked, "The issuer has revoked this credential.")],
            0x02 => [Error(ErrorCodes.CredentialSuspended, "The issuer has suspended this credential.")],
            _ => [Error(ErrorCodes.CredentialStatusUnknown, $"The credential carries unrecognized status value 0x{value:X2}.")],
        };
    }

    /// <summary>
    /// Until when a validated list may answer from cache: the configured duration, shortened by the token's
    /// <c>ttl</c> (the issuer's ceiling) and capped by its <c>exp</c>. At or before <paramref name="now"/>
    /// means do not cache.
    /// </summary>
    public static DateTimeOffset CacheUntil(
        DateTimeOffset now, TimeSpan cacheDuration, long? ttlSeconds, DateTimeOffset? expiresAt)
    {
        var lifetime = cacheDuration;
        // Compared in seconds, not as a TimeSpan: the token chooses the ttl, and one too large or too negative
        // for a TimeSpan would otherwise throw here rather than simply shorten nothing or forbid caching.
        if (ttlSeconds is { } ttl && ttl < lifetime.TotalSeconds)
        {
            lifetime = ttl <= 0 ? TimeSpan.Zero : TimeSpan.FromSeconds(ttl);
        }

        // Saturating both ways, so a configured duration past the calendar's end means "until exp" and a negative
        // one means "do not cache", neither an exception.
        var until = lifetime <= TimeSpan.Zero ? now
            : lifetime >= DateTimeOffset.MaxValue - now ? DateTimeOffset.MaxValue
            : now + lifetime;
        return expiresAt is { } exp && exp < until ? exp : until;
    }

    private static VerificationError Error(string code, string message) => new() { Code = code, Message = message };
}
