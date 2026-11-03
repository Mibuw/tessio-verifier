using System.Text.Json;
using System.Text.Json.Nodes;

namespace Tessio.Verifier.Core;

/// <summary>
/// Reads a NumericDate (RFC 7519 §2) from a credential. <see cref="DateTimeOffset.FromUnixTimeSeconds"/>
/// throws outside years 1 to 9999. A signed claim can name any second count a long holds, so every
/// read in this assembly goes through here. A value outside the range reads as the nearer end of it, so an
/// <c>exp</c> that far ahead does not expire and one that far behind has expired. A JSON number past what a
/// long holds is read through a double and saturates the same way.
/// </summary>
internal static class UnixTime
{
    private static readonly long MinSeconds = DateTimeOffset.MinValue.ToUnixTimeSeconds();
    private static readonly long MaxSeconds = DateTimeOffset.MaxValue.ToUnixTimeSeconds();

    public static DateTimeOffset FromSeconds(long seconds) =>
        DateTimeOffset.FromUnixTimeSeconds(Math.Clamp(seconds, MinSeconds, MaxSeconds));

    public static DateTimeOffset FromSeconds(double seconds) =>
        seconds <= MinSeconds ? DateTimeOffset.MinValue
            : seconds >= MaxSeconds ? DateTimeOffset.MaxValue
            : DateTimeOffset.FromUnixTimeSeconds((long)seconds);

    /// <summary>
    /// Reads a time claim as a NumericDate, to the whole second at or before it. False for anything but a JSON
    /// number, a string holding digits included, because RFC 7519 §4.1.4 to §4.1.6 say each "MUST be a number".
    /// The type check lives here so that no caller can read the value without it.
    /// </summary>
    // SPEC: RFC 7519 §2, a NumericDate is seconds since the epoch, "other than that non-integer values can be
    // represented". A number past what a double holds cannot arrive as an exp, nbf or iat: the JWT parser reads
    // those claims itself and refuses the token. So the last branch only keeps the read from throwing, taking
    // the end the sign points to.
    public static bool TryFromNumericDate(JsonElement value, out DateTimeOffset date)
    {
        date = value.ValueKind != JsonValueKind.Number ? default
            : value.TryGetInt64(out var whole) ? FromSeconds(whole)
            : value.TryGetDouble(out var seconds) ? FromSeconds(Math.Floor(seconds))
            : value.GetRawText().StartsWith('-') ? DateTimeOffset.MinValue : DateTimeOffset.MaxValue;
        return value.ValueKind == JsonValueKind.Number;
    }

    /// <inheritdoc cref="TryFromNumericDate(JsonElement, out DateTimeOffset)"/>
    public static bool TryFromNumericDate(JsonNode? node, out DateTimeOffset date)
    {
        date = default;
        return node is JsonValue value && value.TryGetValue<JsonElement>(out var element)
            && TryFromNumericDate(element, out date);
    }
}
