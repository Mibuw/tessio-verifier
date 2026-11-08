using System.Text.Json;
using System.Text.Json.Nodes;

namespace Tessio.Verifier.Core;

/// <summary>
/// Converts <see cref="JsonNode"/> values into the plain CLR shapes the
/// <see cref="VerificationResult.DisclosedClaims"/> contract documents:
/// string, bool, long/double, <c>List&lt;object?&gt;</c>, <c>Dictionary&lt;string, object?&gt;</c>, or null.
/// </summary>
internal static class JsonValueConverter
{
    /// <summary>
    /// How deeply arrays and objects may nest inside one claim value. The owner of the bound: mdoc element values
    /// take it too (CborValueConverter.MaxDepth). A
    /// result carrying deeper claims would exceed what a serializer reading it accepts once it sits inside other
    /// structure, such as a session view with <see cref="VerificationResult.VerifiedPresentations"/>.
    /// </summary>
    internal const int MaxDepth = 32;

    /// <summary>Whether any member of <paramref name="payload"/> nests arrays or objects deeper than <see cref="MaxDepth"/>.</summary>
    public static bool DeeperThanAllowed(JsonObject payload) =>
        payload.Any(member => Exceeds(member.Value, 1));

    private static bool Exceeds(JsonNode? node, int depth) => node switch
    {
        JsonObject obj => depth > MaxDepth || obj.Any(member => Exceeds(member.Value, depth + 1)),
        JsonArray array => depth > MaxDepth || array.Any(item => Exceeds(item, depth + 1)),
        _ => false,
    };

    public static object? ToClrValue(JsonNode? node) => node switch
    {
        null => null,
        JsonObject obj => obj.ToDictionary(p => p.Key, p => ToClrValue(p.Value), StringComparer.Ordinal),
        JsonArray array => array.Select(ToClrValue).ToList(),
        _ => ScalarToClr(node),
    };

    private static object? ScalarToClr(JsonNode node) => node.GetValueKind() switch
    {
        JsonValueKind.String => node.GetValue<string>(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Number => NumberToClr(node),
        _ => null,
    };

    private static object NumberToClr(JsonNode node)
    {
        var element = node.GetValue<JsonElement>();
        return element.TryGetInt64(out var integer) ? integer : element.GetDouble();
    }
}
