using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Tessio.Verifier.Core;

/// <summary>
/// Parses JSON that arrives from outside, in a credential, a wallet response or fetched metadata, refusing
/// what <see cref="JsonNode"/> would accept and then fail on later: see <see cref="Accepts"/>. RFC 8259 §4
/// says names SHOULD be unique and that parsers disagree on a repeat, so a repeat has no single meaning to
/// hand on. A number the parser reads as infinity would later fail the host that writes it out. Throws
/// <see cref="JsonException"/>, which each caller maps to its own error code.
/// </summary>
/// <remarks>
/// The one owner of these rules in the library, OpenId4Vp included: a second statement of them would be free to
/// drift from this one.
/// </remarks>
internal static class StrictJson
{
    /// <summary>What this parser requires beyond JSON syntax, named in the callers' error messages.</summary>
    public const string Accepts = "text that is valid Unicode, no repeated name and no number outside the range of a double";

    // Throws for a string that is not valid UTF-16, where Encoding.UTF8 would replace the bad code unit silently.
    private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public static JsonNode? Parse(byte[] utf8)
    {
        Check(utf8);
        return JsonNode.Parse(utf8);
    }

    /// <summary>The same rules, for a caller that reads <see cref="JsonElement"/>s. The caller disposes it.</summary>
    public static JsonDocument ParseDocument(byte[] utf8)
    {
        Check(utf8);
        return JsonDocument.Parse(utf8);
    }

    /// <summary>The same rules, for JSON that arrives as a string, such as a form field a host has read.</summary>
    public static JsonDocument ParseDocument(string json)
    {
        byte[] utf8;
        try
        {
            utf8 = Utf8.GetBytes(json);
        }
        catch (EncoderFallbackException e)
        {
            throw new JsonException("A string is not valid Unicode text.", e);
        }

        return ParseDocument(utf8);
    }

    /// <summary>
    /// The rules alone, for a caller that reads the bytes its own way. Throws <see cref="JsonException"/>. A
    /// refusal under these rules names the rule and never the sender's text; text that is not JSON at all is the
    /// reader's own refusal, whose message can quote it, so a caller that passes messages on refuses that first.
    /// </summary>
    public static void Check(byte[] utf8)
    {
        var reader = new Utf8JsonReader(utf8);
        var names = new Stack<HashSet<string>>();
        while (reader.Read())
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.StartObject:
                    names.Push(new HashSet<string>(StringComparer.Ordinal));
                    break;
                case JsonTokenType.EndObject:
                    names.Pop();
                    break;
                case JsonTokenType.PropertyName:
                    if (!names.Peek().Add(ReadText(ref reader)))
                    {
                        throw new JsonException("An object repeats a property name.");
                    }

                    break;
                case JsonTokenType.String:
                    _ = ReadText(ref reader);
                    break;
                case JsonTokenType.Number:
                    if (!reader.TryGetInt64(out _) && (!reader.TryGetDouble(out var d) || !double.IsFinite(d)))
                    {
                        throw new JsonException("A number is outside the range of a double.");
                    }

                    break;
            }
        }
    }

    // GetString throws InvalidOperationException for bytes that are not UTF-8 (RFC 8259 §8.1 requires it)
    // and for an escaped lone surrogate such as "\uD800", which names no character (§8.2 leaves its
    // handling unpredictable). Either is text this verifier cannot read as a claim.
    private static string ReadText(ref Utf8JsonReader reader)
    {
        try
        {
            return reader.GetString()!;
        }
        catch (InvalidOperationException e)
        {
            throw new JsonException("A string is not valid Unicode text.", e);
        }
    }
}
