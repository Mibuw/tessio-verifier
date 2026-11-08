using System.Formats.Cbor;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Converts a CBOR data item to the plain .NET shape used in
/// <see cref="VerificationResult.DisclosedClaims"/>: string, long, double, bool, byte[],
/// List&lt;object?&gt;, Dictionary&lt;string, object?&gt; or null. Dates (tag 0 tdate,
/// tag 1004 full-date) surface as their RFC 3339 strings.
/// </summary>
internal static class CborValueConverter
{
    /// <summary>
    /// How deeply arrays and maps may nest in one value. Recursion is bounded so that a hostile value cannot
    /// overflow the stack; mdoc element values nest a few levels at most. It is the bound disclosed SD-JWT claims
    /// are held to (<see cref="Tessio.Verifier.Core.JsonValueConverter.MaxDepth"/>), so a result's claims share one
    /// depth whichever format they came from.
    /// </summary>
    internal const int MaxDepth = Tessio.Verifier.Core.JsonValueConverter.MaxDepth;

    public static object? Read(CborReader reader) => Read(reader, 0);

    private static object? Read(CborReader reader, int depth)
    {
        if (depth > MaxDepth)
        {
            // InvalidOperationException is what CborFailure.IsMalformed maps to a structure error.
            throw new InvalidOperationException($"A CBOR value nests deeper than {MaxDepth} levels.");
        }

        while (reader.PeekState() == CborReaderState.Tag)
        {
            reader.ReadTag(); // tdate/full-date and similar: expose the tagged content directly.
        }

        switch (reader.PeekState())
        {
            case CborReaderState.TextString:
                return reader.ReadTextString();
            case CborReaderState.UnsignedInteger:
            case CborReaderState.NegativeInteger:
                return reader.ReadInt64();
            case CborReaderState.HalfPrecisionFloat:
            case CborReaderState.SinglePrecisionFloat:
            case CborReaderState.DoublePrecisionFloat:
                return reader.ReadDouble();
            case CborReaderState.Boolean:
                return reader.ReadBoolean();
            case CborReaderState.Null:
                reader.ReadNull();
                return null;
            case CborReaderState.ByteString:
                return reader.ReadByteString();
            case CborReaderState.StartArray:
            {
                List<object?> list = [];
                reader.ReadStartArray();
                while (reader.PeekState() != CborReaderState.EndArray)
                {
                    list.Add(Read(reader, depth + 1));
                }

                reader.ReadEndArray();
                return list;
            }

            case CborReaderState.StartMap:
            {
                Dictionary<string, object?> map = new(StringComparer.Ordinal);
                reader.ReadStartMap();
                while (reader.PeekState() != CborReaderState.EndMap)
                {
                    // Non-text keys are legal CBOR; stringify so the claim survives into the result.
                    var key = reader.PeekState() == CborReaderState.TextString
                        ? reader.ReadTextString()
                        : reader.ReadInt64().ToString(System.Globalization.CultureInfo.InvariantCulture);
                    map[key] = Read(reader, depth + 1);
                }

                reader.ReadEndMap();
                return map;
            }

            default:
                reader.SkipValue();
                return null;
        }
    }
}
