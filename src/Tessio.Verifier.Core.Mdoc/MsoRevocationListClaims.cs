using System.Formats.Cbor;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Reads the claims set of an MSO revocation list whose signature has verified, and holds it to the claims
/// each kind of list must and must not carry.
/// </summary>
internal static class MsoRevocationListClaims
{
    // SPEC: RFC 8392 section 3.1.2 (sub = 2), 3.1.4 (exp = 4), 3.1.5 (nbf = 5), 3.1.6 (iat = 6); draft-ietf-oauth-status-list-20
    // section 5.2 (status list = 65533, ttl = 65534); EAA-6.2.10.1-09 (IdentifierList = 65530).
    private const long SubClaim = 2, ExpClaim = 4, NbfClaim = 5, IatClaim = 6;
    private const long IdentifierListClaim = 65530, StatusListClaim = 65533, TtlClaim = 65534;

    public static MsoRevocationListToken Read(byte[] claims, RevocationListKind kind, ReadOnlyMemory<byte>[] chain)
    {
        string? subject = null;
        long? exp = null, nbf = null, iat = null, ttl = null, bits = null;
        byte[]? lst = null;
        HashSet<string>? identifiers = null;
        var sawStatusList = false;

        // STRICT, so a repeated claim is refused rather than resolved by whichever copy came last.
        var reader = new CborReader(claims, CborConformanceMode.Strict);
        reader.ReadStartMap();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            if (reader.PeekState() is not (CborReaderState.UnsignedInteger or CborReaderState.NegativeInteger))
            {
                reader.SkipValue();
                reader.SkipValue();
                continue;
            }

            switch (reader.ReadInt64())
            {
                case SubClaim:
                    subject = reader.ReadTextString();
                    break;
                case ExpClaim:
                    exp = ReadNumericDate(reader);
                    break;
                case NbfClaim:
                    nbf = ReadNumericDate(reader);
                    break;
                case IatClaim:
                    iat = ReadNumericDate(reader);
                    break;
                case TtlClaim:
                    // SPEC: draft-ietf-oauth-status-list-20 section 5.2, ttl is an unsigned integer. One past long
                    // saturates rather than refuses, as the JWT path's does: it is valid, only longer than any cache.
                    var ttlValue = reader.ReadUInt64();
                    ttl = ttlValue switch
                    {
                        0 => throw new MsoRevocationListToken.InvalidListException("The MSO revocation list's ttl is not a positive integer."),
                        > long.MaxValue => long.MaxValue,
                        _ => (long)ttlValue,
                    };
                    break;
                case StatusListClaim:
                    sawStatusList = true;
                    (bits, lst) = ReadStatusList(reader);
                    break;
                case IdentifierListClaim when kind == RevocationListKind.IdentifierList:
                    identifiers = ReadIdentifierList(reader);
                    break;
                default:
                    reader.SkipValue();
                    break;
            }
        }

        reader.ReadEndMap();

        // SPEC: draft-ietf-oauth-status-list-20 section 5.2, sub and iat REQUIRED; EAA-6.2.10.1-08, "the exp
        // claim shall be present", stricter than the draft's RECOMMENDED. Each absent claim is named, so the
        // refusal says which claims the list's issuer has to add.
        if (subject is null || iat is null || exp is null)
        {
            throw new MsoRevocationListToken.InvalidListException(LacksClaims(subject is null, iat is null, exp is null));
        }

        if (kind == RevocationListKind.StatusList)
        {
            return bits is null || lst is null
                ? throw new MsoRevocationListToken.InvalidListException("The MSO revocation list carries no status list claim (65533).")
                : new MsoRevocationListToken(chain, subject, DateTimeOffset.FromUnixTimeSeconds(exp.Value), NotBefore(nbf), ttl, (int)bits, lst, null);
        }

        // SPEC: EAA-6.2.10.1-09, "the StatusList claim shall not be present in the CWT claims set".
        if (sawStatusList)
        {
            throw new MsoRevocationListToken.InvalidListException("The identifier list carries a status list claim (65533), which it must not.");
        }

        return identifiers is null
            ? throw new MsoRevocationListToken.InvalidListException("The MSO revocation list carries no identifier list claim (65530).")
            : new MsoRevocationListToken(chain, subject, DateTimeOffset.FromUnixTimeSeconds(exp.Value), NotBefore(nbf), ttl, 0, null, identifiers);
    }

    // SPEC: draft-ietf-oauth-status-list-20 section 4.3, StatusList = { bits: 1 / 2 / 4 / 8, lst: bstr,
    // ? aggregation_uri: tstr }.
    private static (long Bits, byte[] Lst) ReadStatusList(CborReader reader)
    {
        long? bits = null;
        byte[]? lst = null;
        reader.ReadStartMap();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            switch (reader.ReadTextString())
            {
                case "bits":
                    bits = reader.ReadInt64();
                    break;
                case "lst":
                    lst = reader.ReadByteString();
                    break;
                default:
                    reader.SkipValue();
                    break;
            }
        }

        reader.ReadEndMap();
        return bits is { } b && StatusListValues.IsAllowedBits(b) && lst is not null
            ? (b, lst)
            : throw new MsoRevocationListToken.InvalidListException("The status list claim does not carry bits of 1, 2, 4 or 8 and an lst byte string.");
    }

    // SPEC: EAA-6.2.10.1-10, IdentifierList = { 'identifiers': { * Identifier => IdentifierInfo },
    // ? 'aggregation_uri': Aggregation_uri * tstr => RFU }, Identifier = bstr. IdentifierInfo is RFU, so only
    // the keys are read.
    private static HashSet<string> ReadIdentifierList(CborReader reader)
    {
        HashSet<string>? identifiers = null;
        reader.ReadStartMap();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            if (reader.ReadTextString() != "identifiers")
            {
                reader.SkipValue();
                continue;
            }

            identifiers = new HashSet<string>(StringComparer.Ordinal);
            reader.ReadStartMap();
            while (reader.PeekState() != CborReaderState.EndMap)
            {
                identifiers.Add(Convert.ToHexString(reader.ReadByteString()));
                reader.SkipValue();
            }

            reader.ReadEndMap();
        }

        reader.ReadEndMap();
        return identifiers ?? throw new MsoRevocationListToken.InvalidListException("The identifier list claim carries no identifiers map.");
    }

    private static string LacksClaims(bool sub, bool iat, bool exp)
    {
        var missing = new[] { sub ? "sub" : null, iat ? "iat" : null, exp ? "exp" : null }.OfType<string>().ToArray();
        return missing.Length == 1
            ? $"The MSO revocation list lacks the required {missing[0]} claim."
            : $"The MSO revocation list lacks the required {string.Join(", ", missing[..^1])} and {missing[^1]} claims.";
    }

    private static DateTimeOffset? NotBefore(long? nbf) => nbf is { } seconds ? DateTimeOffset.FromUnixTimeSeconds(seconds) : null;

    // SPEC: RFC 8392 section 2, NumericDate is an integer or a floating-point number of seconds.
    private static long ReadNumericDate(CborReader reader) => reader.PeekState() switch
    {
        CborReaderState.UnsignedInteger or CborReaderState.NegativeInteger => reader.ReadInt64(),
        CborReaderState.HalfPrecisionFloat or CborReaderState.SinglePrecisionFloat or CborReaderState.DoublePrecisionFloat
            => reader.ReadDouble() is var d && double.IsFinite(d) && Math.Abs(d) < 253402300800
                ? (long)Math.Floor(d)
                : throw new MsoRevocationListToken.InvalidListException("The MSO revocation list carries an out-of-range date."),
        _ => throw new MsoRevocationListToken.InvalidListException("The MSO revocation list carries a date that is not a number."),
    };
}
