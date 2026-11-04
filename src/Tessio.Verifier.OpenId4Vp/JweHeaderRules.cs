// What belongs in this file: the JOSE header rules a JWE recipient applies whatever the algorithm, before
// any key is looked up. Nothing about decrypting, which is EcdhEsJweDecryptor and IdentityModel.

using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Core;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// Refuses an encrypted response whose header marks an extension critical, names a compression, says one
/// thing twice, nests too deep, or is not a single JSON object.
/// </summary>
/// <remarks>
/// <para>
/// Every member is read here, not only the ones decryption needs, because a member nothing reads cannot
/// refuse anything. Each rule says which text it rests on: RFC 7515 and 7516 for crit and the single object,
/// RFC 7516, 7517 and 8259 for duplicates, RFC 8259 for the depth limit, and this library's own policy,
/// under RFC 7516's "application decision", for zip.
/// </para>
/// <para>
/// Applied to every JWE the parser receives, not only to ECDH-ES ones, because none of the rules depends
/// on the key management algorithm.
/// </para>
/// </remarks>
internal static class JweHeaderRules
{
    /// <summary>How deep a header may nest, counting the header object itself, before it is refused.</summary>
    /// <remarks>
    /// The header members the JOSE specifications define nest a level or two: a JWK such as epk is an object
    /// in the header object. Sixteen leaves room for every real header. It is checked here, below
    /// IdentityModel's own limit, rather than left to a reader's default: the refusal then does not depend on
    /// two libraries keeping the same number, and a test can reach it. SPEC: RFC 8259 §9: "An implementation
    /// may set limits on the maximum depth of nesting."
    /// </remarks>
    internal const int MaxDepth = 16;

    /// <summary>Throws <see cref="WalletResponseException"/> when the header of <paramref name="jwe"/> breaks a rule.</summary>
    public static void Enforce(JsonWebToken jwe)
    {
        var header = Base64UrlEncoder.DecodeBytes(jwe.EncodedHeader);

        // The reader's own limit sits above MaxDepth, so the depth refusal below is always the one that fires.
        var reader = new Utf8JsonReader(header, new JsonReaderOptions { MaxDepth = MaxDepth + 1 });
        try
        {
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject or JsonTokenType.StartArray when reader.CurrentDepth >= MaxDepth:
                        throw new WalletResponseException("The encrypted response's header nests deeper than this library reads.");
                    case JsonTokenType.PropertyName when reader.CurrentDepth == 1:
                        TopLevelMember(ref reader);
                        break;
                }
            }
        }
        catch (JsonException)
        {
            // SPEC: RFC 7516 §5.2 step 3: the header must be "a completely valid JSON object conforming to RFC
            // 7159". This reader is strict, so a header that is anything more than that one object (a second
            // object, a comment, stray text after it) is refused here.
            throw new WalletResponseException("The encrypted response's header is not a single JSON object.");
        }

        // SPEC: RFC 7516 §5.2 step 4: "verify that the resulting JOSE Header does not contain duplicate Header
        // Parameter names". RFC 7517 §4 has a JWK parser reject duplicate members or keep the last, which covers
        // epk, and inside a member no specification defines, RFC 8259 §4 says "The names within an object
        // SHOULD be unique" and that otherwise the behaviour of software receiving them is "unpredictable".
        // Refusing is the choice each text allows, at every depth, because which of two values a reader takes
        // is exactly what the two readers of this header, IdentityModel's and this one, could disagree on.
        // StrictJson owns that rule, and with it the rules on text and numbers. A refusal under them names the rule
        // and never the sender's text, and the pass above has already refused anything that is not one JSON
        // object, the one refusal whose message could quote it, so the message may be logged as it stands.
        try
        {
            StrictJson.Check(header);
        }
        catch (JsonException e)
        {
            throw new WalletResponseException($"The encrypted response's header is not JSON with {StrictJson.Accepts}: {e.Message}");
        }
    }

    // Names are compared with ValueTextEquals, which unescapes as any JSON reader does, rather than read into a
    // string: GetString throws for a name that is not valid text, and StrictJson refuses that above as a rule.
    private static void TopLevelMember(ref Utf8JsonReader reader)
    {
        // SPEC: RFC 7515 §4.1.11, applied to JWE by RFC 7516 §4.1.13: "If any of the listed extension Header
        // Parameters are not understood and supported by the recipient, then the JWS is invalid." This library
        // supports no extension, so every list it could be sent fails that rule, and the lists that would not
        // (empty, or naming a parameter JWS or JWA defines) are ones a producer "MUST NOT" send and a recipient
        // "MAY consider ... invalid". So any crit is refused.
        if (reader.ValueTextEquals("crit"))
        {
            throw new WalletResponseException(
                "The encrypted response's header marks parameters as critical (crit); this library supports no JOSE extension.");
        }

        // A policy, not a requirement, and one rule for both routes. The ECDH-ES route decompresses nothing,
        // so it must refuse zip or read the compressed bytes as the payload. IdentityModel decompresses DEF,
        // so on its route this refuses what it would have read; neither OpenID4VP 1.0 nor HAIP 1.0 mentions
        // compressing a response, so the two routes are kept alike rather than one accepting what the other
        // cannot. SPEC: RFC 7518 §7.3 registers zip values as "Compression Algorithms", and RFC 7516 §5.2: "it
        // is an application decision which algorithms may be used in a given context ... unless the
        // algorithms used in the JWE are acceptable to the application, it SHOULD consider the JWE to be
        // invalid."
        if (reader.ValueTextEquals("zip"))
        {
            throw new WalletResponseException(
                "The encrypted response's header names a compression (zip); this library accepts no compressed response.");
        }
    }
}
