// What belongs here: JWE headers the parser refuses although the response otherwise decrypts, under the JOSE
// RFCs, RFC 8259 or this library's policy (zip), on both decryption routes. Headers that fail to decrypt at
// all are CraftedJweHeaderTests'.
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.OpenId4Vp.Tests;

/// <summary>
/// A response encrypted correctly under a header the parser refuses as written: a critical extension, a
/// compression, a member named twice, nesting past the rules' limit, or content after the header object.
/// </summary>
public sealed class JweHeaderRulesTests : IDisposable
{
    private const string Plain = "{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":EPK}";

    private readonly ECDsa _verifierEc = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public void Dispose() => _verifierEc.Dispose();

    private JsonWebKey VerifierPublicJwk()
    {
        var p = _verifierEc.ExportParameters(false);
        return new JsonWebKey { Kty = "EC", Crv = "P-256", X = Base64UrlEncoder.Encode(p.Q.X!), Y = Base64UrlEncoder.Encode(p.Q.Y!) };
    }

    private Task<ParsedWalletResponse> ParseUnder(string headerTemplate) =>
        ParseUnder(headerTemplate, new WalletResponseParserOptions { ResponseDecryptionKey = new ECDsaSecurityKey(_verifierEc) });

    private Task<ParsedWalletResponse> ParseUnder(string headerTemplate, WalletResponseParserOptions options)
    {
        var payload = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["vp_token"] = new Dictionary<string, string[]> { ["pid"] = ["eyJoZWFkZXIifQ.eyJwYXlsb2FkIn0.c2ln~"] },
            ["state"] = "s",
        });
        // EPKDUP repeats the key's crv member, which leaves the key itself unchanged. One pass over the template:
        // a second would rescan the inserted key, whose random coordinates can themselves contain "EPK".
        var jwe = WalletEncryption.EcdhEsUnderHeader(VerifierPublicJwk(), payload, epk => Regex.Replace(
            headerTemplate,
            "EPKDUP|EPK",
            placeholder => placeholder.Value == "EPK"
                ? epk
                : epk.Replace("\"crv\":\"P-256\"", "\"crv\":\"P-256\",\"crv\":\"P-256\"", StringComparison.Ordinal)));
        var parser = new WalletResponseParser(options);
        return parser.ParseDetailedAsync(new WalletResponseData
        {
            ContentType = "application/x-www-form-urlencoded",
            Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal) { ["response"] = [jwe] },
            Body = ReadOnlyMemory<byte>.Empty,
        });
    }

    [Theory]
    [InlineData(Plain)]
    // Members the rules leave alone: an unrecognised one, which RFC 7516 section 4 says to ignore, even when
    // it holds names that are rules at the top level, and the same name in two objects, which is no duplicate.
    // Names that differ only in case are two names, to IdentityModel and to the rules.
    [InlineData("{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":EPK,\"kid\":\"a\",\"KID\":\"b\",\"Zip\":\"DEF\",\"Crit\":[\"x\"]}")]
    [InlineData("{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":EPK,\"x\":\"not the key's\",\"zz\":{\"kty\":1,\"crit\":[\"x\"],\"zip\":\"DEF\"}}")]
    public async Task A_plain_header_parses(string header)
    {
        // The control: without it, every refusal below could be the helper building a broken response.
        Assert.Equal("s", (await ParseUnder(header)).State);
    }

    [Theory]
    [InlineData("{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":EPK,\"crit\":[\"x\"],\"x\":1}")]
    [InlineData("{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":EPK,\"crit\":[\"x\"]}")]
    [InlineData("{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":EPK,\"crit\":[]}")]
    [InlineData("{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":EPK,\"crit\":[\"epk\"]}")]
    [InlineData("{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":EPK,\"crit\":\"x\"}")]
    public async Task A_critical_header_is_refused(string header)
    {
        var refused = await Assert.ThrowsAsync<WalletResponseException>(() => ParseUnder(header));
        Assert.Contains("(crit)", refused.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":EPK,\"zip\":\"DEF\"}")]
    [InlineData("{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":EPK,\"zip\":\"other\"}")]
    public async Task A_compressed_payload_is_refused(string header)
    {
        var refused = await Assert.ThrowsAsync<WalletResponseException>(() => ParseUnder(header));
        Assert.Contains("(zip)", refused.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":EPK,\"epk\":EPK}")]
    [InlineData("{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":EPK,\"kid\":\"a\",\"kid\":\"b\"}")]
    [InlineData("{\"alg\":\"ECDH-ES\",\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":EPK}")]
    // The same name escaped differently is still the same name.
    [InlineData("{\"alg\":\"ECDH-ES\",\"\\u0061lg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":EPK}")]
    // Inside the ephemeral key too: RFC 7517 section 4 sets the same rule for a JWK's members.
    [InlineData("{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":EPKDUP}")]
    // A name the sender chose, line break included, which the message must not repeat.
    [InlineData("{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":EPK,\"a\\nforged\":1,\"a\\nforged\":2}")]
    public async Task A_member_named_twice_is_refused(string header)
    {
        var refused = await Assert.ThrowsAsync<WalletResponseException>(() => ParseUnder(header));
        Assert.Contains("repeats a property name", refused.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("forged", refused.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":EPK,\"x\":{\"\\uD800\":1}}")]
    [InlineData("{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":EPK,\"n\":1e400}")]
    public async Task A_header_with_text_or_a_number_JSON_rules_refuse_is_refused_not_thrown(string header)
    {
        // A name that is not valid text used to throw out of the parser when read into a string, and a number a
        // double reads as infinity used to pass. Both are StrictJson's rules, applied here as everywhere else.
        var refused = await Assert.ThrowsAsync<WalletResponseException>(() => ParseUnder(header));
        Assert.Contains("is not JSON with", refused.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task A_header_nested_deeper_than_the_rules_read_is_refused_and_one_level_less_is_not(bool objects)
    {
        // An unrecognised member is ignored however it is shaped, unless it nests past what the rules read.
        // The header object is the first level, so the member may take MaxDepth - 1 levels and no more,
        // whether it nests arrays or objects.
        string Under(int levels) => "{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":EPK,\"zz\":" + (objects
            ? string.Concat(Enumerable.Repeat("{\"a\":", levels - 1)) + "{}" + new string('}', levels - 1)
            : new string('[', levels) + new string(']', levels)) + "}";

        Assert.Equal("s", (await ParseUnder(Under(JweHeaderRules.MaxDepth - 1))).State);
        var refused = await Assert.ThrowsAsync<WalletResponseException>(() => ParseUnder(Under(JweHeaderRules.MaxDepth)));
        Assert.Contains("nests deeper", refused.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_refused_header_costs_no_key_lookup()
    {
        var lookups = 0;
        var options = new WalletResponseParserOptions
        {
            ResponseDecryptionKeyResolver = _ => { lookups++; return new ECDsaSecurityKey(_verifierEc); },
        };

        await Assert.ThrowsAsync<WalletResponseException>(() => ParseUnder("{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":EPK,\"crit\":[\"x\"]}", options));
        Assert.Equal(0, lookups);
        Assert.Equal("s", (await ParseUnder(Plain, options)).State);
        Assert.Equal(1, lookups);
    }

    [Theory]
    [InlineData("{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":EPK}{\"crit\":[\"x\"]}")]
    [InlineData("{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":EPK}x")]
    [InlineData("{\"alg\":\"ECDH-ES\",\"enc\":\"A128GCM\",\"epk\":EPK}//x")]
    public async Task A_header_with_anything_after_its_object_is_refused(string header)
    {
        // RFC 7516 §5.2 step 3: the header is one JSON object and nothing else.
        var refused = await Assert.ThrowsAsync<WalletResponseException>(() => ParseUnder(header));
        Assert.Contains("not a single JSON object", refused.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("crit", "(crit)")]
    [InlineData("zip", "(zip)")]
    public async Task The_rules_hold_on_the_IdentityModel_route_too(string member, string rule)
    {
        // A dir response is decrypted by IdentityModel's handler, not the ECDH-ES decryptor, and the rules
        // run before either, so they hold on this route as well.
        var key = new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32));
        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        var inner = handler.CreateToken("{\"vp_token\":{\"pid\":[\"eyJoZWFkZXIifQ.eyJwYXlsb2FkIn0.c2ln~\"]},\"state\":\"s\"}");
        var credentials = new EncryptingCredentials(key, "dir", SecurityAlgorithms.Aes128CbcHmacSha256);
        var jwe = member == "zip"
            ? handler.EncryptToken(inner, credentials, "DEF")
            : handler.EncryptToken(inner, credentials, new Dictionary<string, object> { ["crit"] = new[] { "x" }, ["x"] = 1 });
        var parser = new WalletResponseParser(new WalletResponseParserOptions { ResponseDecryptionKey = key });
        WalletResponseData Form(string response) => new()
        {
            ContentType = "application/x-www-form-urlencoded",
            Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal) { ["response"] = [response] },
            Body = ReadOnlyMemory<byte>.Empty,
        };

        var refused = await Assert.ThrowsAsync<WalletResponseException>(() => parser.ParseDetailedAsync(Form(jwe)));
        Assert.Contains(rule, refused.Message, StringComparison.Ordinal);
        // The control on this route: the same response without the member parses.
        Assert.Equal("s", (await parser.ParseDetailedAsync(Form(handler.EncryptToken(inner, credentials)))).State);
    }
}
