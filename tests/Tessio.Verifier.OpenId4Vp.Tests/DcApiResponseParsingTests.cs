using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.OpenId4Vp.Tests;

/// <summary>
/// An OpenID4VP response returned through the Digital Credentials API: the <c>data</c> object a page receives,
/// cleartext under <c>dc_api</c>, a single <c>response</c> JWE under <c>dc_api.jwt</c> (OpenID4VP 1.0 Appendix
/// A.2 and A.4).
/// </summary>
public sealed class DcApiResponseParsingTests : IDisposable
{
    private readonly ECDsa _verifierEc = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public void Dispose() => _verifierEc.Dispose();

    private string Sealed(string payloadJson)
    {
        var p = _verifierEc.ExportParameters(false);
        var jwk = new JsonWebKey { Kty = "EC", Crv = "P-256", X = Base64UrlEncoder.Encode(p.Q.X!), Y = Base64UrlEncoder.Encode(p.Q.Y!) };
        return WalletEncryption.EcdhEsTo(jwk, payloadJson);
    }

    private WalletResponseParser Parser(bool readErrorResponses = false) => new(new WalletResponseParserOptions
    {
        ResponseDecryptionKey = new ECDsaSecurityKey(_verifierEc),
        ReadErrorResponses = readErrorResponses,
    });

    [Fact]
    public async Task ACleartextResponse_YieldsItsPresentations_Unencrypted()
    {
        var parsed = await Parser().ParseDcApiAsync("""{"vp_token":{"pid":["a.b.c~","d.e.f~"]}}""");

        Assert.Equal(["a.b.c~", "d.e.f~"], parsed.Credentials.Select(c => c.RawValue));
        Assert.False(parsed.Encrypted);
        Assert.Null(parsed.Error);
    }

    [Theory]
    [InlineData("""{"vp_token":{"pid":["junk"],"pid":["a.b.c~"]}}""")]
    [InlineData("""{"vp_token":{"pid":["a.b.c~"]},"note":1e400}""")]
    public async Task ADataObjectBreakingTheJsonRules_IsRefused(string dataJson)
    {
        // A credential query named twice inside vp_token, or a number a double reads as infinity, used to pass: the
        // repeat check looked at the top level only, and numbers were not checked at all.
        await Assert.ThrowsAsync<WalletResponseException>(() => Parser().ParseDcApiAsync(dataJson));
    }

    [Fact]
    public async Task AnEncryptedResponse_IsDecrypted_AndMarkedEncrypted()
    {
        var parsed = await Parser().ParseDcApiAsync(
            $$"""{"response":"{{Sealed("""{"vp_token":{"mdl":["o2d2ZXJzaW9u"]}}""")}}"}""");

        Assert.Equal("o2d2ZXJzaW9u", Assert.Single(parsed.Credentials).RawValue);
        Assert.True(parsed.Encrypted);
    }

    [Theory]
    [InlineData("""{"vp_token":{"pid":["a.b.c~"]},"state":"s-1"}""")]
    [InlineData("""{"vp_token":{"pid":["a.b.c~"]},"state":42}""")]
    public async Task AState_IsNeverReturned_BecauseTheTransportDefinesNone(string dataJson)
    {
        var parsed = await Parser().ParseDcApiAsync(dataJson);

        Assert.Null(parsed.State);
    }

    [Fact]
    public async Task AStateSealedInAnEncryptedResponse_IsNotReturnedEither()
    {
        var parsed = await Parser().ParseDcApiAsync(
            $$"""{"response":"{{Sealed("""{"vp_token":{"pid":["a.b.c~"]},"state":"s-1"}""")}}"}""");

        Assert.Null(parsed.State);
    }

    [Fact]
    public async Task ACleartextError_IsReturned_WhenTheCallerReadsErrors()
    {
        var parsed = await Parser(readErrorResponses: true).ParseDcApiAsync("""{"error":"access_denied"}""");

        Assert.Equal("access_denied", parsed.Error);
        Assert.Empty(parsed.Credentials);
        Assert.False(parsed.Encrypted);
    }

    [Fact]
    public async Task ASealedError_IsReturned_MarkedEncrypted()
    {
        var parsed = await Parser(readErrorResponses: true).ParseDcApiAsync(
            $$"""{"response":"{{Sealed("""{"error":"access_denied"}""")}}"}""");

        Assert.Equal("access_denied", parsed.Error);
        Assert.True(parsed.Encrypted);
    }

    [Fact]
    public async Task ByDefault_AnError_IsThrown()
    {
        await Assert.ThrowsAsync<WalletResponseException>(() => Parser().ParseDcApiAsync("""{"error":"access_denied"}"""));
    }

    [Theory]
    [InlineData("""
                "vp_token":{"pid":["a.b.c~"]}
                """)]
    [InlineData("""
                "error":"access_denied"
                """)]
    public async Task AnEncryptedResponseBesideCleartextParameters_IsRefused(string cleartextMember)
    {
        var dataJson = $$"""{"response":"{{Sealed("""{"vp_token":{"pid":["x.y.z~"]}}""")}}",{{cleartextMember}}}""";

        var e = await Assert.ThrowsAsync<WalletResponseException>(() => Parser(readErrorResponses: true).ParseDcApiAsync(dataJson));
        Assert.Contains("beside cleartext", e.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("""not json""")]
    [InlineData("""["vp_token"]""")]
    [InlineData("""{}""")]
    [InlineData("""{"response":42}""")]
    [InlineData("""{"response":"not-a-jwe"}""")]
    [InlineData("""{"vp_token":{"pid":[42]}}""")]
    [InlineData("""{"vp_token":{"pid":["\uD800"]}}""")]
    public async Task AMalformedObject_IsAWalletResponseException(string dataJson)
    {
        await Assert.ThrowsAsync<WalletResponseException>(() => Parser(readErrorResponses: true).ParseDcApiAsync(dataJson));
    }

    [Fact]
    public async Task AnEncryptedResponse_WithNoKeyConfigured_IsAWalletResponseException()
    {
        var parser = new WalletResponseParser();

        await Assert.ThrowsAsync<WalletResponseException>(() => parser.ParseDcApiAsync(
            $$"""{"response":"{{Sealed("""{"vp_token":{"pid":["a.b.c~"]}}""")}}"}"""));
    }
}
