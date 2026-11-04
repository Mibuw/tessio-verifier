using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.OpenId4Vp.Tests;

/// <summary>
/// An Authorization Error Response sealed inside a <c>direct_post.jwt</c> <c>response</c>. OpenID4VP 1.0 section
/// 5.6: "Both successful and error responses SHOULD be returned using the supplied Response Mode", so this is the
/// form a wallet uses when the request asked for encryption. It is read under the cleartext form's rules.
/// </summary>
public sealed class SealedAuthorizationErrorResponseParsingTests : IDisposable
{
    private readonly ECDsa _verifierEc = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public void Dispose() => _verifierEc.Dispose();

    private string Sealed(string payloadJson)
    {
        var p = _verifierEc.ExportParameters(false);
        var jwk = new JsonWebKey { Kty = "EC", Crv = "P-256", X = Base64UrlEncoder.Encode(p.Q.X!), Y = Base64UrlEncoder.Encode(p.Q.Y!) };
        return WalletEncryption.EcdhEsTo(jwk, payloadJson);
    }

    private static WalletResponseData Form(string sealedResponse) => new()
    {
        ContentType = "application/x-www-form-urlencoded",
        Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal) { ["response"] = [sealedResponse] },
        Body = ReadOnlyMemory<byte>.Empty,
    };

    private WalletResponseParser Parser(bool readErrorResponses) => new(new WalletResponseParserOptions
    {
        ResponseDecryptionKey = new ECDsaSecurityKey(_verifierEc),
        ReadErrorResponses = readErrorResponses,
    });

    [Fact]
    public async Task ASealedErrorResponse_IsReturned_WithItsCodeAndState()
    {
        var parsed = await Parser(readErrorResponses: true).ParseDetailedAsync(
            Form(Sealed("""{"error":"access_denied","error_description":"The holder declined","state":"s-1"}""")));

        Assert.Equal("access_denied", parsed.Error);
        Assert.Equal("s-1", parsed.State);
        Assert.True(parsed.Encrypted);
        Assert.Empty(parsed.Credentials);
    }

    [Fact]
    public async Task ByDefault_ASealedErrorResponse_IsStillThrown()
    {
        await Assert.ThrowsAsync<WalletResponseException>(() => Parser(readErrorResponses: false).ParseDetailedAsync(
            Form(Sealed("""{"error":"access_denied","state":"s-1"}"""))));
    }

    [Fact]
    public async Task AnErrorBesideASealedPresentation_IsReadAsThePresentation()
    {
        var parsed = await Parser(readErrorResponses: true).ParseDetailedAsync(
            Form(Sealed("""{"vp_token":{"pid":["a.b.c~"]},"error":"access_denied","state":"s-1"}""")));

        Assert.Null(parsed.Error);
        Assert.Equal("a.b.c~", Assert.Single(parsed.Credentials).RawValue);
    }

    [Theory]
    [InlineData("""{"error":42,"state":"s-1"}""")]
    [InlineData("""{"error":"access\"denied","state":"s-1"}""")]
    [InlineData("""{"error":"","state":"s-1"}""")]
    public async Task ASealedErrorThatIsNotAnAllowedCode_IsRefused(string payloadJson)
    {
        await Assert.ThrowsAsync<WalletResponseException>(() =>
            Parser(readErrorResponses: true).ParseDetailedAsync(Form(Sealed(payloadJson))));
    }

    [Fact]
    public async Task ParseAsync_StillThrows_OnASealedErrorResponse()
    {
        await Assert.ThrowsAsync<WalletResponseException>(() => Parser(readErrorResponses: true).ParseAsync(
            Form(Sealed("""{"error":"access_denied","state":"s-1"}"""))));
    }

    [Theory]
    [InlineData("""{"vp_token":{"pid":["junk"]},"vp_token":{"pid":["a.b.c~"]},"state":"s-1"}""")]
    [InlineData("""{"vp_token":{"pid":["a.b.c~"]},"state":"s-1","state":"s-2"}""")]
    [InlineData("""{"vp_token":{"pid":["junk"],"pid":["a.b.c~"]},"state":"s-1"}""")]
    public async Task ASealedPayloadNamingAParameterTwice_IsRefused(string payloadJson)
    {
        // The form a wallet posts refuses a repeated field; the payload sealed inside it is held to the same rule,
        // so a second vp_token cannot ride along beside the one verified.
        await Assert.ThrowsAsync<WalletResponseException>(() =>
            Parser(readErrorResponses: true).ParseDetailedAsync(Form(Sealed(payloadJson))));
    }
}
