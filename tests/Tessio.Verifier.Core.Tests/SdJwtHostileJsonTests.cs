using System.Text;
using System.Text.RegularExpressions;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.Core.Tests;

/// <summary>
/// Signed JSON the verifier used to throw on or skip. It covers a repeated key, a number no double holds
/// and text that is not valid Unicode, then times outside the calendar or not numbers at all and a status
/// index that is not an integer. Anyone can sign a payload with an x5c of their own, so these reach the
/// verifier past the signature check. The verdict is a result, never an exception.
/// </summary>
public class SdJwtHostileJsonTests
{
    private static VerificationContext Context() => new()
    {
        Nonce = TestCredentialBuilder.DefaultNonce,
        Audience = TestCredentialBuilder.DefaultAudience,
    };

    private static async Task<VerificationResult> VerifyAsync(TestCredentialBuilder builder)
    {
        using var certificate = builder.UseCertificate();
        var verifier = new SdJwtVcVerifier(new FakeTrustListResolver(), httpClient: new HttpClient(new FakeHttpHandler()));
        return await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context(), null);
    }

    private static string Raw(string json) => Base64UrlEncoder.Encode(json);

    private static void AddRawDisclosure(TestCredentialBuilder builder, string json)
    {
        var disclosure = Raw(json);
        builder.ExtraDisclosures.Add(disclosure);
        builder.ExtraSdDigests.Add(DisclosureProcessor.ComputeDigest(disclosure));
    }

    [Fact]
    public async Task VerifyAsync_RepeatedKeyInSignedPayload_IsRefused()
    {
        var builder = new TestCredentialBuilder
        {
            RewritePayloadJson = json => json.Replace("\"iss\":", "\"vct\":\"https://other.example/x\",\"iss\":", StringComparison.Ordinal),
        };

        var result = await VerifyAsync(builder);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.StructureInvalid);
    }

    [Fact]
    public async Task VerifyAsync_AHeaderSignedByHand_StillVerifies()
    {
        // The builder signs by hand whenever a header rewrite is set. Without a rewrite that changes anything, the
        // credential verifies, so a refusal in the test below comes from the header, not from the signing.
        var builder = new TestCredentialBuilder { RewriteHeaderJson = json => json };

        var result = await VerifyAsync(builder);

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
    }

    [Fact]
    public async Task VerifyAsync_AJoseHeaderNamingX5cTwice_IsRefused()
    {
        // RFC 8259 §4: parsers disagree on a repeated name, so a header carrying two chains has no single signer.
        var builder = new TestCredentialBuilder
        {
            RewriteHeaderJson = json => json.Replace("\"typ\":", "\"x5c\":[\"AA==\"],\"typ\":", StringComparison.Ordinal),
        };

        var result = await VerifyAsync(builder);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.StructureInvalid
                                            && e.Message.Contains("JOSE header", StringComparison.Ordinal));
    }

    [Fact]
    public async Task VerifyAsync_RepeatedKeyInDisclosedObject_IsRefused()
    {
        var builder = new TestCredentialBuilder();
        AddRawDisclosure(builder, """["s","o",{"a":1,"a":2}]""");

        var result = await VerifyAsync(builder);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.DisclosureInvalid);
    }

    [Fact]
    public async Task VerifyAsync_DisclosedNumberBeyondADouble_IsRefused()
    {
        var builder = new TestCredentialBuilder();
        AddRawDisclosure(builder, """["s","big",1e400]""");

        var result = await VerifyAsync(builder);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.DisclosureInvalid);
    }

    [Theory]
    [InlineData("exp", "99999999999999", true)]
    [InlineData("exp", "-99999999999999", false)]
    [InlineData("nbf", "99999999999999", false)]
    [InlineData("nbf", "-99999999999999", true)]
    [InlineData("exp", "99999999999999.5", true)]
    [InlineData("exp", "-99999999999999.5", false)]
    public async Task VerifyAsync_TimeClaimBeyondTheCalendar_ReadsAsTheNearerEnd(string claim, string number, bool valid)
    {
        var builder = new TestCredentialBuilder
        {
            Exp = null,
            RewritePayloadJson = json => PrependMember(json, claim, number),
        };

        var result = await VerifyAsync(builder);

        Assert.Equal(valid, result.IsValid);
    }

    [Fact]
    public async Task VerifyAsync_FractionalTimeClaim_ReadsAsTheWholeSecondAtOrBeforeIt()
    {
        // Floor, not truncation: -0.5 is half a second before the epoch, so the whole second at or before it is
        // 23:59:59 on the last day of 1969. Truncating toward zero would read it as the epoch itself.
        var builder = new TestCredentialBuilder
        {
            Exp = null,
            RewritePayloadJson = json => PrependMember(json, "exp", "-0.5"),
        };

        var result = await VerifyAsync(builder);

        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.CredentialExpired
                                            && e.Message.Contains("1969-12-31T23:59:59", StringComparison.Ordinal));
    }

    // SPEC: RFC 7519 §4.1.4 and §4.1.5, "Its value MUST be a number containing a NumericDate value."
    // A string used to be skipped, so "exp":"0" never expired.
    // A string reaches this library's own check, so its message is pinned: a read that threw would reach the outer
    // net as structure_invalid too. The JWT parser refuses null and true itself, before that check runs.
    [Theory]
    [InlineData("exp", "\"0\"", "is not a NumericDate")]
    [InlineData("nbf", "\"4102444800\"", "is not a NumericDate")]
    [InlineData("exp", "null", "malformed")]
    [InlineData("exp", "true", "malformed")]
    public async Task VerifyAsync_TimeClaimThatIsNotANumber_IsRefused(string claim, string value, string message)
    {
        var builder = new TestCredentialBuilder
        {
            Exp = null,
            RewritePayloadJson = json => PrependMember(json, claim, value),
        };

        var result = await VerifyAsync(builder);

        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.StructureInvalid
                                            && e.Message.Contains(message, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("99999999999999")]
    [InlineData("-99999999999999")]
    public async Task VerifyAsync_KeyBindingIatBeyondTheCalendar_IsRefusedNotThrown(string iat)
    {
        var builder = new TestCredentialBuilder
        {
            RewriteKbPayloadJson = json => Regex.Replace(json, "\"iat\":-?\\d+", $"\"iat\":{iat}"),
        };

        var result = await VerifyAsync(builder);

        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.KeyBindingInvalid);
    }

    [Fact]
    public async Task VerifyAsync_KeyBindingIatAsAString_IsRefused()
    {
        // SPEC: RFC 7519 §4.1.6, iat "MUST be a number". The value is now, so only its type is wrong: the
        // handler's claim reads "1700000000" and 1700000000 alike, which is how a string iat used to pass.
        var builder = new TestCredentialBuilder
        {
            RewriteKbPayloadJson = json => Regex.Replace(json, "\"iat\":(\\d+)", "\"iat\":\"$1\""),
        };

        var result = await VerifyAsync(builder);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.KeyBindingInvalid
                                            && e.Message.Contains("not a numeric timestamp", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("$1.5")]
    [InlineData("$1e0")]
    public async Task VerifyAsync_KeyBindingIatAsAFractionOrExponent_IsAccepted(string replacement)
    {
        // SPEC: RFC 7519 §2, a NumericDate is a number, "other than that non-integer values can be represented".
        // Refusing the string form must not refuse these, which are numbers.
        var builder = new TestCredentialBuilder
        {
            RewriteKbPayloadJson = json => Regex.Replace(json, "\"iat\":(\\d+)", $"\"iat\":{replacement}"),
        };

        var result = await VerifyAsync(builder);

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Message)));
    }

    [Fact]
    public async Task VerifyAsync_KeyBindingPayloadRepeatingAMember_IsRefused()
    {
        // RFC 8259 §4: parsers disagree on a repeated name, so a stale iat beside a fresh one has no single
        // meaning. The KB-JWT is read as the issuer-signed payload is, and refused.
        var builder = new TestCredentialBuilder
        {
            RewriteKbPayloadJson = json => json.Replace("{", "{\"iat\":0,", StringComparison.Ordinal),
        };

        var result = await VerifyAsync(builder);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.KeyBindingInvalid
                                            && e.Message.Contains("payload is not JSON", StringComparison.Ordinal));
    }

    [Fact]
    public async Task VerifyAsync_DisclosedLoneSurrogate_IsRefusedAsADisclosure()
    {
        var builder = new TestCredentialBuilder();
        AddRawDisclosure(builder, """["s","o","\uD800"]""");

        var result = await VerifyAsync(builder);

        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.DisclosureInvalid);
    }

    private static string PrependMember(string json, string name, string value) =>
        $"{{\"{name}\":{value},{json[1..]}";

    [Theory]
    [InlineData("1.5")]
    [InlineData("1e300")]
    [InlineData("9223372036854775808")]
    public async Task VerifyAsync_StatusIndexNotAnInteger_IsRefusedNotThrown(string idx)
    {
        var builder = new TestCredentialBuilder
        {
            Status = (0, "https://issuer.example/statuslists/1"),
            RewritePayloadJson = json => json.Replace("\"idx\":0", $"\"idx\":{idx}", StringComparison.Ordinal),
        };

        var result = await VerifyAsync(builder);

        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.StatusInvalid);
    }

    [Theory]
    [InlineData(long.MaxValue, 253402300799)]
    [InlineData(long.MinValue, -62135596800)]
    [InlineData(1748537300L, 1748537300)]
    public void UnixTime_ClampsToTheCalendar(long seconds, long expected) =>
        Assert.Equal(expected, UnixTime.FromSeconds(seconds).ToUnixTimeSeconds());

    [Fact]
    public async Task VerifyAsync_OrdinaryDisclosedObjectAndNumbers_StillVerify()
    {
        var builder = new TestCredentialBuilder();
        AddRawDisclosure(builder, """["s","o",{"a":1,"b":2.5,"c":1e10}]""");

        var result = await VerifyAsync(builder);

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task VerifyAsync_DisclosureNotValidUtf8_IsRefusedAsADisclosure(bool inName)
    {
        var builder = new TestCredentialBuilder();
        byte[] head = Encoding.UTF8.GetBytes(inName ? "[\"s\",\"" : "[\"s\",\"o\",\"");
        byte[] tail = Encoding.UTF8.GetBytes(inName ? "\",1]" : "\"]");
        var disclosure = Base64UrlEncoder.Encode([.. head, 0xC3, 0x28, .. tail]);
        builder.ExtraDisclosures.Add(disclosure);
        builder.ExtraSdDigests.Add(DisclosureProcessor.ComputeDigest(disclosure));

        var result = await VerifyAsync(builder);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.DisclosureInvalid);
    }
}
