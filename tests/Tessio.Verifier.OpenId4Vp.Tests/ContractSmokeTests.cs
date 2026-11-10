using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.OpenId4Vp.Tests;

public class ContractSmokeTests
{
    [Fact]
    public void Interfaces_ArePublic()
    {
        Assert.True(typeof(IPresentationRequestBuilder).IsInterface);
        Assert.True(typeof(IPresentationResponseParser).IsInterface);
    }

    [Fact]
    public void IPresentationRequestBuilder_BuildAsync_ReturnsTaskOfPresentationRequest()
    {
        var method = typeof(IPresentationRequestBuilder).GetMethod(nameof(IPresentationRequestBuilder.BuildAsync));
        Assert.NotNull(method);
        Assert.Equal(typeof(Task<PresentationRequest>), method!.ReturnType);
    }

    [Fact]
    public void PresentationRequestOptions_DefaultsToDirectPostJwt()
    {
        var options = new PresentationRequestOptions
        {
            ClientId = "x509_san_dns:verifier.example",
            Nonce = "n-0S6_WzA2Mj",
            DcqlQueryJson = """{"credentials":[]}""",
            ResponseUri = new Uri("https://verifier.example/wallet-callback"),
        };
        Assert.Equal(ResponseMode.DirectPostJwt, options.ResponseMode);
        Assert.Null(options.State);
        Assert.Null(options.RequestLifetime);
        Assert.Null(options.ClientMetadataJson);
        Assert.Null(options.TransactionDataJson);
        Assert.Null(options.VerifierInfoJson);
    }

    [Fact]
    public void PresentationRequestOptions_AcceptsAllOptionalFields()
    {
        var options = new PresentationRequestOptions
        {
            ClientId = "https://verifier.example",
            Nonce = "n-0S6_WzA2Mj",
            DcqlQueryJson = """{"credentials":[]}""",
            ResponseUri = new Uri("https://verifier.example/wallet-callback"),
            ResponseMode = ResponseMode.DirectPost,
            State = "s-abc",
            RequestLifetime = TimeSpan.FromSeconds(90),
            ClientMetadataJson = """{"client_name":"Example Verifier"}""",
            TransactionDataJson = """{"payment_id":"pay_123"}""",
            VerifierInfoJson = """[{"format":"registration_cert","data":"eyJ0eXAiOiJyYy13cnArand0In0.e30.c2ln"}]""",
        };
        Assert.Equal(ResponseMode.DirectPost, options.ResponseMode);
        Assert.Equal(TimeSpan.FromSeconds(90), options.RequestLifetime);
        Assert.NotNull(options.ClientMetadataJson);
        Assert.NotNull(options.VerifierInfoJson);
    }

    [Fact]
    public void PresentationRequest_ByValue_Constructs()
    {
        var request = new PresentationRequest.ByValue
        {
            ClientId = "https://verifier.example",
            Nonce = "n-0S6_WzA2Mj",
            AuthorizationRequestUri = new Uri("openid4vp://?request=eyJ..."),
            SignedRequestObject = "eyJ.signed.req",
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(2),
        };
        Assert.IsType<PresentationRequest.ByValue>(request);
        Assert.IsAssignableFrom<PresentationRequest>(request);
    }

    [Fact]
    public void PresentationRequest_ByReference_CarriesRequestUri()
    {
        var request = new PresentationRequest.ByReference
        {
            ClientId = "https://verifier.example",
            Nonce = "n-0S6_WzA2Mj",
            AuthorizationRequestUri = new Uri("openid4vp://?request_uri=https://verifier.example/req/abc"),
            SignedRequestObject = "eyJ.signed.req",
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(2),
            RequestUri = new Uri("https://verifier.example/req/abc"),
        };
        Assert.Equal("https://verifier.example/req/abc", request.RequestUri.AbsoluteUri);
    }

    [Fact]
    public void PresentationRequest_DiscriminatesByPatternMatching()
    {
        PresentationRequest request = new PresentationRequest.ByValue
        {
            ClientId = "https://verifier.example",
            Nonce = "n",
            AuthorizationRequestUri = new Uri("openid4vp://?request=x"),
            SignedRequestObject = "x",
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(2),
        };

        var label = request switch
        {
            PresentationRequest.ByValue => "by-value",
            PresentationRequest.ByReference => "by-reference",
            _ => "unknown",
        };
        Assert.Equal("by-value", label);
    }

    [Fact]
    public void WalletResponseData_DirectPost_PopulatesFormOnly()
    {
        var response = new WalletResponseData
        {
            ContentType = "application/x-www-form-urlencoded",
            Form = new Dictionary<string, IReadOnlyList<string>>
            {
                ["vp_token"] = new[] { "eyJ..." },
                ["state"] = new[] { "s-abc" },
            },
            Body = ReadOnlyMemory<byte>.Empty,
        };
        Assert.Equal(new[] { "eyJ..." }, response.Form["vp_token"]);
        Assert.True(response.Body.IsEmpty);
    }

    [Fact]
    public void WalletResponseData_DirectPostJwt_PopulatesBodyOnly()
    {
        var response = new WalletResponseData
        {
            ContentType = "application/jwt",
            Form = new Dictionary<string, IReadOnlyList<string>>(),
            Body = new ReadOnlyMemory<byte>([0x65, 0x79, 0x4a]),
        };
        Assert.Empty(response.Form);
        Assert.Equal(3, response.Body.Length);
    }
}
