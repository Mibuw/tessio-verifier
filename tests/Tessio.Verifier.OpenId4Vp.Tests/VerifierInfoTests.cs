using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Core.Mdoc.Tests;

namespace Tessio.Verifier.OpenId4Vp.Tests;

/// <summary>
/// <c>verifier_info</c> (OpenID4VP 1.0 §5.11) on both transports: a verifier that holds a registration
/// certificate must be able to send it, and the wallet checks a signature over the exact bytes it receives,
/// so what arrives has to be what was handed in.
/// </summary>
public sealed class VerifierInfoTests : IDisposable
{
    private const string Dcql =
        """{"credentials":[{"id":"pid","format":"dc+sd-jwt","claims":[{"path":["family_name"]}]}]}""";

    // Shaped like the registration certificate element the EUDI reference implementation emits: format
    // "registration_cert", the attestation a compact JWT in data whose typ header is "rc-wrp+jwt". The value
    // below is not a real certificate and does not verify; these tests are about carriage, not validation.
    private const string RegistrationCertificate =
        "eyJ0eXAiOiJyYy13cnArand0IiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJ2ZXJpZmllci5leGFtcGxlIn0.c2lnbmF0dXJl";

    private const string VerifierInfo =
        $$"""[{"format":"registration_cert","data":"{{RegistrationCertificate}}"}]""";

    private readonly TestReaderCertificates _certificates = new();

    public void Dispose() => _certificates.Dispose();

    private SignedPresentationRequestBuilder Builder() => new(new PresentationRequestBuilderOptions
    {
        SigningCredentials = new SigningCredentials(
            new ECDsaSecurityKey(_certificates.ReaderKey), SecurityAlgorithms.EcdsaSha256),
        SigningCertificateChain = [_certificates.Reader],
    });

    private static PresentationRequestOptions Options() => new()
    {
        ClientId = "x509_san_dns:verifier.example",
        Nonce = "n-0S6_WzA2Mj",
        DcqlQueryJson = Dcql,
        ResponseUri = new Uri("https://verifier.example/wallet-callback"),
    };

    private static JsonObject Payload(string jwt) =>
        JsonNode.Parse(Base64UrlEncoder.DecodeBytes(new JsonWebToken(jwt).EncodedPayload))!.AsObject();

    [Fact]
    public async Task ASignedRequest_CarriesTheAttestationExactlyAsItWasGiven()
    {
        var request = await Builder().BuildAsync(Options() with { VerifierInfoJson = VerifierInfo });

        var verifierInfo = Payload(request.SignedRequestObject)["verifier_info"]!.AsArray();
        var element = Assert.Single(verifierInfo)!.AsObject();
        Assert.Equal("registration_cert", (string?)element["format"]);

        // Byte for byte: the wallet validates the attestation's signature over this string, so a builder that
        // re-encoded it — padding the base64url, say — would produce a request the wallet rejects.
        Assert.Equal(RegistrationCertificate, (string?)element["data"]);
    }

    [Fact]
    public async Task ASignedRequest_OmitsVerifierInfo_WhenTheVerifierHasNone()
    {
        var request = await Builder().BuildAsync(Options());

        // §5.11 makes the parameter optional, and an empty array is not a valid value for it, so the claim has
        // to be absent rather than present and empty.
        Assert.False(Payload(request.SignedRequestObject).ContainsKey("verifier_info"));
    }

    [Fact]
    public async Task ASignedRequest_KeepsSeveralAttestations_InTheOrderGiven()
    {
        var two =
            $$"""[{"format":"registration_cert","data":"{{RegistrationCertificate}}"},{"format":"jwt","data":"second"}]""";

        var request = await Builder().BuildAsync(Options() with { VerifierInfoJson = two });

        var verifierInfo = Payload(request.SignedRequestObject)["verifier_info"]!.AsArray();
        Assert.Equal(2, verifierInfo.Count);
        Assert.Equal(RegistrationCertificate, (string?)verifierInfo[0]!["data"]);
        Assert.Equal("second", (string?)verifierInfo[1]!["data"]);
    }

    [Fact]
    public async Task ASignedRequest_RefusesVerifierInfoThatIsNotJson()
    {
        // The same refusal transaction_data and client_metadata give for the same mistake: these are JSON
        // strings the verifier's own code supplies, and a malformed one is a programming error, not input.
        // JsonReaderException, a JsonException, exactly as a malformed transaction_data gives.
        await Assert.ThrowsAnyAsync<JsonException>(
            () => Builder().BuildAsync(Options() with { VerifierInfoJson = "not json" }));
    }

    [Fact]
    public void ADigitalCredentialsApiRequest_CarriesTheAttestationToo()
    {
        var options = new DcApiPresentationRequestOptions
        {
            Nonce = "n-0S6_WzA2Mj",
            DcqlQueryJson = Dcql,
            ExpectedOrigins = ["https://verifier.example"],
            ClientMetadataJson = ClientMetadata.Build("dc+sd-jwt", null),
            EncryptedResponse = false,
            VerifierInfoJson = VerifierInfo,
        };

        var request = new DcApiPresentationRequestBuilder().Build(options);

        var data = JsonNode.Parse(request.DataJson)!.AsObject();
        var element = Assert.Single(data["verifier_info"]!.AsArray())!.AsObject();
        Assert.Equal(RegistrationCertificate, (string?)element["data"]);
    }

    [Fact]
    public void ASignedDigitalCredentialsApiRequest_CarriesItInsideTheSignedPayload()
    {
        var options = new DcApiPresentationRequestOptions
        {
            Nonce = "n-0S6_WzA2Mj",
            DcqlQueryJson = Dcql,
            ExpectedOrigins = ["https://verifier.example"],
            ClientMetadataJson = ClientMetadata.Build("dc+sd-jwt", null),
            EncryptedResponse = false,
            ClientId = ClientIdentifier.X509Hash(_certificates.Reader),
            VerifierInfoJson = VerifierInfo,
        };

        var builder = new DcApiPresentationRequestBuilder(new PresentationRequestBuilderOptions
        {
            SigningCredentials = new SigningCredentials(
                new ECDsaSecurityKey(_certificates.ReaderKey), SecurityAlgorithms.EcdsaSha256),
            SigningCertificateChain = [_certificates.Reader],
        });

        var signed = JsonNode.Parse(builder.Build(options).DataJson)!.AsObject();

        // SPEC: Appendix A.3.2.1 — the JWS is the data object's request claim, so the parameters, verifier_info
        // among them, are its payload and are covered by the signature.
        var element = Assert.Single(Payload((string)signed["request"]!)["verifier_info"]!.AsArray())!.AsObject();
        Assert.Equal(RegistrationCertificate, (string?)element["data"]);
    }
}
