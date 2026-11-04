using System.Formats.Cbor;
using System.Security.Cryptography;
using Tessio.Verifier.Core;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// An issuerAuth that names its Document Signer certificate by x5u and binds it with x5t, as CIR (EU) 2026/1731
/// Annex I has a PID do: "The Protected Header ... shall contain the x5u and the x5t header parameters, both
/// specified in RFC 9360", with "The digest algorithm used in the x5t header parameter shall be SHA-256."
/// </summary>
public sealed class X5uTests : IDisposable
{
    private const string Url = "https://pid-provider.test/ds.cer";

    private readonly MdocTestBuilder _builder = new() { X5U = Url, X5T = true };
    private readonly RevocationListHttp _http = new();

    private MdocVerifier Verifier(HttpClient? client = null, bool resolveX5u = true) => new(
        new StaticTrustListResolver(
            [_builder.DsCertificate.Subject], source: "mdoc-test", trustAnchors: [_builder.IacaCertificate]),
        options: new MdocVerifierOptions { ResolveX5u = resolveX5u }, clock: null, httpClient: client ?? new HttpClient(_http));

    private Task<VerificationResult> VerifyAsync(MdocVerifier verifier) => verifier.VerifyAsync(
        new PresentedCredential { Format = MdocVerifier.Format, RawValue = _builder.BuildBase64Url() },
        new MdocVerificationContext
        {
            ExpectedDocType = MdocTestBuilder.DefaultDocType,
            ClientId = _builder.ClientId,
            Nonce = _builder.Nonce,
            EncryptionKeyThumbprint = _builder.EncryptionKeyThumbprint,
            ResponseUri = _builder.ResponseUri,
        });

    private static string Errors(VerificationResult result) =>
        string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}"));

    private static byte[] CoseX509Sequence(params byte[][] certificates)
    {
        var writer = new CborWriter(CborConformanceMode.Lax, allowMultipleRootLevelValues: true);
        foreach (var certificate in certificates)
        {
            writer.WriteByteString(certificate);
        }

        return writer.Encode();
    }

    [Fact]
    public async Task ASignerNamedByX5uAndBoundByX5t_Verifies()
    {
        _http.Serve(Url, _builder.DsCertificate.RawData);

        var result = await VerifyAsync(Verifier());

        Assert.True(result.IsValid, Errors(result));
        Assert.Single(_http.Requested);
    }

    [Fact]
    public async Task ByDefault_AnX5u_IsNotFetched_AndTheRefusalSaysWhy()
    {
        // Off unless the host turns it on: the URL is the presented mdoc's choice, and it is fetched before trust is
        // known. The refusal names the option, so an operator meeting such an mdoc can tell what to change.
        _http.Serve(Url, _builder.DsCertificate.RawData);

        var result = await VerifyAsync(Verifier(resolveX5u: false));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.IssuerKeyUnresolvable
            && e.Message.Contains("x5u resolution is off", StringComparison.Ordinal));
        Assert.Empty(_http.Requested);
        Assert.False(new MdocVerifierOptions().ResolveX5u);
    }

    [Fact]
    public async Task ByDefault_AnX5chainBesideAnX5u_StillVerifies()
    {
        _builder.X5ChainBesideX5U = true;

        var result = await VerifyAsync(Verifier(resolveX5u: false));

        Assert.True(result.IsValid, Errors(result));
        Assert.Empty(_http.Requested);
    }

    [Fact]
    public async Task AnX5uServingACoseX509Sequence_Verifies()
    {
        // SPEC: RFC 9360 section 2, application/cose-x509 is "a CBOR sequence of single-entry COSE_X509
        // structures (encoding "bstr")".
        _http.Serve(Url, CoseX509Sequence(_builder.DsCertificate.RawData, _builder.IacaCertificate.RawData));

        var result = await VerifyAsync(Verifier());

        Assert.True(result.IsValid, Errors(result));
    }

    [Theory]
    [InlineData(System.Security.Cryptography.X509Certificates.X509ContentType.Pkcs7)]
    [InlineData(System.Security.Cryptography.X509Certificates.X509ContentType.Pkcs12)]
    public async Task AnX5uServingACertificateBundle_IsRefused_OnEveryFramework(
        System.Security.Cryptography.X509Certificates.X509ContentType type)
    {
        // Not read: the body must be exactly one DER certificate or a COSE_X509 sequence, whatever the platform's
        // certificate loader would also accept.
        var bundle = new System.Security.Cryptography.X509Certificates.X509Certificate2Collection(_builder.DsCertificate)
            .Export(type)!;
        _http.Serve(Url, bundle);

        var result = await VerifyAsync(Verifier());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.IssuerKeyUnresolvable);
    }

    [Fact]
    public async Task ACertificateNotMatchingTheX5t_IsRefused()
    {
        _builder.X5THash = SHA256.HashData(_builder.IacaCertificate.RawData);
        _http.Serve(Url, _builder.DsCertificate.RawData);

        var result = await VerifyAsync(Verifier());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.IssuerKeyUnresolvable && e.Message.Contains("x5t", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnX5uWithoutAnX5t_IsRefused_WithoutAFetch()
    {
        // SPEC: RFC 9360 section 2, for x5u "The end-entity certificate MUST be integrity protected by COSE".
        _builder.X5T = false;
        _http.Serve(Url, _builder.DsCertificate.RawData);

        var result = await VerifyAsync(Verifier());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.IssuerKeyUnresolvable);
        Assert.Empty(_http.Requested);
    }

    [Fact]
    public async Task AnX5tOnlyInTheUnprotectedHeader_DoesNotBindAnX5u()
    {
        _builder.X5TUnprotected = true;
        _http.Serve(Url, _builder.DsCertificate.RawData);

        var result = await VerifyAsync(Verifier());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.IssuerKeyUnresolvable);
        Assert.Empty(_http.Requested);
    }

    [Fact]
    public async Task AnX5tNotUsingSha256_IsRefused()
    {
        _builder.X5TAlgorithm = -43; // SHA-384
        _builder.X5THash = SHA384.HashData(_builder.DsCertificate.RawData);
        _http.Serve(Url, _builder.DsCertificate.RawData);

        var result = await VerifyAsync(Verifier());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.MsoInvalid && e.Message.Contains("the only digest accepted", StringComparison.Ordinal));
        Assert.Empty(_http.Requested);
    }

    [Fact]
    public async Task AnX5uThatIsNotHttps_IsRefused_WithoutAFetch()
    {
        _builder.X5U = "http://pid-provider.test/ds.cer";

        var result = await VerifyAsync(Verifier());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.IssuerKeyUnresolvable && e.Message.Contains("HTTPS", StringComparison.Ordinal));
        Assert.Empty(_http.Requested);
    }

    [Fact]
    public async Task AnX5uOnlyInTheUnprotectedHeader_IsRefused_WithoutAFetch()
    {
        // Unsigned, so anyone holding the issuerAuth could point it elsewhere. CIR 2026/1731 Annex I puts it in the
        // protected header.
        _builder.X5UUnprotected = true;
        _http.Serve(Url, _builder.DsCertificate.RawData);

        var result = await VerifyAsync(Verifier());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.IssuerKeyUnresolvable
            && e.Message.Contains("not in the protected header", StringComparison.Ordinal));
        Assert.Empty(_http.Requested);
    }

    [Fact]
    public async Task AnOtherwiseInvalidPresentation_DoesNotKeepItsResource()
    {
        // Trusted and signed, but answering another request: not a verified credential, so nothing is kept.
        _http.Serve(Url, _builder.DsCertificate.RawData);
        var verifier = Verifier();

        async Task<VerificationResult> WrongNonce() => await verifier.VerifyAsync(
            new PresentedCredential { Format = MdocVerifier.Format, RawValue = _builder.BuildBase64Url() },
            new MdocVerificationContext
            {
                ExpectedDocType = MdocTestBuilder.DefaultDocType,
                ClientId = _builder.ClientId,
                Nonce = "another nonce",
                EncryptionKeyThumbprint = _builder.EncryptionKeyThumbprint,
                ResponseUri = _builder.ResponseUri,
            });

        Assert.False((await WrongNonce()).IsValid);
        Assert.False((await WrongNonce()).IsValid);
        Assert.Equal(2, _http.Requested.Count);
    }

    [Fact]
    public async Task AnUntrustedDocumentSigner_IsNotKept()
    {
        // The presenter chooses both the URL and the x5t, so a match proves nothing until the chain is trusted.
        _http.Serve(Url, _builder.DsCertificate.RawData);
        var verifier = new MdocVerifier(
            new StaticTrustListResolver(["CN=Someone Else"], source: "mdoc-test"),
            options: new MdocVerifierOptions { ResolveX5u = true }, clock: null, httpClient: new HttpClient(_http));

        var first = await VerifyAsync(verifier);
        var second = await VerifyAsync(verifier);

        Assert.False(first.IsValid);
        Assert.False(second.IsValid);
        Assert.Equal(2, _http.Requested.Count);
    }

    [Fact]
    public async Task AnX5uOnAnInternalAddress_IsRefused_BeforeConnecting()
    {
        // The default client refuses an address outside the public internet before it connects.
        _builder.X5U = "https://127.0.0.1:9/ds.cer";

        var result = await VerifyAsync(new MdocVerifier(
            new StaticTrustListResolver(
                [_builder.DsCertificate.Subject], source: "mdoc-test", trustAnchors: [_builder.IacaCertificate]),
            new MdocVerifierOptions { ResolveX5u = true }));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.IssuerKeyUnresolvable
            && e.Message.Contains("outside the public internet", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnX5uThatAnswersNotFound_IsRefused()
    {
        var result = await VerifyAsync(Verifier());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.IssuerKeyUnresolvable);
        Assert.Single(_http.Requested);
    }

    [Fact]
    public async Task AnX5chainBesideTheX5u_IsUsed_WithoutAFetch()
    {
        _builder.X5ChainBesideX5U = true;

        var result = await VerifyAsync(Verifier());

        Assert.True(result.IsValid, Errors(result));
        Assert.Empty(_http.Requested);
    }

    [Fact]
    public async Task AnX5chainThatDisagreesWithTheX5t_IsRefused()
    {
        // When both are present they must agree: x5t names the end-entity certificate, whichever header carries it.
        _builder.X5ChainBesideX5U = true;
        _builder.X5THash = SHA256.HashData(_builder.IacaCertificate.RawData);

        var result = await VerifyAsync(Verifier());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.IssuerKeyUnresolvable && e.Message.Contains("x5t", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AFetchedCertificate_IsReused_ForTheNextPresentation()
    {
        _http.Serve(Url, _builder.DsCertificate.RawData);
        var verifier = Verifier();

        var first = await VerifyAsync(verifier);
        var second = await VerifyAsync(verifier);

        Assert.True(first.IsValid, Errors(first));
        Assert.True(second.IsValid, Errors(second));
        Assert.Single(_http.Requested);
    }

    [Fact]
    public async Task ACertificateNotMatchingTheX5t_IsNotKept()
    {
        // The URL is the presenter's choice and the fetch comes before any check, so only a match is cached.
        _builder.X5THash = SHA256.HashData(_builder.IacaCertificate.RawData);
        _http.Serve(Url, _builder.DsCertificate.RawData);
        var verifier = Verifier();

        var first = await VerifyAsync(verifier);
        var second = await VerifyAsync(verifier);

        Assert.False(first.IsValid);
        Assert.False(second.IsValid);
        Assert.Equal(2, _http.Requested.Count);
    }

    public void Dispose()
    {
        _builder.Dispose();
        _http.Dispose();
    }
}
