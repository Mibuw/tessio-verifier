using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.Core.Tests;

/// <summary>
/// An SD-JWT VC that names its signing certificate by x5u and binds it with x5t#S256, as CIR (EU) 2026/1731 Annex
/// I has a PID do: "The Protected Header of the digital signature signing a person identification data in SD-JWT
/// VC format shall contain the x5u and the x5t#S256 header parameters, specified in RFC 7515."
/// </summary>
public sealed class X5uTests : IDisposable
{
    private const string Url = "https://pid-provider.test/signer.pem";

    private readonly TestCredentialBuilder _builder = new();
    private readonly FakeHttpHandler _http = new();
    private readonly X509Certificate2 _certificate;

    public X5uTests() => _certificate = _builder.UseCertificate();

    private static VerificationContext Context() => new()
    {
        Nonce = TestCredentialBuilder.DefaultNonce,
        Audience = TestCredentialBuilder.DefaultAudience,
    };

    private static string Errors(VerificationResult result) =>
        string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}"));

    private static string Pem(X509Certificate2 certificate) => certificate.ExportCertificatePem();

    // Replaces the x5c header the builder writes with the given x5u and x5t#S256, either of which may be left out.
    private void Header(string? x5u, byte[]? thumbprint, bool keepX5c = false) =>
        _builder.RewriteHeaderJson = json =>
        {
            var header = JsonNode.Parse(json)!.AsObject();
            if (!keepX5c)
            {
                header.Remove("x5c");
            }

            if (x5u is not null)
            {
                header["x5u"] = x5u;
            }

            if (thumbprint is not null)
            {
                header["x5t#S256"] = Base64UrlEncoder.Encode(thumbprint);
            }

            return header.ToJsonString();
        };

    private byte[] OwnThumbprint => SHA256.HashData(_certificate.RawData);

    private static SdJwtVcVerifierOptions On => new() { ResolveX5u = true };

    private Task<VerificationResult> VerifyAsync(FakeTrustListResolver? trust = null, HttpClient? client = null, bool resolveX5u = true) =>
        new SdJwtVcVerifier(
                trust ?? new FakeTrustListResolver(), new SdJwtVcVerifierOptions { ResolveX5u = resolveX5u },
                httpClient: client ?? new HttpClient(_http))
            .VerifyAsync(new PresentedCredential { Format = "dc+sd-jwt", RawValue = _builder.Build() }, Context());

    [Fact]
    public async Task ASignerNamedByX5uAndBoundByX5tS256_Verifies()
    {
        Header(Url, OwnThumbprint);
        _http.MapBytes(Url, System.Text.Encoding.ASCII.GetBytes(Pem(_certificate)));
        var trust = new FakeTrustListResolver();

        var result = await VerifyAsync(trust);

        Assert.True(result.IsValid, Errors(result));
        Assert.Equal("x5c", result.Issuer.KeyResolutionMethod);
        Assert.Equal(1, trust.SeenChainLength);
        Assert.Single(_http.Requested);
    }

    [Fact]
    public async Task ByDefault_AnX5u_IsNotFetched_AndTheRefusalSaysWhy()
    {
        // With no iss the x5u is the only way to a key, so the refusal names the option.
        _builder.Issuer = "";
        Header(Url, OwnThumbprint);
        _http.MapBytes(Url, System.Text.Encoding.ASCII.GetBytes(Pem(_certificate)));

        var result = await VerifyAsync(resolveX5u: false);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.IssuerKeyUnresolvable
            && e.Message.Contains("x5u resolution is off", StringComparison.Ordinal));
        Assert.Empty(_http.Requested);
        Assert.False(new SdJwtVcVerifierOptions().ResolveX5u);
    }

    [Fact]
    public async Task ByDefault_AnX5uBesideAnIss_ResolvesByMetadata_AsBefore()
    {
        // Off means the x5u is ignored, as it was before it was read at all: a credential that also names an HTTPS
        // iss still resolves its key through JWT VC Issuer Metadata.
        Header(Url, OwnThumbprint);
        _http.Map("https://issuer.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"{{_builder.Issuer}}","jwks":{{_builder.BuildJwksJson()}}}""");
        _http.MapBytes(Url, System.Text.Encoding.ASCII.GetBytes(Pem(_certificate)));

        var result = await VerifyAsync(resolveX5u: false);

        Assert.True(result.IsValid, Errors(result));
        Assert.Equal("jwt-vc-issuer-metadata", result.Issuer.KeyResolutionMethod);
        Assert.DoesNotContain(Url, _http.Requested);
    }

    [Theory]
    [InlineData("x5c")]
    [InlineData("X5C")]
    public async Task AnIssuerKeyJudgedByItsX5cRatherThanItsKeyMembers_DoesNotVerify(string certificateMember)
    {
        // SPEC: RFC 7517 §4.7, the x5c key "MUST match the public key represented by other members of the JWK".
        // The metadata's RSA key names another key in n and e and carries the signer's certificate. The key set's
        // keys are their key members, so the signature does not verify, however the member's name is cased. RSA,
        // because a key set also yields a key built from an RSA key's certificate; an EC key is built from x and y
        // alone.
        Header(x5u: null, thumbprint: null);
        using var signer = RSA.Create(2048);
        using var other = RSA.Create(2048);
        _builder.IssuerRsa = signer;
        using var signerCertificate = new CertificateRequest("CN=Test Issuer", signer, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
        var key = other.ExportParameters(false);
        var jwks = $$"""{"keys":[{"kty":"RSA","n":"{{Base64UrlEncoder.Encode(key.Modulus!)}}","e":"{{Base64UrlEncoder.Encode(key.Exponent!)}}","{{certificateMember}}":["{{Convert.ToBase64String(signerCertificate.RawData)}}"]}]}""";
        _http.Map("https://issuer.example/.well-known/jwt-vc-issuer", $$"""{"issuer":"{{_builder.Issuer}}","jwks":{{jwks}}}""");

        var result = await VerifyAsync(resolveX5u: false);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.SignatureInvalid);
    }

    [Fact]
    public async Task AnIssuerKeyWithACertificateButNoKeyMembers_IsNoSigningKey()
    {
        // SPEC: RFC 7518 §6.3.1, an RSA public key's n and e "MUST be present". A key that carries only the signer's
        // certificate has no key members, so the set holds no signing key.
        Header(x5u: null, thumbprint: null);
        using var signer = RSA.Create(2048);
        _builder.IssuerRsa = signer;
        using var signerCertificate = new CertificateRequest("CN=Test Issuer", signer, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
        var jwks = $$"""{"keys":[{"kty":"RSA","x5c":["{{Convert.ToBase64String(signerCertificate.RawData)}}"]}]}""";
        _http.Map("https://issuer.example/.well-known/jwt-vc-issuer", $$"""{"issuer":"{{_builder.Issuer}}","jwks":{{jwks}}}""");

        var result = await VerifyAsync(resolveX5u: false);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.IssuerMetadataInvalid);
    }

    [Fact]
    public async Task AnIssuerKeyThatIsNoSigningKey_IsLeftOut_WhateverTheProcessWideDefault()
    {
        // The process-wide default would hand an unresolved JWK on as a key; the metadata's key set never does.
        Header(x5u: null, thumbprint: null);
        using var signer = RSA.Create(2048);
        _builder.IssuerRsa = signer;
        var key = signer.ExportParameters(false);
        var jwks = $$"""{"keys":[{"kty":"RSA","use":"enc","n":"{{Base64UrlEncoder.Encode(key.Modulus!)}}","e":"{{Base64UrlEncoder.Encode(key.Exponent!)}}"}]}""";
        _http.Map("https://issuer.example/.well-known/jwt-vc-issuer", $$"""{"issuer":"{{_builder.Issuer}}","jwks":{{jwks}}}""");

        var before = JsonWebKeySet.DefaultSkipUnresolvedJsonWebKeys;
        JsonWebKeySet.DefaultSkipUnresolvedJsonWebKeys = false;
        try
        {
            var result = await VerifyAsync(resolveX5u: false);

            Assert.False(result.IsValid);
            Assert.Contains(result.Errors, e => e.Code == ErrorCodes.IssuerMetadataInvalid);
        }
        finally
        {
            JsonWebKeySet.DefaultSkipUnresolvedJsonWebKeys = before;
        }
    }

    [Theory]
    [InlineData("\"not a key set\"")]
    [InlineData("[]")]
    public async Task IssuerMetadataWhoseJwksIsNotAKeySet_IsRefused_NotThrown(string jwks)
    {
        Header(x5u: null, thumbprint: null);
        _http.Map("https://issuer.example/.well-known/jwt-vc-issuer", $$"""{"issuer":"{{_builder.Issuer}}","jwks":{{jwks}}}""");

        var result = await VerifyAsync(resolveX5u: false);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.IssuerMetadataInvalid);
    }

    [Fact]
    public async Task ByDefault_AnX5uThatIsNotAString_IsIgnored()
    {
        // Off, the x5u is never read, so a malformed one does not refuse a credential that verified before.
        _builder.RewriteHeaderJson = json =>
        {
            var header = JsonNode.Parse(json)!.AsObject();
            header.Remove("x5c");
            header["x5u"] = 7;
            return header.ToJsonString();
        };
        _http.Map("https://issuer.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"{{_builder.Issuer}}","jwks":{{_builder.BuildJwksJson()}}}""");

        var result = await VerifyAsync(resolveX5u: false);

        Assert.True(result.IsValid, Errors(result));
        Assert.Equal("jwt-vc-issuer-metadata", result.Issuer.KeyResolutionMethod);
    }

    [Fact]
    public async Task AnX5uWithoutAThumbprint_AndNoIss_IsRefused_WithoutAFetch()
    {
        _builder.Issuer = "";
        Header(Url, thumbprint: null);
        _http.MapBytes(Url, System.Text.Encoding.ASCII.GetBytes(Pem(_certificate)));

        var result = await VerifyAsync();

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.IssuerKeyUnresolvable && e.Message.Contains("not bound by an x5t#S256", StringComparison.Ordinal));
        Assert.Empty(_http.Requested);
    }

    [Fact]
    public async Task AnX5uWithoutAThumbprint_BesideAnIss_IsIgnored_AndResolvesByMetadata()
    {
        Header(Url, thumbprint: null);
        _http.Map("https://issuer.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"{{_builder.Issuer}}","jwks":{{_builder.BuildJwksJson()}}}""");
        _http.MapBytes(Url, System.Text.Encoding.ASCII.GetBytes(Pem(_certificate)));

        var result = await VerifyAsync();

        Assert.True(result.IsValid, Errors(result));
        Assert.Equal("jwt-vc-issuer-metadata", result.Issuer.KeyResolutionMethod);
        Assert.DoesNotContain(Url, _http.Requested);
    }

    [Fact]
    public async Task ACertificateNotMatchingTheThumbprint_IsRefused()
    {
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var stranger = new CertificateRequest("CN=Someone Else", other, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
        Header(Url, SHA256.HashData(stranger.RawData));
        _http.MapBytes(Url, System.Text.Encoding.ASCII.GetBytes(Pem(_certificate)));

        var result = await VerifyAsync();

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.IssuerKeyUnresolvable && e.Message.Contains("x5t#S256", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnX5cThatDisagreesWithTheThumbprint_IsRefused()
    {
        // When both are present they must agree: x5t#S256 names the signing certificate, whichever header carries it.
        Header(x5u: null, thumbprint: new byte[32], keepX5c: true);

        var result = await VerifyAsync();

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.IssuerKeyUnresolvable && e.Message.Contains("x5t#S256", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnX5cWithItsOwnThumbprint_Verifies()
    {
        Header(x5u: null, OwnThumbprint, keepX5c: true);

        var result = await VerifyAsync();

        Assert.True(result.IsValid, Errors(result));
        Assert.Empty(_http.Requested);
    }

    [Fact]
    public async Task AnX5uThatIsNotHttps_IsRefused_WithoutAFetch()
    {
        Header("http://pid-provider.test/signer.pem", OwnThumbprint);

        var result = await VerifyAsync();

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.IssuerKeyUnresolvable && e.Message.Contains("HTTPS", StringComparison.Ordinal));
        Assert.Empty(_http.Requested);
    }

    [Fact]
    public async Task AnX5uServingSomethingOtherThanPem_IsRefused()
    {
        // RFC 7515 section 4.1.5: the resource is "in PEM-encoded form". A bare DER certificate is not.
        Header(Url, OwnThumbprint);
        _http.MapBytes(Url, _certificate.RawData);

        var result = await VerifyAsync();

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.IssuerKeyUnresolvable && e.Message.Contains("PEM", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnX5uCertificateBlockHoldingABundleAroundTheSigner_IsRefused()
    {
        // A CERTIFICATE block holds one DER certificate, read by the same loader as an x5c entry. The signer wrapped
        // in a PKCS#12 would match the thumbprint if the bundle were read as the certificate inside it.
        Header(Url, OwnThumbprint);
        var bundle = new X509Certificate2Collection(_certificate).Export(X509ContentType.Pkcs12)!;
        _http.MapBytes(Url, System.Text.Encoding.ASCII.GetBytes(PemEncoding.WriteString("CERTIFICATE", bundle)));

        var result = await VerifyAsync();

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.IssuerKeyUnresolvable && e.Message.Contains("PEM", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnX5uResourceWithAnotherBlockBeforeTheCertificate_StillVerifies()
    {
        // Only CERTIFICATE blocks are read, in order; anything else in the file is skipped.
        Header(Url, OwnThumbprint);
        var other = PemEncoding.WriteString("PUBLIC KEY", _certificate.PublicKey.ExportSubjectPublicKeyInfo());
        _http.MapBytes(Url, System.Text.Encoding.ASCII.GetBytes(other + "\n" + Pem(_certificate)));

        var result = await VerifyAsync();

        Assert.True(result.IsValid, Errors(result));
    }

    [Fact]
    public async Task AnX5uOnAnInternalAddress_IsRefused_BeforeConnecting()
    {
        Header("https://127.0.0.1:9/signer.pem", OwnThumbprint);

        var result = await new SdJwtVcVerifier(new FakeTrustListResolver(), On)
            .VerifyAsync(new PresentedCredential { Format = "dc+sd-jwt", RawValue = _builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.IssuerKeyUnresolvable
            && e.Message.Contains("outside the public internet", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AFetchedCertificate_IsReused_ForTheNextPresentation()
    {
        Header(Url, OwnThumbprint);
        _http.MapBytes(Url, System.Text.Encoding.ASCII.GetBytes(Pem(_certificate)));
        var verifier = new SdJwtVcVerifier(new FakeTrustListResolver(), On, httpClient: new HttpClient(_http));

        var first = await verifier.VerifyAsync(new PresentedCredential { Format = "dc+sd-jwt", RawValue = _builder.Build() }, Context());
        var second = await verifier.VerifyAsync(new PresentedCredential { Format = "dc+sd-jwt", RawValue = _builder.Build() }, Context());

        Assert.True(first.IsValid, Errors(first));
        Assert.True(second.IsValid, Errors(second));
        Assert.Single(_http.Requested);
    }

    [Fact]
    public async Task AnUntrustedCredentialsCertificate_IsNotKept()
    {
        // The presenter chooses both the URL and the thumbprint, so a match proves nothing until the chain is
        // trusted. Keeping it earlier would let anyone fill the cache.
        Header(Url, OwnThumbprint);
        _http.MapBytes(Url, System.Text.Encoding.ASCII.GetBytes(Pem(_certificate)));
        var verifier = new SdJwtVcVerifier(new FakeTrustListResolver(trusted: false), On, httpClient: new HttpClient(_http));

        var first = await verifier.VerifyAsync(new PresentedCredential { Format = "dc+sd-jwt", RawValue = _builder.Build() }, Context());
        var second = await verifier.VerifyAsync(new PresentedCredential { Format = "dc+sd-jwt", RawValue = _builder.Build() }, Context());

        Assert.False(first.IsValid);
        Assert.False(second.IsValid);
        Assert.Equal(2, _http.Requested.Count(u => u == Url));
    }

    [Fact]
    public async Task AnOtherwiseInvalidPresentation_DoesNotKeepItsResource()
    {
        // Trusted and signed, but answering another request: not a verified credential, so nothing is kept.
        Header(Url, OwnThumbprint);
        _http.MapBytes(Url, System.Text.Encoding.ASCII.GetBytes(Pem(_certificate)));
        var verifier = new SdJwtVcVerifier(new FakeTrustListResolver(), On, httpClient: new HttpClient(_http));
        var wrongNonce = new VerificationContext { Nonce = "another nonce", Audience = TestCredentialBuilder.DefaultAudience };

        var first = await verifier.VerifyAsync(new PresentedCredential { Format = "dc+sd-jwt", RawValue = _builder.Build() }, wrongNonce);
        var second = await verifier.VerifyAsync(new PresentedCredential { Format = "dc+sd-jwt", RawValue = _builder.Build() }, wrongNonce);

        Assert.False(first.IsValid);
        Assert.False(second.IsValid);
        Assert.Equal(2, _http.Requested.Count(u => u == Url));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AMalformedThumbprint_OnTheMetadataRoute_IsIgnored_AsBefore(bool resolveX5u)
    {
        // x5t#S256 is read only on the routes that use it: x5c, and x5u with resolution on.
        _builder.RewriteHeaderJson = json =>
        {
            var header = JsonNode.Parse(json)!.AsObject();
            header.Remove("x5c");
            header["x5t#S256"] = "!!!";
            return header.ToJsonString();
        };
        _http.Map("https://issuer.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"{{_builder.Issuer}}","jwks":{{_builder.BuildJwksJson()}}}""");

        var result = await VerifyAsync(resolveX5u: resolveX5u);

        Assert.True(result.IsValid, Errors(result));
        Assert.Equal("jwt-vc-issuer-metadata", result.Issuer.KeyResolutionMethod);
    }

    [Fact]
    public async Task ACertificateNotMatchingTheThumbprint_IsNotKept()
    {
        // The URL is the presenter's choice and the fetch comes before any check, so only a match is cached.
        Header(Url, new byte[32]);
        _http.MapBytes(Url, System.Text.Encoding.ASCII.GetBytes(Pem(_certificate)));
        var verifier = new SdJwtVcVerifier(new FakeTrustListResolver(), On, httpClient: new HttpClient(_http));

        var first = await verifier.VerifyAsync(new PresentedCredential { Format = "dc+sd-jwt", RawValue = _builder.Build() }, Context());
        var second = await verifier.VerifyAsync(new PresentedCredential { Format = "dc+sd-jwt", RawValue = _builder.Build() }, Context());

        Assert.False(first.IsValid);
        Assert.False(second.IsValid);
        Assert.Equal(2, _http.Requested.Count(u => u == Url));
    }

    public void Dispose()
    {
        _builder.Dispose();
        _http.Dispose();
    }
}
