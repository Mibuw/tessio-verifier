using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Tests;

/// <summary>
/// End-to-end verifier tests over real signed credentials: happy paths for both key-resolution
/// mechanisms plus the negative catalogue (tampering, replay, trust, policy).
/// </summary>
public class SdJwtVcVerifierTests
{
    private static VerificationContext Context(
        string? expectedVct = null,
        IReadOnlyList<string>? expectedVctValues = null) => new()
    {
        Nonce = TestCredentialBuilder.DefaultNonce,
        Audience = TestCredentialBuilder.DefaultAudience,
        ExpectedVct = expectedVct,
        ExpectedVctValues = expectedVctValues,
    };

    private static PresentedCredential Credential(string raw, string format = "dc+sd-jwt") =>
        new() { Format = format, RawValue = raw };

    private static SdJwtVcVerifier MetadataVerifier(
        TestCredentialBuilder builder,
        ITrustListResolver? trust = null,
        SdJwtVcVerifierOptions? options = null)
    {
        var http = new FakeHttpHandler().Map(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""");
        return new SdJwtVcVerifier(trust ?? new FakeTrustListResolver(), options, new HttpClient(http));
    }

    // ---- Happy paths --------------------------------------------------------------------------

    [Fact]
    public async Task ValidCredential_MetadataResolution_Verifies()
    {
        using var builder = new TestCredentialBuilder();
        builder.PlainClaims["issuing_country"] = "DE";
        var trust = new FakeTrustListResolver();

        var result = await MetadataVerifier(builder, trust).VerifyAsync(Credential(builder.Build()), Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
        Assert.Empty(result.Errors);
        Assert.Equal("Möbius", result.DisclosedClaims["family_name"]);
        Assert.Equal(true, result.DisclosedClaims["age_over_18"]);
        Assert.Equal("DE", result.DisclosedClaims["issuing_country"]);
        Assert.True(result.Issuer.Trusted);
        Assert.Equal("jwt-vc-issuer-metadata", result.Issuer.KeyResolutionMethod);
        Assert.Equal(TestCredentialBuilder.DefaultIssuer, trust.SeenIssuer);
        Assert.Equal(0, trust.SeenChainLength);
    }

    public static TheoryData<string> MetadataRepeats => ["issuer", "jwks"];

    [Theory]
    [MemberData(nameof(MetadataRepeats))]
    public async Task IssuerMetadataNamingAMemberTwice_IsRefused(string member)
    {
        // Unsigned, from a host the credential names, and held to the rules signed JSON is: RFC 8259 §4 leaves a
        // repeated name to the parser, so metadata carrying two issuers or two key sets has no single answer.
        using var builder = new TestCredentialBuilder();
        var jwks = builder.BuildJwksJson();
        var metadata = member == "issuer"
            ? $$"""{"issuer":"https://other.example","issuer":"{{builder.Issuer}}","jwks":{{jwks}}}"""
            : $$"""{"issuer":"{{builder.Issuer}}","jwks":{"keys":[]},"jwks":{{jwks}}}""";
        var http = new FakeHttpHandler().Map("https://issuer.example/.well-known/jwt-vc-issuer", metadata);

        var result = await new SdJwtVcVerifier(new FakeTrustListResolver(), httpClient: new HttpClient(http))
            .VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.IssuerKeyUnresolvable
                                            && e.Message.Contains("repeats a property name", StringComparison.Ordinal));
    }

    /// <summary>
    /// The trust provenance the resolver returns has to REACH the caller, on both verdicts.
    /// </summary>
    /// <remarks>
    /// The resolver's own tests prove it computes these; they say nothing about whether this verifier
    /// copies them into <c>IssuerInfo</c>. Deleting the three assignments in <c>SdJwtVcVerifier</c> leaves
    /// every other test in this file green, which is the shape of defect this file exists to catch.
    /// </remarks>
    [Fact]
    public async Task IssuerInfo_CarriesTheTrustProvenance_OnSuccessAndOnFailure()
    {
        using var builder = new TestCredentialBuilder();
        builder.UseCertificate();
        var trust = new FakeTrustListResolver { Anchor = ("CN=Test Root, C=EU", "ABCD1234") };

        var ok = await new SdJwtVcVerifier(trust).VerifyAsync(Credential(builder.Build()), Context());

        Assert.True(ok.IsValid, string.Join("; ", ok.Errors.Select(e => e.Code)));
        Assert.Equal("fake://trust-list", ok.Issuer.TrustListSource);
        Assert.Equal("CN=Test Root, C=EU", ok.Issuer.TrustAnchorSubject);
        Assert.Equal("ABCD1234", ok.Issuer.TrustAnchorThumbprint);

        // A refusal names the list and no anchor. This is the verdict a relying party comes back to
        // question, and an implementation carrying provenance only on the passing branch would satisfy
        // the assertions above and fail these.
        using var refusedBuilder = new TestCredentialBuilder();
        refusedBuilder.UseCertificate();
        var refusing = new FakeTrustListResolver(trusted: false);

        var refused = await new SdJwtVcVerifier(refusing)
            .VerifyAsync(Credential(refusedBuilder.Build()), Context());

        Assert.False(refused.IsValid);
        Assert.Equal("fake://trust-list", refused.Issuer.TrustListSource);
        Assert.Null(refused.Issuer.TrustAnchorSubject);
        Assert.Null(refused.Issuer.TrustAnchorThumbprint);
    }

    [Fact]
    public async Task ValidCredential_X5cResolution_Verifies_AndHandsChainToTrustSeam()
    {
        using var builder = new TestCredentialBuilder();
        builder.UseCertificate();
        var trust = new FakeTrustListResolver();

        var result = await new SdJwtVcVerifier(trust).VerifyAsync(Credential(builder.Build()), Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
        Assert.Equal("x5c", result.Issuer.KeyResolutionMethod);
        Assert.Equal(1, trust.SeenChainLength);
    }

    [Fact]
    public async Task WithheldClaim_IsAbsent_DisclosedClaimIsPresent()
    {
        using var builder = new TestCredentialBuilder();
        builder.Withhold.Add("family_name");
        builder.DecoyDigests = 2;

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(builder.Build()), Context());

        Assert.True(result.IsValid);
        Assert.False(result.DisclosedClaims.ContainsKey("family_name"));
        Assert.Equal(true, result.DisclosedClaims["age_over_18"]);
    }

    [Fact]
    public async Task NoKeyBinding_Allowed_WhenNotRequired()
    {
        using var builder = new TestCredentialBuilder { IncludeKbJwt = false, IncludeCnf = false };
        var options = new SdJwtVcVerifierOptions { RequireKeyBinding = false };

        var result = await MetadataVerifier(builder, options: options)
            .VerifyAsync(Credential(builder.Build()), Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
    }

    [Fact]
    public async Task LegacyTyp_Accepted_OnlyWithCompatibilityFlag()
    {
        using var builder = new TestCredentialBuilder { Typ = "vc+sd-jwt" };
        var raw = builder.Build();

        var strict = await MetadataVerifier(builder).VerifyAsync(Credential(raw), Context());
        Assert.False(strict.IsValid);
        Assert.Equal("typ_invalid", strict.Errors.Single().Code);

        var compat = await MetadataVerifier(builder, options: new SdJwtVcVerifierOptions { AcceptLegacyVcSdJwtTyp = true })
            .VerifyAsync(Credential(raw, format: "vc+sd-jwt"), Context());
        Assert.True(compat.IsValid, string.Join("; ", compat.Errors.Select(e => e.Code)));
    }

    [Fact]
    public async Task ExpectedVct_Match_Passes()
    {
        using var builder = new TestCredentialBuilder();

        var result = await MetadataVerifier(builder)
            .VerifyAsync(Credential(builder.Build()), Context(expectedVct: TestCredentialBuilder.DefaultVct));

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task ExpectedVctValues_Passes_WhenTheCredentialTypeIsNotTheFirstEntry()
    {
        // SPEC: OpenID4VP 1.0 §B.3.5 states vct_values as the "allowed values for the type of the
        // requested Verifiable Credential", and the Wallet MAY answer with "any of the specified
        // types". The credential's own type sits SECOND here on purpose: the check this replaces
        // compared the first entry only, so a first-entry test would pass against the defect too.
        using var builder = new TestCredentialBuilder();

        var result = await MetadataVerifier(builder).VerifyAsync(
            Credential(builder.Build()),
            Context(expectedVctValues: new[] { "https://credentials.example/other", TestCredentialBuilder.DefaultVct }));

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
    }

    [Fact]
    public async Task ExpectedVctValues_Fails_WhenTheCredentialTypeIsInNoEntry()
    {
        using var builder = new TestCredentialBuilder();

        var result = await MetadataVerifier(builder).VerifyAsync(
            Credential(builder.Build()),
            Context(expectedVctValues: new[] { "https://credentials.example/other", "https://credentials.example/third" }));

        Assert.False(result.IsValid);

        // The message names every type that would have been accepted. Naming one of several is what
        // sends the holder looking for a fault in the credential they were actually asked for.
        var error = Assert.Single(result.Errors, e => e.Code == "vct_mismatch");
        Assert.Contains("https://credentials.example/other", error.Message, StringComparison.Ordinal);
        Assert.Contains("https://credentials.example/third", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExpectedVct_And_ExpectedVctValues_AreReadTogether()
    {
        // VerificationContext is a frozen contract, so ExpectedVct could not be widened in place and
        // ExpectedVctValues was added beside it. A caller that sets both accepts the union, and this
        // pins that rule so the two properties cannot drift into a precedence order nobody documented.
        using var builder = new TestCredentialBuilder();

        var result = await MetadataVerifier(builder).VerifyAsync(
            Credential(builder.Build()),
            Context(
                expectedVct: TestCredentialBuilder.DefaultVct,
                expectedVctValues: new[] { "https://credentials.example/other" }));

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
    }

    [Fact]
    public async Task OneExpectedVct_KeepsTheMismatchMessageItAlwaysHad()
    {
        // A set renders as "one of 'a', 'b'". A single expected type must still read "expects 'a'".
        // Error CODES are the contract and messages are not, so this does not promise stability to
        // consumers. It pins the wording because this sentence is what an operator reads when a
        // refusal has to be explained, and adding the set must not reword the single-type case.
        using var builder = new TestCredentialBuilder();

        var result = await MetadataVerifier(builder)
            .VerifyAsync(Credential(builder.Build()), Context(expectedVct: "https://credentials.example/other"));

        Assert.Equal(
            $"The credential type is '{TestCredentialBuilder.DefaultVct}'; "
                + "this verification expects 'https://credentials.example/other'.",
            Assert.Single(result.Errors, e => e.Code == "vct_mismatch").Message);
    }

    // ---- Tampering & replay -------------------------------------------------------------------

    [Fact]
    public async Task TamperedSignature_FailsSignature()
    {
        using var builder = new TestCredentialBuilder();
        var raw = builder.Build();

        var tampered = TamperIssuerSignature(raw);

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(tampered), Context());

        Assert.False(result.IsValid);
        Assert.Equal("signature_invalid", result.Errors.Single().Code);
    }

    [Fact]
    public async Task TamperedDisclosure_IsRejected()
    {
        using var builder = new TestCredentialBuilder();
        var raw = builder.Build();

        // Replace the first disclosure with a re-encoded variant claiming a different value.
        var parts = raw.Split('~');
        parts[1] = TestCredentialBuilder.MakeDisclosure("family_name", "Mallory");
        var tampered = string.Join('~', parts);

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(tampered), Context());

        Assert.False(result.IsValid);
        Assert.Equal("disclosure_unreferenced", result.Errors.Single().Code);
    }

    [Fact]
    public async Task WrongNonce_FailsKeyBinding()
    {
        using var builder = new TestCredentialBuilder { KbNonce = "stale-or-replayed-nonce" };

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "nonce_mismatch");
    }

    [Fact]
    public async Task WrongAudience_FailsKeyBinding()
    {
        using var builder = new TestCredentialBuilder { KbAudience = "https://other-verifier.example" };

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "audience_mismatch");
    }

    [Fact]
    public async Task SdHashOverDifferentPresentation_FailsKeyBinding()
    {
        using var builder = new TestCredentialBuilder { SdHashOverride = "something~else~" };

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "sd_hash_mismatch");
    }

    [Fact]
    public async Task MissingKeyBinding_WhenRequired_Fails()
    {
        using var builder = new TestCredentialBuilder { IncludeKbJwt = false };

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "key_binding_missing");
    }

    [Fact]
    public async Task KbJwtWithoutCnf_Fails()
    {
        using var builder = new TestCredentialBuilder { IncludeCnf = false };

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "confirmation_key_missing");
    }

    // ---- Policy -------------------------------------------------------------------------------

    [Fact]
    public async Task ExpiredCredential_Fails()
    {
        using var builder = new TestCredentialBuilder { Exp = DateTimeOffset.UtcNow.AddHours(-2).ToUnixTimeSeconds() };

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "credential_expired");
    }

    [Fact]
    public async Task NotYetValidCredential_Fails()
    {
        using var builder = new TestCredentialBuilder { Nbf = DateTimeOffset.UtcNow.AddHours(2).ToUnixTimeSeconds() };

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "credential_not_yet_valid");
    }

    [Fact]
    public async Task UntrustedIssuer_FailsWithTrustedFalse()
    {
        using var builder = new TestCredentialBuilder();

        var result = await MetadataVerifier(builder, new FakeTrustListResolver(trusted: false))
            .VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.False(result.Issuer.Trusted);
        Assert.Contains(result.Errors, e => e.Code == "issuer_untrusted");
        Assert.Empty(result.DisclosedClaims);
    }

    [Fact]
    public async Task VctMismatch_Fails()
    {
        using var builder = new TestCredentialBuilder();

        var result = await MetadataVerifier(builder)
            .VerifyAsync(Credential(builder.Build()), Context(expectedVct: "https://credentials.example/other"));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "vct_mismatch");
    }

    [Fact]
    public async Task MissingVct_Fails()
    {
        using var builder = new TestCredentialBuilder { Vct = null };

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "vct_missing");
    }

    /// <remarks>
    /// On the x5c route, because the key is in hand there whatever the trust verdict. On the metadata
    /// route an untrusted issuer's key is never fetched, so nothing after trust can be checked (see
    /// <see cref="UntrustedIssuer_OnTheMetadataRoute_IsRefusedWithoutAnyFetch"/>).
    /// </remarks>
    [Fact]
    public async Task PolicyFailures_AreAccumulated_NotFirstOnly()
    {
        using var builder = new TestCredentialBuilder
        {
            Exp = DateTimeOffset.UtcNow.AddHours(-2).ToUnixTimeSeconds(),
            KbNonce = "wrong-nonce",
        };
        builder.UseCertificate();

        var result = await new SdJwtVcVerifier(new FakeTrustListResolver(trusted: false))
            .VerifyAsync(Credential(builder.Build()), Context());

        var codes = result.Errors.Select(e => e.Code).ToList();
        Assert.Contains("credential_expired", codes);
        Assert.Contains("nonce_mismatch", codes);
        Assert.Contains("issuer_untrusted", codes);
    }

    // ---- Trust before any fetch ---------------------------------------------------------------

    /// <summary>
    /// An issuer the trust seam refuses gets no request of any kind: its metadata lives on a host the
    /// credential names, and so does its status list.
    /// </summary>
    [Fact]
    public async Task UntrustedIssuer_OnTheMetadataRoute_IsRefusedWithoutAnyFetch()
    {
        using var builder = new TestCredentialBuilder();
        builder.Status = (0, "https://issuer.example/statuslists/1");
        var http = new FakeHttpHandler().Map(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""");

        var result = await new SdJwtVcVerifier(new FakeTrustListResolver(trusted: false), httpClient: new HttpClient(http))
            .VerifyAsync(Credential(builder.Build()), Context());

        Assert.Empty(http.Requested);
        Assert.False(result.IsValid);
        Assert.Equal(["issuer_untrusted"], result.Errors.Select(e => e.Code));
        Assert.Equal(TestCredentialBuilder.DefaultIssuer, result.Issuer.Identifier);
        Assert.Equal("jwt-vc-issuer-metadata", result.Issuer.KeyResolutionMethod);
        Assert.Equal("fake://trust-list", result.Issuer.TrustListSource);
        Assert.Empty(result.DisclosedClaims);
    }

    /// <summary>
    /// On the x5c route the key is in the credential, so the signature is checked before the trust seam
    /// is asked, and a forged credential never reaches the seam at all.
    /// </summary>
    [Fact]
    public async Task ForgedSignature_OnTheX5cRoute_NeverReachesTheTrustSeam()
    {
        using var builder = new TestCredentialBuilder();
        builder.UseCertificate();
        var trust = new FakeTrustListResolver();

        var result = await new SdJwtVcVerifier(trust).VerifyAsync(Credential(TamperIssuerSignature(builder.Build())), Context());

        Assert.Equal(["signature_invalid"], result.Errors.Select(e => e.Code));
        Assert.Null(trust.SeenIssuer);
    }

    /// <summary>
    /// On the x5c route the trust seam is asked only after every check that needs nothing but the
    /// credential, so a correctly signed credential that fails structurally never reaches it either.
    /// </summary>
    [Fact]
    public async Task StructurallyInvalidCredential_OnTheX5cRoute_NeverReachesTheTrustSeam()
    {
        using var builder = new TestCredentialBuilder();
        builder.UseCertificate();
        var parts = builder.Build().Split('~');
        parts[1] = TestCredentialBuilder.MakeDisclosure("family_name", "Mallory");
        var trust = new FakeTrustListResolver();

        var result = await new SdJwtVcVerifier(trust).VerifyAsync(Credential(string.Join('~', parts)), Context());

        Assert.Equal(["disclosure_unreferenced"], result.Errors.Select(e => e.Code));
        Assert.Null(trust.SeenIssuer);
    }

    /// <summary>
    /// A trusted issuer whose iss is not HTTPS is refused before its metadata is requested, even though
    /// metadata is served at the cleartext address.
    /// </summary>
    [Fact]
    public async Task TrustedIssuer_WithANonHttpsIss_IsRefused_WithoutFetchingItsMetadata()
    {
        using var builder = new TestCredentialBuilder { Issuer = "http://issuer.example" };
        var http = new FakeHttpHandler().Map(
            "http://issuer.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""");

        var result = await new SdJwtVcVerifier(new FakeTrustListResolver(), httpClient: new HttpClient(http))
            .VerifyAsync(Credential(builder.Build()), Context());

        Assert.Empty(http.Requested);
        Assert.Equal(["issuer_key_unresolvable"], result.Errors.Select(e => e.Code));
    }

    /// <summary>
    /// The control for the test above: the same credential from a trusted issuer does fetch, so an
    /// empty request log there means trust stopped it, not that nothing ever fetches.
    /// </summary>
    [Fact]
    public async Task TrustedIssuer_OnTheMetadataRoute_FetchesItsMetadata()
    {
        using var builder = new TestCredentialBuilder();
        var http = new FakeHttpHandler().Map(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""");

        var result = await new SdJwtVcVerifier(new FakeTrustListResolver(), httpClient: new HttpClient(http))
            .VerifyAsync(Credential(builder.Build()), Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
        Assert.Equal(["https://issuer.example/.well-known/jwt-vc-issuer"], http.Requested);
    }

    /// <summary>
    /// On the x5c route the key needs no fetch, but the status list still would. An untrusted chain
    /// must not send it, and still reports its other failures.
    /// </summary>
    [Fact]
    public async Task UntrustedIssuer_OnTheX5cRoute_DoesNotFetchTheStatusList()
    {
        using var builder = new TestCredentialBuilder { KbNonce = "wrong-nonce" };
        builder.UseCertificate();
        builder.Status = (0, "https://issuer.example/statuslists/1");
        var http = new FakeHttpHandler();

        var result = await new SdJwtVcVerifier(new FakeTrustListResolver(trusted: false), httpClient: new HttpClient(http))
            .VerifyAsync(Credential(builder.Build()), Context());

        Assert.Empty(http.Requested);
        var codes = result.Errors.Select(e => e.Code).ToList();
        Assert.Contains("issuer_untrusted", codes);
        Assert.Contains("nonce_mismatch", codes);
        Assert.DoesNotContain(codes, code => code.StartsWith("status_", StringComparison.Ordinal));
    }

    // ---- Format & resolution ------------------------------------------------------------------

    [Fact]
    public async Task WrongFormatIdentifier_IsRejected()
    {
        using var builder = new TestCredentialBuilder();

        var result = await MetadataVerifier(builder)
            .VerifyAsync(Credential(builder.Build(), format: "vc+sd-jwt"), Context());

        Assert.False(result.IsValid);
        Assert.Equal("format_unsupported", result.Errors.Single().Code);
    }

    [Fact]
    public async Task GarbageRawValue_IsRejected()
    {
        var result = await new SdJwtVcVerifier(new FakeTrustListResolver())
            .VerifyAsync(Credential("not-a-credential"), Context());

        Assert.False(result.IsValid);
        Assert.Equal("structure_invalid", result.Errors.Single().Code);
    }

    [Fact]
    public async Task MetadataIssuerMismatch_IsRejected()
    {
        using var builder = new TestCredentialBuilder();
        var http = new FakeHttpHandler().Map(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"https://someone-else.example","jwks":{{builder.BuildJwksJson()}}}""");
        var verifier = new SdJwtVcVerifier(new FakeTrustListResolver(), httpClient: new HttpClient(http));

        var result = await verifier.VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Equal("issuer_metadata_invalid", result.Errors.Single().Code);
    }

    /// <summary>
    /// Both key sources at once is refused, and neither key set is used. The inline set is the issuer's real
    /// key, so without the check this credential would verify, and the uri would never be read.
    /// </summary>
    [Fact]
    public async Task MetadataWithBothJwksAndJwksUri_IsRejected_WithoutReadingTheUri()
    {
        using var builder = new TestCredentialBuilder();
        var http = new FakeHttpHandler().Map(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}},"jwks_uri":"https://issuer.example/jwks"}""");
        var verifier = new SdJwtVcVerifier(new FakeTrustListResolver(), httpClient: new HttpClient(http));

        var result = await verifier.VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Equal("issuer_metadata_invalid", result.Errors.Single().Code);
        Assert.DoesNotContain("https://issuer.example/jwks", http.Requested);
    }

    // WITH x5c THE CERTIFICATE NAMES THE ISSUER, and iss is the issuer only where a subjectAltName names
    // it. SPEC: draft-ietf-oauth-sd-jwt-vc-13 section 3.5 (pinned by HAIP 1.0 Final section 6.1.1),
    // "the Issuer of the Verifiable Credential is the subject of the end-entity certificate"; drafts -13
    // and -19 carry no requirement that iss match a SAN, which was draft -09's. A certificate naming
    // another host therefore VERIFIES, and its subject, not the unbacked iss, is the reported issuer.
    // The trust verdict rests on the chain alone, so the resolver must be asked about that subject.
    [Fact]
    public async Task X5cWithDnsSanNamingAnother_IsAccepted_AndNamesTheIssuerByCertificate()
    {
        using var builder = new TestCredentialBuilder();
        var leaf = builder.UseCertificate(sanDnsName: "not-the-issuer.example");
        var trust = new FakeTrustListResolver();

        var result = await new SdJwtVcVerifier(trust).VerifyAsync(Credential(builder.Build()), Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
        AssertNamedByCertificate(result, leaf);
        Assert.Equal(leaf.Subject, trust.SeenIssuer);
    }

    // A leaf with NO subject alternative name names nothing, so iss is not backed either and the subject
    // is the issuer. The EUDI Wallet Reference Implementation's PID issuer ships exactly such a leaf, and
    // we rejected its every credential until 2026-09-20; it is accepted, and now also named correctly.
    [Fact]
    public async Task X5cWithoutSan_IsAccepted_AndNamesTheIssuerByCertificate()
    {
        using var builder = new TestCredentialBuilder();
        var leaf = builder.UseCertificate(withSan: false);

        var result = await new SdJwtVcVerifier(new FakeTrustListResolver())
            .VerifyAsync(Credential(builder.Build()), Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
        Assert.Equal("x5c", result.Issuer.KeyResolutionMethod);
        AssertNamedByCertificate(result, leaf);
    }

    // ASSERTING NO NAME and ASSERTING A NAME WE CANNOT ENUMERATE are different. These cover a SAN that
    // carries a uniformResourceIdentifier and no dNSName, so only the URI comparison can name iss. Without
    // them, a resolver that stopped finding the parsed extension would report a certificate's unbacked
    // iss as the issuer.
    [Fact]
    public async Task X5cWithUriSanNamingAnother_NamesTheIssuerByCertificate()
    {
        using var builder = new TestCredentialBuilder();
        var leaf = builder.UseCertificate(sanUri: "https://not-the-issuer.example/");

        var result = await new SdJwtVcVerifier(new FakeTrustListResolver())
            .VerifyAsync(Credential(builder.Build()), Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
        AssertNamedByCertificate(result, leaf);
    }

    // The ordinary case: a dNSName equal to the iss host names iss, so iss stays the issuer.
    [Fact]
    public async Task X5cWithDnsSanMatchingIssHost_KeepsIssAsTheIssuer()
    {
        using var builder = new TestCredentialBuilder();
        builder.UseCertificate();

        var result = await new SdJwtVcVerifier(new FakeTrustListResolver())
            .VerifyAsync(Credential(builder.Build()), Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
        Assert.Equal(TestCredentialBuilder.DefaultIssuer, result.Issuer.Identifier);
        Assert.Null(result.Issuer.ClaimedIssuer);
    }

    [Fact]
    public async Task X5cWithUriSanMatchingIss_IsAccepted()
    {
        using var builder = new TestCredentialBuilder();
        builder.UseCertificate(sanUri: TestCredentialBuilder.DefaultIssuer);

        var result = await new SdJwtVcVerifier(new FakeTrustListResolver())
            .VerifyAsync(Credential(builder.Build()), Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
        Assert.Equal("x5c", result.Issuer.KeyResolutionMethod);
        Assert.Equal(TestCredentialBuilder.DefaultIssuer, result.Issuer.Identifier);
        Assert.Null(result.Issuer.ClaimedIssuer);
    }

    // A LOOKALIKE DOMAIN IS NOT A MATCH. The URI comparison used to be a substring test over the
    // formatted extension, so any name that merely STARTS with iss satisfied it and registering
    // `issuer.example.attacker.test` was the whole attack. A lookalike must never get iss as its name.
    [Fact]
    public async Task X5cWithLookalikeUriSan_NamesTheIssuerByCertificate()
    {
        using var builder = new TestCredentialBuilder();
        var leaf = builder.UseCertificate(sanUri: TestCredentialBuilder.DefaultIssuer + ".attacker.test/");

        var result = await new SdJwtVcVerifier(new FakeTrustListResolver())
            .VerifyAsync(Credential(builder.Build()), Context());

        AssertNamedByCertificate(result, leaf);
    }

    private static void AssertNamedByCertificate(VerificationResult result, System.Security.Cryptography.X509Certificates.X509Certificate2 leaf)
    {
        Assert.Equal(leaf.Subject, result.Issuer.Identifier);
        Assert.Equal(TestCredentialBuilder.DefaultIssuer, result.Issuer.ClaimedIssuer);
    }

    [Fact]
    public async Task IssuerMetadataUnreachable_IsRejected()
    {
        using var builder = new TestCredentialBuilder();
        var verifier = new SdJwtVcVerifier(new FakeTrustListResolver(), httpClient: new HttpClient(new FakeHttpHandler()));

        var result = await verifier.VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Equal("issuer_key_unresolvable", result.Errors.Single().Code);
    }

    [Fact]
    public async Task WellKnownPath_InsertsSegmentBetweenHostAndPath()
    {
        // SPEC: draft-ietf-oauth-sd-jwt-vc-13 §5.1: iss with a path component.
        using var builder = new TestCredentialBuilder { Issuer = "https://issuer.example/tenant/1234" };
        var http = new FakeHttpHandler().Map(
            "https://issuer.example/.well-known/jwt-vc-issuer/tenant/1234",
            $$"""{"issuer":"https://issuer.example/tenant/1234","jwks":{{builder.BuildJwksJson()}}}""");

        var result = await new SdJwtVcVerifier(new FakeTrustListResolver(), httpClient: new HttpClient(http))
            .VerifyAsync(Credential(builder.Build()), Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
        Assert.Contains("https://issuer.example/.well-known/jwt-vc-issuer/tenant/1234", http.Requested);
    }

    // ---- KB-JWT iat freshness (found by the OIDF conformance suite) ----------------------------

    [Fact]
    public async Task KbJwt_IatFarInPast_FailsKeyBinding()
    {
        using var builder = new TestCredentialBuilder { KbIatOverride = DateTimeOffset.UtcNow.AddYears(-1) };

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "key_binding_invalid" && e.Message.Contains("past"));
    }

    [Fact]
    public async Task KbJwt_IatFarInFuture_FailsKeyBinding()
    {
        using var builder = new TestCredentialBuilder { KbIatOverride = DateTimeOffset.UtcNow.AddYears(1) };

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "key_binding_invalid" && e.Message.Contains("future"));
    }

    [Fact]
    public async Task KbJwt_IatWithinWindow_Verifies()
    {
        // Two minutes old: inside the 5-minute default window, so it must still pass.
        using var builder = new TestCredentialBuilder { KbIatOverride = DateTimeOffset.UtcNow.AddMinutes(-2) };

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(builder.Build()), Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
    }

    [Fact]
    public async Task CredentialType_ReportsTheVct_OnASuccessfulVerification()
    {
        using var builder = new TestCredentialBuilder();

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(builder.Build()), Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
        Assert.Equal(TestCredentialBuilder.DefaultVct, result.CredentialType);
    }

    [Fact]
    public async Task CredentialType_ReportsWhatArrived_OnAVctMismatch()
    {
        // The case this exists for. A request naming several types learns which one the holder
        // actually presented ONLY from here: the mismatch message happens to interpolate it, but a
        // caller cannot parse a message, and on the passing path there is no message at all.
        using var builder = new TestCredentialBuilder();

        var result = await MetadataVerifier(builder)
            .VerifyAsync(Credential(builder.Build()), Context(expectedVct: "https://credentials.example/other"));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "vct_mismatch");
        Assert.Equal(TestCredentialBuilder.DefaultVct, result.CredentialType);
    }

    [Fact]
    public async Task CredentialType_IsNull_WhenVerificationFailsBeforeTheTypeIsRead()
    {
        // Null means "not established", not "the credential declared none". A signature that fails is
        // rejected before the payload is parsed, so there is nothing to report and reporting an empty
        // string would be the stronger, false claim.
        using var builder = new TestCredentialBuilder();
        var presentation = builder.Build();
        var tampered = TamperIssuerSignature(presentation);

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(tampered), Context());

        // Asserting the CODE as well, because the point is that it failed at the SIGNATURE. A tamper
        // that made the token malformed would also leave CredentialType null and the test would pass
        // while exercising a different path entirely.
        Assert.False(result.IsValid);
        // The literal, not the constant, matching this project's dominant convention: CONTRIBUTING
        // declares these codes append-only observable behaviour, so pinning the string is the point.
        // A rename would pass against the constant and break every consumer.
        Assert.Contains(result.Errors, e => e.Code == "signature_invalid");
        Assert.Null(result.CredentialType);
    }

    /// <summary>
    /// Flips one character in the MIDDLE of the issuer JWT's signature segment, leaving the
    /// presentation's structure intact so it still parses and fails at the signature.
    /// </summary>
    /// <remarks>
    /// Deliberately not the last character: base64url's final character carries partial bits, so some
    /// flips there decode to identical bytes and the signature still verifies. A test built on that
    /// would pass or fail depending on the key it happened to generate.
    /// </remarks>
    private static string TamperIssuerSignature(string presentation)
    {
        var tildeAt = presentation.IndexOf('~');
        var sigStart = presentation.LastIndexOf('.', tildeAt) + 1;
        var mid = (sigStart + tildeAt) / 2;
        return presentation[..mid] + (presentation[mid] == 'A' ? 'B' : 'A') + presentation[(mid + 1)..];
    }
}
