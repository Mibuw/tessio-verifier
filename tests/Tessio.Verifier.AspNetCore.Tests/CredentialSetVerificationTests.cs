using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Core;
using Tessio.Verifier.Core.Mdoc;
using Tessio.Verifier.OpenId4Vp;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// One DCQL query offering a PID as an ISO mdoc or as an SD-JWT VC, as alternatives in one credential set
/// (OpenID4VP 1.0 section 6.2). Whichever the wallet answers verifies in the format of the Credential Query its
/// <c>vp_token</c> key names (section 8.1), and the result reports that id. Driven through the Digital Credentials
/// API, signed and unsigned, through the redirect seam and through the built-in callback, which parses before it
/// knows the session.
/// </summary>
/// <remarks>
/// The answers are built here from the mock issuers rather than the public wallet helper, because that helper keys
/// every answer <c>credential</c> and these tests are about the key.
/// </remarks>
public sealed class CredentialSetVerificationTests : IDisposable
{
    private const string Origin = "https://verifier.example";
    private const string PidDocType = "eu.europa.ec.eudi.pid.1";
    private const string PidVct = "urn:eudi:pid:1";
    private const string MdocId = "pid_mdoc";
    private const string SdJwtId = "pid_sd_jwt";

    private static readonly string PidQuery = Dcql.AnyOf(
        DcqlCredentialQuery.Mdoc(MdocId, PidDocType, [new DcqlClaim { Path = [PidDocType, "age_over_18"] }]),
        DcqlCredentialQuery.SdJwtVc(SdJwtId, [PidVct], [new DcqlClaim { Path = ["age_over_18"] }]));

    private readonly MockCredentialIssuer _issuer = new();
    private readonly MockMdocIssuer _mdocIssuer = new();
    private readonly ECDsa _encryptionKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ServiceProvider _provider;

    public CredentialSetVerificationTests()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ITrustListResolver>(_ => new StaticTrustListResolver(
            [MockCredentialIssuer.Issuer, _mdocIssuer.DsCertificate.Subject], "test", [_issuer.Certificate, _mdocIssuer.IacaCertificate]));
        services.AddTessioVerifier(options => options.Mode = VerifierMode.Mock);
        _provider = services.BuildServiceProvider();
    }

    public void Dispose()
    {
        _provider.Dispose();
        _encryptionKey.Dispose();
        _signingKey.Dispose();
        _issuer.Dispose();
        _mdocIssuer.Dispose();
    }

    private WalletResponseVerifier Verifier => (WalletResponseVerifier)_provider.GetRequiredService<IWalletResponseVerifier>();

    private JsonObject EncryptionJwk()
    {
        var p = _encryptionKey.ExportParameters(false);
        return new JsonObject
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Base64UrlEncoder.Encode(p.Q.X!),
            ["y"] = Base64UrlEncoder.Encode(p.Q.Y!),
            ["use"] = "enc",
            ["alg"] = "ECDH-ES",
            ["kid"] = "1",
        };
    }

    private DcApiPresentationRequest Request(bool signedRequest, bool encrypted, string query = "", string? transactionDataJson = null)
    {
        var options = new DcApiPresentationRequestOptions
        {
            Nonce = "nonce-1",
            TransactionDataJson = transactionDataJson,
            DcqlQueryJson = query.Length > 0 ? query : PidQuery,
            EncryptedResponse = encrypted,
            ExpectedOrigins = [Origin],
            ClientMetadataJson = ClientMetadata.BuildForFormats(["mso_mdoc", "dc+sd-jwt"], encrypted ? EncryptionJwk() : null),
        };

        return signedRequest
            ? new DcApiPresentationRequestBuilder(new PresentationRequestBuilderOptions
            {
                SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(_signingKey), SecurityAlgorithms.EcdsaSha256),
            }).Build(options with { ClientId = "x509_hash:example" })
            : new DcApiPresentationRequestBuilder().Build(options);
    }

    private string MdocPresentation(DcApiPresentationRequest request) =>
        _mdocIssuer.IssueDeviceResponseOverTranscript(
            ["age_over_18"],
            PidDocType,
            PidDocType,
            SessionTranscriptBuilder.BuildForDcApi(
                Origin,
                request.Nonce,
                RequestParameters.AsksForEncryptedResponse(request) ? RequestParameters.TryGetEncryptionKeyThumbprint(request) : null));

    private string SdJwtPresentation(DcApiPresentationRequest request) =>
        _issuer.IssuePresentation(["age_over_18"], PidVct, request.Nonce, $"origin:{Origin}");

    /// <summary>The <c>data</c> object a wallet returns, its vp_token keyed as given, sealed when the request asked.</summary>
    private static string Data(DcApiPresentationRequest request, params (string Key, string Presentation)[] answers)
    {
        // A key given twice carries both presentations, in the order given; keys keep the order given too.
        var parameters = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["vp_token"] = answers.GroupBy(a => a.Key).ToDictionary(g => g.Key, g => g.Select(a => a.Presentation).ToArray()),
        });

        return RequestParameters.AsksForEncryptedResponse(request)
            ? JsonSerializer.Serialize(new Dictionary<string, string>
            {
                ["response"] = EcdhEsJweEncryptor.Encrypt(parameters, RequestParameters.TryGetEncryptionJwkJson(request)!),
            })
            : parameters;
    }

    private Task<VerificationResult> VerifyAsync(DcApiPresentationRequest request, string data) =>
        Verifier.VerifyDcApiAsync(request, Origin, data, new ECDsaSecurityKey(_encryptionKey));

    private static string Errors(VerificationResult result) =>
        string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}"));

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public async Task An_mdoc_answer_verifies_and_reports_its_credential_query(bool signedRequest, bool encrypted)
    {
        var request = Request(signedRequest, encrypted);

        var result = await VerifyAsync(request, Data(request, (MdocId, MdocPresentation(request))));

        Assert.True(result.IsValid, Errors(result));
        Assert.Equal(MdocId, result.CredentialQueryId);
        Assert.Equal(PidDocType, result.CredentialType);
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public async Task An_sd_jwt_answer_verifies_and_reports_its_credential_query(bool signedRequest, bool encrypted)
    {
        var request = Request(signedRequest, encrypted);

        var result = await VerifyAsync(request, Data(request, (SdJwtId, SdJwtPresentation(request))));

        Assert.True(result.IsValid, Errors(result));
        Assert.Equal(SdJwtId, result.CredentialQueryId);
        Assert.Equal(PidVct, result.CredentialType);
    }

    [Fact]
    public async Task An_answer_keyed_by_an_id_not_in_the_query_is_refused()
    {
        var request = Request(signedRequest: false, encrypted: true);

        var result = await VerifyAsync(request, Data(request, (Dcql.DefaultCredentialId, MdocPresentation(request))));

        var error = Assert.Single(result.Errors);
        Assert.Equal("response_invalid", error.Code);
        Assert.Contains("names no Credential Query", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_answer_satisfying_no_option_of_a_required_set_is_refused()
    {
        // The PID either way, and the age attestation as well: two required sets.
        var query = Dcql.Query(
            [
                DcqlCredentialQuery.Mdoc(MdocId, PidDocType, [new DcqlClaim { Path = [PidDocType, "age_over_18"] }]),
                DcqlCredentialQuery.SdJwtVc(SdJwtId, [PidVct], [new DcqlClaim { Path = ["age_over_18"] }]),
                DcqlCredentialQuery.Mdoc("av", "eu.europa.ec.av.1", [new DcqlClaim { Path = ["eu.europa.ec.av.1", "age_over_18"] }]),
            ],
            new DcqlCredentialSet { Options = [[MdocId], [SdJwtId]] },
            new DcqlCredentialSet { Options = [["av"]] });
        var request = Request(signedRequest: false, encrypted: true, query);

        var result = await VerifyAsync(request, Data(request, (MdocId, MdocPresentation(request))));

        var error = Assert.Single(result.Errors);
        Assert.Equal("response_invalid", error.Code);
        Assert.Contains("no option", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_mdoc_presentation_under_the_sd_jwt_id_is_refused_because_the_format_follows_the_key()
    {
        var request = Request(signedRequest: false, encrypted: true);

        var result = await VerifyAsync(request, Data(request, (SdJwtId, MdocPresentation(request))));

        Assert.False(result.IsValid);
        Assert.Equal(SdJwtId, result.CredentialQueryId);
    }

    [Fact]
    public async Task An_sd_jwt_presentation_under_the_mdoc_id_is_refused_because_the_format_follows_the_key()
    {
        var request = Request(signedRequest: false, encrypted: true);

        var result = await VerifyAsync(request, Data(request, (MdocId, SdJwtPresentation(request))));

        Assert.False(result.IsValid);
        Assert.Equal(MdocId, result.CredentialQueryId);
    }

    [Fact]
    public async Task Each_answer_is_checked_against_its_own_credential_querys_type()
    {
        // Two entries of one format with different types, the other one first, and an SD-JWT entry before both: the
        // type compared is the entry the key names, not the first entry, nor the first entry of the same format.
        const string MdlDocType = "org.iso.18013.5.1.mDL";
        var query = Dcql.AnyOf(
            DcqlCredentialQuery.SdJwtVc(SdJwtId, [PidVct], [new DcqlClaim { Path = ["age_over_18"] }]),
            DcqlCredentialQuery.Mdoc("mdl", MdlDocType, [new DcqlClaim { Path = ["org.iso.18013.5.1", "age_over_18"] }]),
            DcqlCredentialQuery.Mdoc(MdocId, PidDocType, [new DcqlClaim { Path = [PidDocType, "age_over_18"] }]));
        var request = Request(signedRequest: false, encrypted: true, query);
        var mdl = _mdocIssuer.IssueDeviceResponseOverTranscript(
            ["age_over_18"], MdlDocType, "org.iso.18013.5.1",
            SessionTranscriptBuilder.BuildForDcApi(Origin, request.Nonce, RequestParameters.TryGetEncryptionKeyThumbprint(request)));

        var pidAsPid = await VerifyAsync(request, Data(request, (MdocId, MdocPresentation(request))));
        Assert.True(pidAsPid.IsValid, Errors(pidAsPid));
        var mdlAsMdl = await VerifyAsync(request, Data(request, ("mdl", mdl)));
        Assert.True(mdlAsMdl.IsValid, Errors(mdlAsMdl));

        var mdlAsPid = await VerifyAsync(request, Data(request, (MdocId, mdl)));
        Assert.Contains(mdlAsPid.Errors, e => e.Code == MdocErrorCodes.DocTypeMismatch);
        var pidAsMdl = await VerifyAsync(request, Data(request, ("mdl", MdocPresentation(request))));
        Assert.Contains(pidAsMdl.Errors, e => e.Code == MdocErrorCodes.DocTypeMismatch);
    }

    [Theory]
    [InlineData("""{"credentials":[{"id":"a","format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"}},{"id":"b","format":"dc+sd-jwt","meta":{}}],"credential_sets":[{"options":[["a"],["b"]]}]}""")]
    [InlineData("""{"credentials":[{"id":"a","format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"}},{"id":"a","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}}]}""")]
    [InlineData("""{"credentials":[{"format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"}},{"format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}}]}""")]
    [InlineData("""{"credentials":[{"id":"a","format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"}}],"credential_sets":[{"options":[["b"]]}]}""")]
    public async Task A_query_whose_answers_cannot_each_be_matched_to_a_typed_entry_cannot_be_verified(string query)
    {
        // A second entry with no type, two entries with one id, entries with no id, a set naming no entry.
        var request = Request(signedRequest: false, encrypted: true, query);

        Assert.False(WalletResponseVerifier.CanVerify(request));
        var result = await VerifyAsync(request, Data(request, ("a", MdocPresentation(request))));
        Assert.Equal(ErrorCodes.RequestUnverifiable, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public void A_single_credential_query_without_an_id_can_still_be_verified_as_before()
    {
        var request = Request(
            signedRequest: false, encrypted: true, """{"credentials":[{"format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"}}]}""");

        Assert.True(WalletResponseVerifier.CanVerify(request));
    }

    /// <summary>
    /// Entry <c>b</c> names no format: its answer would be read in the configured format (mdoc for an mdoc process),
    /// while its own type, vct_values, says SD-JWT, so the mdoc docType comparison would read null and be skipped.
    /// </summary>
    private const string EntryWithoutFormat =
        """{"credentials":[{"id":"a","format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"}},{"id":"b","meta":{"vct_values":["urn:eudi:pid:1"]}}],"credential_sets":[{"options":[["a"],["b"]]}]}""";

    /// <summary>Entry <c>a</c> is an mdoc entry that states no docType, with readable ids and formats throughout.</summary>
    private const string MdocEntryWithoutType =
        """{"credentials":[{"id":"a","format":"mso_mdoc","meta":{}},{"id":"b","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}}],"credential_sets":[{"options":[["a"],["b"]]}]}""";

    [Theory]
    [InlineData(EntryWithoutFormat, "b")]
    [InlineData(MdocEntryWithoutType, "a")]
    public async Task An_entry_whose_type_would_go_unchecked_fails_CanVerify_and_is_refused_before_verification_over_the_digital_credentials_api(string query, string key)
    {
        var request = Request(signedRequest: false, encrypted: true, query);

        var result = await VerifyAsync(request, Data(request, (key, MdocPresentation(request))));

        Assert.False(WalletResponseVerifier.CanVerify(request));
        Assert.Equal(ErrorCodes.RequestUnverifiable, Assert.Single(result.Errors).Code);
    }

    [Theory]
    [InlineData(EntryWithoutFormat, "b")]
    [InlineData(MdocEntryWithoutType, "a")]
    public async Task An_entry_whose_type_would_go_unchecked_is_refused_through_the_redirect_seam_even_unasked(string query, string key)
    {
        // VerifyAsync does not call CanVerify for its caller, so the refusal has to happen where the type is read.
        // The process is configured for mdoc, so an answer under an entry with no format is read as an mdoc.
        var services = new ServiceCollection();
        services.AddSingleton<ITrustListResolver>(_ => new StaticTrustListResolver(
            [MockCredentialIssuer.Issuer, _mdocIssuer.DsCertificate.Subject], "test", [_issuer.Certificate, _mdocIssuer.IacaCertificate]));
        services.AddTessioVerifier(options =>
        {
            options.Mode = VerifierMode.Mock;
            options.CredentialFormat = "mso_mdoc";
        });
        await using var provider = services.BuildServiceProvider();
        var session = await provider.GetRequiredService<InMemorySessionStore>().CreateAsync(new PresentationRequestOptions
        {
            ClientId = "x509_san_dns:verifier.example",
            Nonce = Tokens.NewNonce(),
            State = Tokens.NewNonce(),
            DcqlQueryJson = query,
            ResponseUri = new Uri("https://verifier.example/verify/callback"),
            ResponseMode = ResponseMode.DirectPost,
            RequestLifetime = TimeSpan.FromMinutes(5),
        });

        var result = await provider.GetRequiredService<IWalletResponseVerifier>()
            .VerifyAsync(session, Form(session, key, RedirectMdoc(session)));

        Assert.Equal(ErrorCodes.RequestUnverifiable, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public async Task A_failing_alternative_is_discarded_and_the_one_that_verifies_answers_the_set()
    {
        // SPEC: OpenID4VP 1.0 section 8.6: a presentation that fails its own checks "MUST be discarded". The SD-JWT
        // answer is bound to another nonce; the mdoc alone still completes an option.
        var request = Request(signedRequest: false, encrypted: true);
        var stale = _issuer.IssuePresentation(["age_over_18"], PidVct, "another-nonce", $"origin:{Origin}");

        var result = await VerifyAsync(request, Data(request, (SdJwtId, stale), (MdocId, MdocPresentation(request))));

        Assert.True(result.IsValid, Errors(result));
        Assert.Equal(MdocId, result.CredentialQueryId);
    }

    [Fact]
    public async Task When_what_remains_answers_no_option_the_response_is_refused_with_the_discarded_failure()
    {
        var request = Request(signedRequest: false, encrypted: true);
        var stale = _issuer.IssuePresentation(["age_over_18"], PidVct, "another-nonce", $"origin:{Origin}");

        var result = await VerifyAsync(request, Data(request, (SdJwtId, stale)));

        Assert.False(result.IsValid);
        Assert.Equal(SdJwtId, result.CredentialQueryId);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.NonceMismatch);
    }

    [Fact]
    public async Task When_every_set_is_optional_and_nothing_verified_the_response_is_still_refused()
    {
        var query = Dcql.Query(
            [
                DcqlCredentialQuery.Mdoc(MdocId, PidDocType, [new DcqlClaim { Path = [PidDocType, "age_over_18"] }]),
                DcqlCredentialQuery.SdJwtVc(SdJwtId, [PidVct], [new DcqlClaim { Path = ["age_over_18"] }]),
            ],
            new DcqlCredentialSet { Options = [[MdocId], [SdJwtId]], Required = false });
        var request = Request(signedRequest: false, encrypted: true, query);
        var stale = _issuer.IssuePresentation(["age_over_18"], PidVct, "another-nonce", $"origin:{Origin}");

        var result = await VerifyAsync(request, Data(request, (SdJwtId, stale)));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.NonceMismatch);
    }

    [Fact]
    public async Task Without_credential_sets_a_discarded_presentation_leaves_a_query_unanswered_and_is_refused()
    {
        var query = Dcql.Query(
            [
                DcqlCredentialQuery.Mdoc(MdocId, PidDocType, [new DcqlClaim { Path = [PidDocType, "age_over_18"] }]),
                DcqlCredentialQuery.SdJwtVc(SdJwtId, [PidVct], [new DcqlClaim { Path = ["age_over_18"] }]),
            ]);
        var request = Request(signedRequest: false, encrypted: true, query);
        var stale = _issuer.IssuePresentation(["age_over_18"], PidVct, "another-nonce", $"origin:{Origin}");

        var result = await VerifyAsync(request, Data(request, (MdocId, MdocPresentation(request)), (SdJwtId, stale)));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.NonceMismatch);
    }

    /// <summary>A transaction_data parameter with one object naming <paramref name="credentialIds"/>.</summary>
    private static (string Json, string Entry) TransactionData(params string[] credentialIds)
    {
        var entry = Base64UrlEncoder.Encode(JsonSerializer.Serialize(new { type = "example_payment", credential_ids = credentialIds }));
        return (JsonSerializer.Serialize(new[] { entry }), entry);
    }

    private string SdJwtAcknowledging(DcApiPresentationRequest request, string entry) =>
        _issuer.IssuePresentation(["age_over_18"], PidVct, request.Nonce, $"origin:{Origin}", [entry]);

    [Fact]
    public async Task Transaction_data_bound_to_the_sd_jwt_entry_is_acknowledged_by_its_answer()
    {
        var (json, entry) = TransactionData(SdJwtId);
        var request = Request(signedRequest: false, encrypted: true, transactionDataJson: json);

        var result = await VerifyAsync(request, Data(request, (SdJwtId, SdJwtAcknowledging(request, entry))));

        Assert.True(result.IsValid, Errors(result));
    }

    [Fact]
    public async Task An_entry_no_transaction_data_names_is_not_held_to_it()
    {
        // OpenID4VP 1.0 section 8.4 puts the acknowledgement "in the respective Credential presentation". With two
        // credentials required together and the transaction bound to one, the other's answer carries no hashes, and
        // is not refused for it.
        const string AgeVct = "urn:example:age:1";
        var query = Dcql.Query(
            [
                DcqlCredentialQuery.SdJwtVc(SdJwtId, [PidVct], [new DcqlClaim { Path = ["age_over_18"] }]),
                DcqlCredentialQuery.SdJwtVc("age", [AgeVct], [new DcqlClaim { Path = ["age_over_18"] }]),
            ],
            new DcqlCredentialSet { Options = [[SdJwtId, "age"]] });
        var (json, entry) = TransactionData(SdJwtId);
        var request = Request(signedRequest: false, encrypted: true, query: query, transactionDataJson: json);
        var unbound = _issuer.IssuePresentation(["age_over_18"], AgeVct, request.Nonce, $"origin:{Origin}");

        var result = await VerifyAsync(request, Data(request, (SdJwtId, SdJwtAcknowledging(request, entry)), ("age", unbound)));

        Assert.True(result.IsValid, Errors(result));
        Assert.Equal(2, result.VerifiedPresentations!.Count);
    }

    [Fact]
    public async Task An_mdoc_answer_cannot_stand_in_for_transaction_data_bound_to_the_sd_jwt_entry()
    {
        // The set is satisfied by the mdoc, but the transaction was to be authorized by the SD-JWT VC entry, and an
        // mdoc carries no acknowledgement this library checks.
        var (json, _) = TransactionData(SdJwtId);
        var request = Request(signedRequest: false, encrypted: true, transactionDataJson: json);

        var result = await VerifyAsync(request, Data(request, (MdocId, MdocPresentation(request))));

        Assert.Equal(ErrorCodes.TransactionDataMissing, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public async Task A_discarded_sd_jwt_that_failed_its_transaction_data_does_not_let_the_mdoc_beside_it_answer()
    {
        var (json, _) = TransactionData(SdJwtId);
        var request = Request(signedRequest: false, encrypted: true, transactionDataJson: json);
        var (_, otherEntry) = TransactionData("someone_else");
        var wrongBinding = SdJwtAcknowledging(request, otherEntry);

        var result = await VerifyAsync(request, Data(request, (SdJwtId, wrongBinding), (MdocId, MdocPresentation(request))));

        Assert.Equal(ErrorCodes.TransactionDataMissing, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public async Task Transaction_data_naming_an_mdoc_entry_cannot_be_verified()
    {
        var (json, _) = TransactionData(MdocId);
        var request = Request(signedRequest: false, encrypted: true, transactionDataJson: json);

        var result = await VerifyAsync(request, Data(request, (MdocId, MdocPresentation(request))));

        Assert.False(WalletResponseVerifier.CanVerify(request));
        Assert.Equal(ErrorCodes.RequestUnverifiable, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public async Task Transaction_data_naming_an_mdoc_entry_is_refused_through_the_redirect_seam_even_unasked()
    {
        var (json, _) = TransactionData(MdocId);
        var session = await _provider.GetRequiredService<InMemorySessionStore>().CreateAsync(new PresentationRequestOptions
        {
            ClientId = "x509_san_dns:verifier.example",
            Nonce = Tokens.NewNonce(),
            State = Tokens.NewNonce(),
            DcqlQueryJson = PidQuery,
            ResponseUri = new Uri("https://verifier.example/verify/callback"),
            ResponseMode = ResponseMode.DirectPost,
            TransactionDataJson = json,
            RequestLifetime = TimeSpan.FromMinutes(5),
        });

        var result = await Verifier.VerifyAsync(session, Form(session, MdocId, RedirectMdoc(session)));

        Assert.Equal(ErrorCodes.TransactionDataMissing, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public async Task Transaction_data_whose_credential_ids_cannot_be_read_is_refused_through_the_redirect_seam_even_unasked()
    {
        // base64url of a JSON object without credential_ids: nothing says which entry must acknowledge it.
        var entry = Base64UrlEncoder.Encode("""{"type":"example_payment"}""");
        var session = await _provider.GetRequiredService<InMemorySessionStore>().CreateAsync(new PresentationRequestOptions
        {
            ClientId = "x509_san_dns:verifier.example",
            Nonce = Tokens.NewNonce(),
            State = Tokens.NewNonce(),
            DcqlQueryJson = PidQuery,
            ResponseUri = new Uri("https://verifier.example/verify/callback"),
            ResponseMode = ResponseMode.DirectPost,
            TransactionDataJson = JsonSerializer.Serialize(new[] { entry }),
            RequestLifetime = TimeSpan.FromMinutes(5),
        });
        var acknowledging = _issuer.IssuePresentation(
            ["age_over_18"], PidVct, session.Request.Nonce, session.Request.ClientId, [entry]);

        var result = await Verifier.VerifyAsync(session, Form(session, SdJwtId, acknowledging));

        Assert.False(WalletResponseVerifier.CanVerify(session.Request));
        Assert.Equal(ErrorCodes.RequestUnverifiable, Assert.Single(result.Errors).Code);
    }

    private const string OtherVct = "urn:example:membership:1";

    private static DcqlCredentialQuery SdJwtEntry(string id, string vct) =>
        DcqlCredentialQuery.SdJwtVc(id, [vct], [new DcqlClaim { Path = ["age_over_18"] }]);

    /// <summary>Transaction data of several objects, each naming the ids given.</summary>
    private static (string Json, string[] Entries) TransactionDataObjects(params string[][] credentialIds)
    {
        var entries = credentialIds
            .Select(ids => Base64UrlEncoder.Encode(JsonSerializer.Serialize(new { type = "example_payment", credential_ids = ids })))
            .ToArray();
        return (JsonSerializer.Serialize(entries), entries);
    }

    public static TheoryData<string, string[][]> EntriesNeededTogether => new()
    {
        // One option needing both entries, one object naming both.
        { Dcql.Query([SdJwtEntry("a", PidVct), SdJwtEntry("b", OtherVct)], new DcqlCredentialSet { Options = [["a", "b"]] }), [["a", "b"]] },
        // The same query, an object for a alone beside one naming both: b is still needed with a.
        { Dcql.Query([SdJwtEntry("a", PidVct), SdJwtEntry("b", OtherVct)], new DcqlCredentialSet { Options = [["a", "b"]] }), [["a"], ["a", "b"]] },
        // Two required sets, each satisfied by one of the named entries.
        { Dcql.Query([SdJwtEntry("a", PidVct), SdJwtEntry("b", OtherVct)], new DcqlCredentialSet { Options = [["a"]] }, new DcqlCredentialSet { Options = [["b"]] }), [["a", "b"]] },
        // No credential sets: every entry is requested.
        { Dcql.Query([SdJwtEntry("a", PidVct), SdJwtEntry("b", OtherVct)]), [["a", "b"]] },
    };

    [Theory]
    [MemberData(nameof(EntriesNeededTogether))]
    public async Task Transaction_data_naming_two_entries_an_answer_may_need_together_cannot_be_verified(string query, string[][] credentialIds)
    {
        // SPEC: OpenID4VP 1.0 section 5.1: "the Wallet MUST use only one of the referenced Credentials for transaction
        // authorization". Which one it used cannot be told, and the other would be refused for not acknowledging it.
        var (json, entries) = TransactionDataObjects(credentialIds);
        var request = Request(signedRequest: false, encrypted: true, query, json);
        var a = _issuer.IssuePresentation(["age_over_18"], PidVct, request.Nonce, $"origin:{Origin}", [.. entries]);
        var b = _issuer.IssuePresentation(["age_over_18"], OtherVct, request.Nonce, $"origin:{Origin}");

        var result = await VerifyAsync(request, Data(request, ("a", a), ("b", b)));

        Assert.False(WalletResponseVerifier.CanVerify(request));
        Assert.Equal(ErrorCodes.RequestUnverifiable, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public async Task Transaction_data_naming_two_entries_needed_together_is_refused_through_the_redirect_seam_even_unasked()
    {
        var (json, entries) = TransactionDataObjects(["a", "b"]);
        var session = await _provider.GetRequiredService<InMemorySessionStore>().CreateAsync(new PresentationRequestOptions
        {
            ClientId = "x509_san_dns:verifier.example",
            Nonce = Tokens.NewNonce(),
            State = Tokens.NewNonce(),
            DcqlQueryJson = Dcql.Query([SdJwtEntry("a", PidVct), SdJwtEntry("b", OtherVct)], new DcqlCredentialSet { Options = [["a", "b"]] }),
            ResponseUri = new Uri("https://verifier.example/verify/callback"),
            ResponseMode = ResponseMode.DirectPost,
            TransactionDataJson = json,
            RequestLifetime = TimeSpan.FromMinutes(5),
        });
        var a = _issuer.IssuePresentation(["age_over_18"], PidVct, session.Request.Nonce, session.Request.ClientId, [.. entries]);

        var result = await Verifier.VerifyAsync(session, Form(session, "a", a));

        Assert.Equal(ErrorCodes.RequestUnverifiable, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public async Task Transaction_data_naming_two_alternatives_is_acknowledged_by_whichever_answers()
    {
        var query = Dcql.AnyOf(SdJwtEntry("a", PidVct), SdJwtEntry("b", OtherVct));
        var (json, entries) = TransactionDataObjects(["a", "b"]);
        var request = Request(signedRequest: false, encrypted: true, query, json);
        var b = _issuer.IssuePresentation(["age_over_18"], OtherVct, request.Nonce, $"origin:{Origin}", [.. entries]);

        var result = await VerifyAsync(request, Data(request, ("b", b)));

        Assert.True(WalletResponseVerifier.CanVerify(request));
        Assert.True(result.IsValid, Errors(result));
        Assert.Equal("b", result.CredentialQueryId);
    }

    private const string MultipleSdJwtQuery =
        """{"credentials":[{"id":"pid","format":"dc+sd-jwt","multiple":true,"meta":{"vct_values":["urn:eudi:pid:1"]}}]}""";

    [Fact]
    public async Task Under_multiple_a_failing_presentation_is_discarded_and_the_good_one_beside_it_answers()
    {
        var request = Request(signedRequest: false, encrypted: true, MultipleSdJwtQuery);
        var stale = _issuer.IssuePresentation(["age_over_18"], PidVct, "another-nonce", $"origin:{Origin}");

        var result = await VerifyAsync(request, Data(request, ("pid", stale), ("pid", SdJwtPresentation(request))));

        Assert.True(result.IsValid, Errors(result));
        Assert.Single(result.VerifiedPresentations!);
    }

    [Fact]
    public async Task Under_multiple_all_failing_presentations_are_refused()
    {
        var request = Request(signedRequest: false, encrypted: true, MultipleSdJwtQuery);
        var stale = _issuer.IssuePresentation(["age_over_18"], PidVct, "another-nonce", $"origin:{Origin}");

        var result = await VerifyAsync(request, Data(request, ("pid", stale), ("pid", stale)));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.NonceMismatch);
    }

    [Fact]
    public async Task The_result_follows_the_querys_order_not_the_order_the_wallet_put_its_keys_in()
    {
        // Both alternatives answered and both verify. The mdoc entry comes first in the query.
        var request = Request(signedRequest: false, encrypted: true);
        var mdoc = MdocPresentation(request);
        var sdJwt = SdJwtPresentation(request);

        var sdJwtFirst = await VerifyAsync(request, Data(request, (SdJwtId, sdJwt), (MdocId, mdoc)));
        var mdocFirst = await VerifyAsync(request, Data(request, (MdocId, mdoc), (SdJwtId, sdJwt)));

        Assert.Equal(MdocId, sdJwtFirst.CredentialQueryId);
        Assert.Equal(MdocId, mdocFirst.CredentialQueryId);
        Assert.Equal([MdocId, SdJwtId], sdJwtFirst.VerifiedPresentations!.Select(p => p.CredentialQueryId));
        Assert.Equal(PidVct, sdJwtFirst.VerifiedPresentations![1].CredentialType);
    }

    /// <summary>A redirect session asking for the PID either way, answered in the clear.</summary>
    private async Task<VerificationSession> RedirectSessionAsync() =>
        await _provider.GetRequiredService<InMemorySessionStore>().CreateAsync(new PresentationRequestOptions
        {
            ClientId = "x509_san_dns:verifier.example",
            Nonce = Tokens.NewNonce(),
            State = Tokens.NewNonce(),
            DcqlQueryJson = PidQuery,
            ResponseUri = new Uri("https://verifier.example/verify/callback"),
            ResponseMode = ResponseMode.DirectPost,
            ClientMetadataJson = ClientMetadata.BuildForFormats(["mso_mdoc", "dc+sd-jwt"]),
            RequestLifetime = TimeSpan.FromMinutes(5),
        });

    private static WalletResponseData Form(VerificationSession session, string key, string presentation) => new()
    {
        ContentType = "application/x-www-form-urlencoded",
        Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
        {
            ["vp_token"] = [JsonSerializer.Serialize(new Dictionary<string, string[]> { [key] = [presentation] })],
            ["state"] = [session.Request.State!],
        },
        Body = ReadOnlyMemory<byte>.Empty,
    };

    private string RedirectMdoc(VerificationSession session) => _mdocIssuer.IssueDeviceResponse(
        ["age_over_18"], PidDocType, PidDocType, session.Request.ClientId, session.Request.Nonce, null,
        "https://verifier.example/verify/callback");

    private string RedirectSdJwt(VerificationSession session) =>
        _issuer.IssuePresentation(["age_over_18"], PidVct, session.Request.Nonce, session.Request.ClientId);

    [Fact]
    public async Task Either_answer_verifies_through_the_redirect_seam()
    {
        var mdocSession = await RedirectSessionAsync();
        var mdoc = await Verifier.VerifyAsync(mdocSession, Form(mdocSession, MdocId, RedirectMdoc(mdocSession)));
        Assert.True(mdoc.IsValid, Errors(mdoc));
        Assert.Equal(MdocId, mdoc.CredentialQueryId);

        var sdJwtSession = await RedirectSessionAsync();
        var sdJwt = await Verifier.VerifyAsync(sdJwtSession, Form(sdJwtSession, SdJwtId, RedirectSdJwt(sdJwtSession)));
        Assert.True(sdJwt.IsValid, Errors(sdJwt));
        Assert.Equal(SdJwtId, sdJwt.CredentialQueryId);

        var strayResult = await Verifier.VerifyAsync(sdJwtSession, Form(sdJwtSession, "credential", RedirectSdJwt(sdJwtSession)));
        var stray = Assert.Single(strayResult.Errors);
        Assert.Equal("response_invalid", stray.Code);
        Assert.Contains("names no Credential Query", stray.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_redirect_seam_refuses_a_query_of_several_credentials_without_readable_ids_even_unasked()
    {
        // VerifyAsync does not call CanVerify for its caller. Two entries sharing an id: an answer under that id
        // cannot be matched to either, so reading it against the first entry would be a guess.
        const string query = """{"credentials":[{"id":"a","format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"}},{"id":"a","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}}]}""";
        var session = await _provider.GetRequiredService<InMemorySessionStore>().CreateAsync(new PresentationRequestOptions
        {
            ClientId = "x509_san_dns:verifier.example",
            Nonce = Tokens.NewNonce(),
            State = Tokens.NewNonce(),
            DcqlQueryJson = query,
            ResponseUri = new Uri("https://verifier.example/verify/callback"),
            ResponseMode = ResponseMode.DirectPost,
            RequestLifetime = TimeSpan.FromMinutes(5),
        });

        var result = await Verifier.VerifyAsync(session, Form(session, "a", RedirectMdoc(session)));

        Assert.Equal(ErrorCodes.RequestUnverifiable, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public async Task Either_answer_completes_a_session_through_the_built_in_callback()
    {
        // The callback's parser is configured for the process (dc+sd-jwt by default) and reads the response before
        // it knows which session it answers, so an mdoc answer verifies only if the session's query decides its format.
        var processor = _provider.GetRequiredService<WalletCallbackProcessor>();
        var store = _provider.GetRequiredService<InMemorySessionStore>();

        foreach (var (key, issue) in new (string, Func<VerificationSession, string>)[] { (MdocId, RedirectMdoc), (SdJwtId, RedirectSdJwt) })
        {
            var session = await RedirectSessionAsync();
            await processor.ProcessAsync(Form(session, key, issue(session)), CancellationToken.None);

            var completed = await store.GetAsync(session.SessionId);
            Assert.Equal(VerificationSessionStatus.Completed, completed!.Status);
            Assert.True(completed.Result!.IsValid, Errors(completed.Result));
            Assert.Equal(key, completed.Result.CredentialQueryId);
        }
    }
}
