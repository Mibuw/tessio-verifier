using System.Text.Json;
using Tessio.Verifier.Core;

namespace Tessio.Verifier.OpenId4Vp.Tests;

/// <summary>
/// Reading a <c>vp_token</c> against the DCQL query it answers (<see cref="WalletResponseParserOptions.DcqlQueryJson"/>):
/// each presentation in the format of the Credential Query its key names (OpenID4VP 1.0 section 8.1), and the keys
/// held to the combinations the query requested (section 6.4.2).
/// </summary>
public sealed class CredentialSetResponseParsingTests
{
    private const string PidDocType = "eu.europa.ec.eudi.pid.1";
    private const string Presentation = "eyJoZWFkZXIifQ.eyJwYXlsb2FkIn0.c2ln~";

    private static readonly string PidQuery = Dcql.AnyOf(
        DcqlCredentialQuery.Mdoc("pid_mdoc", PidDocType, [new DcqlClaim { Path = [PidDocType, "age_over_18"] }]),
        DcqlCredentialQuery.SdJwtVc("pid_sd_jwt", ["urn:eudi:pid:1"], [new DcqlClaim { Path = ["age_over_18"] }]));

    private static WalletResponseData Form(string vpToken) => new()
    {
        ContentType = "application/x-www-form-urlencoded",
        Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal) { ["vp_token"] = [vpToken] },
        Body = ReadOnlyMemory<byte>.Empty,
    };

    private static string VpToken(params (string Key, string[] Presentations)[] entries) =>
        JsonSerializer.Serialize(entries.ToDictionary(e => e.Key, e => e.Presentations));

    private static Task<IReadOnlyList<PresentedCredential>> Parse(string query, string vpToken) =>
        new WalletResponseParser(new WalletResponseParserOptions { DcqlQueryJson = query }).ParseAsync(Form(vpToken));

    [Theory]
    [InlineData("pid_mdoc", "mso_mdoc")]
    [InlineData("pid_sd_jwt", "dc+sd-jwt")]
    public async Task Each_answer_is_read_in_the_format_of_the_credential_query_its_key_names(string id, string format)
    {
        var credential = Assert.Single(await Parse(PidQuery, VpToken((id, [Presentation]))));

        Assert.Equal(format, credential.Format);
        Assert.Equal(id, credential.CredentialQueryId);
        Assert.Equal(Presentation, credential.RawValue);
    }

    [Fact]
    public async Task A_key_naming_no_credential_query_is_refused()
    {
        var e = await Assert.ThrowsAsync<WalletResponseException>(() => Parse(PidQuery, VpToken(("credential", [Presentation]))));

        Assert.Contains("names no Credential Query", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_empty_array_under_a_key_is_refused_rather_than_read_as_absent()
    {
        // OpenID4VP 1.0 section 8.1: each value is "an array of one or more Presentations", and an optional Credential
        // Query with no matching Credentials has no entry at all. So the other alternative answering beside an empty
        // one does not make it acceptable.
        var e = await Assert.ThrowsAsync<WalletResponseException>(
            () => Parse(PidQuery, VpToken(("pid_mdoc", []), ("pid_sd_jwt", [Presentation]))));

        Assert.Contains("no presentation under it", e.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("pid_mdoc", e.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("""{"pid_mdoc":[[]],"pid_sd_jwt":["a.b.c~"]}""")]
    [InlineData("""{"pid_mdoc":[[],[[]]],"pid_sd_jwt":["a.b.c~"]}""")]
    public async Task A_key_holding_only_nested_empty_arrays_is_refused_too(string vpToken)
    {
        var e = await Assert.ThrowsAsync<WalletResponseException>(() => Parse(PidQuery, vpToken));

        Assert.Contains("no presentation under it", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_empty_key_refusal_applies_without_a_configured_query_as_well()
    {
        var e = await Assert.ThrowsAsync<WalletResponseException>(
            () => new WalletResponseParser().ParseAsync(Form("""{"a":[],"b":["a.b.c~"]}""")));

        Assert.Contains("no presentation under it", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_answer_satisfying_no_option_of_a_required_set_is_refused()
    {
        var query = Dcql.Query(
            [
                DcqlCredentialQuery.Mdoc("pid", PidDocType, [new DcqlClaim { Path = [PidDocType, "age_over_18"] }]),
                DcqlCredentialQuery.Mdoc("mdl", "org.iso.18013.5.1.mDL", [new DcqlClaim { Path = ["org.iso.18013.5.1", "age_over_18"] }]),
                DcqlCredentialQuery.SdJwtVc("age", ["urn:eudi:pid:1"], [new DcqlClaim { Path = ["age_over_18"] }]),
            ],
            new DcqlCredentialSet { Options = [["pid", "mdl"], ["age"]] });

        // Half of the first option and nothing of the second.
        var e = await Assert.ThrowsAsync<WalletResponseException>(() => Parse(query, VpToken(("pid", [Presentation]))));
        Assert.Contains("no option", e.Message, StringComparison.Ordinal);

        // Either whole option answers it.
        Assert.Equal(2, (await Parse(query, VpToken(("pid", [Presentation]), ("mdl", [Presentation])))).Count);
        Assert.Single(await Parse(query, VpToken(("age", [Presentation]))));
    }

    [Fact]
    public async Task A_presentation_outside_every_option_it_completes_is_refused()
    {
        var query = Dcql.Query(
            [
                DcqlCredentialQuery.Mdoc("pid", PidDocType, [new DcqlClaim { Path = [PidDocType, "age_over_18"] }]),
                DcqlCredentialQuery.Mdoc("mdl", "org.iso.18013.5.1.mDL", [new DcqlClaim { Path = ["org.iso.18013.5.1", "age_over_18"] }]),
                DcqlCredentialQuery.SdJwtVc("age", ["urn:eudi:pid:1"], [new DcqlClaim { Path = ["age_over_18"] }]),
            ],
            new DcqlCredentialSet { Options = [["age"]] },
            new DcqlCredentialSet { Options = [["pid", "mdl"]], Required = false });

        // The optional set may go unanswered.
        Assert.Single(await Parse(query, VpToken(("age", [Presentation]))));

        // Half of its option is not an answer to it.
        await Assert.ThrowsAsync<WalletResponseException>(() => Parse(query, VpToken(("age", [Presentation]), ("pid", [Presentation]))));
    }

    [Fact]
    public async Task Without_credential_sets_every_credential_query_must_be_answered()
    {
        // SPEC: OpenID4VP 1.0 section 6.4.2: "If credential_sets is not provided, the Verifier requests presentations
        // for all Credentials in credentials to be returned."
        var query = Dcql.Query(
            [
                DcqlCredentialQuery.Mdoc("pid_mdoc", PidDocType, [new DcqlClaim { Path = [PidDocType, "age_over_18"] }]),
                DcqlCredentialQuery.SdJwtVc("pid_sd_jwt", ["urn:eudi:pid:1"], [new DcqlClaim { Path = ["age_over_18"] }]),
            ]);

        var e = await Assert.ThrowsAsync<WalletResponseException>(() => Parse(query, VpToken(("pid_mdoc", [Presentation]))));
        Assert.Contains("'pid_sd_jwt'", e.Message, StringComparison.Ordinal);
        Assert.Equal(2, (await Parse(query, VpToken(("pid_mdoc", [Presentation]), ("pid_sd_jwt", [Presentation])))).Count);
    }

    [Fact]
    public async Task Two_presentations_for_a_credential_query_that_does_not_allow_multiple_are_refused()
    {
        // SPEC: OpenID4VP 1.0 section 8.1: "When multiple is omitted, or set to false, the array MUST contain only one
        // Presentation."
        await Assert.ThrowsAsync<WalletResponseException>(() => Parse(PidQuery, VpToken(("pid_mdoc", [Presentation, Presentation]))));

        var multiple = PidQuery.Replace("\"id\":\"pid_mdoc\",", "\"id\":\"pid_mdoc\",\"multiple\":true,", StringComparison.Ordinal);
        Assert.Equal(2, (await Parse(multiple, VpToken(("pid_mdoc", [Presentation, Presentation])))).Count);
    }

    [Fact]
    public async Task A_bare_presentation_answers_the_only_credential_query_and_is_refused_where_there_are_several()
    {
        var single = Assert.Single(await Parse(Dcql.Mdoc(PidDocType, PidDocType, "age_over_18"), Presentation));
        Assert.Equal(Dcql.DefaultCredentialId, single.CredentialQueryId);
        Assert.Equal("mso_mdoc", single.Format);

        await Assert.ThrowsAsync<WalletResponseException>(() => Parse(PidQuery, Presentation));
    }

    [Fact]
    public async Task Without_a_query_the_configured_format_is_kept_and_the_key_is_reported()
    {
        var parser = new WalletResponseParser(new WalletResponseParserOptions { PresentationFormat = "mso_mdoc" });

        var credential = Assert.Single(await parser.ParseAsync(Form(VpToken(("anything", [Presentation])))));

        Assert.Equal("mso_mdoc", credential.Format);
        Assert.Equal("anything", credential.CredentialQueryId);
        Assert.Null(Assert.Single(await parser.ParseAsync(Form(Presentation))).CredentialQueryId);
    }

    [Fact]
    public async Task A_credential_query_naming_no_format_falls_back_to_the_configured_one()
    {
        const string query = """{"credentials":[{"id":"a","meta":{"vct_values":["urn:x"]}}]}""";
        var parser = new WalletResponseParser(new WalletResponseParserOptions { PresentationFormat = "mso_mdoc", DcqlQueryJson = query });

        Assert.Equal("mso_mdoc", Assert.Single(await parser.ParseAsync(Form(VpToken(("a", [Presentation]))))).Format);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("""{"credentials":[]}""")]
    [InlineData("""{"credentials":[{"format":"mso_mdoc"}]}""")]
    [InlineData("""{"credentials":[{"id":"a b","format":"mso_mdoc"}]}""")]
    [InlineData("""{"credentials":[{"id":"a","format":"mso_mdoc"},{"id":"a","format":"dc+sd-jwt"}]}""")]
    [InlineData("""{"credentials":[{"id":"a","format":"mso_mdoc","multiple":"yes"}]}""")]
    [InlineData("""{"credentials":[{"id":"a","format":"mso_mdoc"}],"credential_sets":[]}""")]
    [InlineData("""{"credentials":[{"id":"a","format":"mso_mdoc"}],"credential_sets":[{"options":[["b"]]}]}""")]
    [InlineData("""{"credentials":[{"id":"a","format":"mso_mdoc"}],"credential_sets":[{"options":[["a"]],"required":"no"}]}""")]
    [InlineData("""{"credentials":[{"id":"a","format":"mso_mdoc"},{"id":"b","meta":{"vct_values":["urn:x"]}}],"credential_sets":[{"options":[["a"],["b"]]}]}""")]
    [InlineData("""{"credentials":[{"id":"a","meta":{"vct_values":["urn:x"]}}],"credential_sets":[{"options":[["a"]]}]}""")]
    public void A_configured_query_the_parser_cannot_read_is_refused_when_the_parser_is_made(string query)
    {
        // The last two name no format on an entry of a query asking for several credentials, which would leave its
        // answer read in the configured format whichever entry it answers.
        Assert.Equal("options", Assert.Throws<ArgumentException>(
            () => new WalletResponseParser(new WalletResponseParserOptions { DcqlQueryJson = query })).ParamName);
    }

    [Fact]
    public async Task A_query_made_unreadable_after_construction_fails_every_parse_before_the_response_is_read()
    {
        var options = new WalletResponseParserOptions { DcqlQueryJson = PidQuery };
        var parser = new WalletResponseParser(options);
        options.DcqlQueryJson = "not json";

        // A response that is itself malformed: the configuration error is reported, not the wallet's.
        await Assert.ThrowsAsync<InvalidOperationException>(() => parser.ParseAsync(Form("{")));
        await Assert.ThrowsAsync<InvalidOperationException>(() => parser.ParseDcApiAsync("not json either"));
    }

    [Fact]
    public async Task The_digital_credentials_api_response_is_read_against_the_query_too()
    {
        var parser = new WalletResponseParser(new WalletResponseParserOptions { DcqlQueryJson = PidQuery });
        var data = JsonSerializer.Serialize(new { vp_token = new Dictionary<string, string[]> { ["pid_mdoc"] = [Presentation] } });

        var credential = Assert.Single((await parser.ParseDcApiAsync(data)).Credentials);
        Assert.Equal("mso_mdoc", credential.Format);

        var stray = JsonSerializer.Serialize(new { vp_token = new Dictionary<string, string[]> { ["other"] = [Presentation] } });
        await Assert.ThrowsAsync<WalletResponseException>(() => parser.ParseDcApiAsync(stray));
    }
}
