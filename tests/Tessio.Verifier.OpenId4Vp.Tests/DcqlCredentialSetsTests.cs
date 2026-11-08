using System.Text.Json;
using System.Text.Json.Nodes;

namespace Tessio.Verifier.OpenId4Vp.Tests;

/// <summary>
/// A DCQL query asking for several Credential Queries, related by credential_sets (OpenID4VP 1.0 section 6.2),
/// as <see cref="Dcql.Query"/> and <see cref="Dcql.AnyOf"/> build it.
/// </summary>
public sealed class DcqlCredentialSetsTests
{
    private const string PidDocType = "eu.europa.ec.eudi.pid.1";
    private const string PidVct = "urn:eudi:pid:1";

    private static DcqlCredentialQuery MdocPid(string id = "pid_mdoc") =>
        DcqlCredentialQuery.Mdoc(id, PidDocType, [new DcqlClaim { Path = [PidDocType, "age_over_18"] }]);

    private static DcqlCredentialQuery SdJwtPid(string id = "pid_sd_jwt") =>
        DcqlCredentialQuery.SdJwtVc(id, [PidVct], [new DcqlClaim { Path = ["age_over_18"] }]);

    [Fact]
    public void AnyOf_WritesBothCredentialQueries_AndOneSetWithEachAsAnOption()
    {
        Assert.Equal(
            """{"credentials":[{"id":"pid_mdoc","format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.eudi.pid.1"},"claims":[{"path":["eu.europa.ec.eudi.pid.1","age_over_18"]}]},{"id":"pid_sd_jwt","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["age_over_18"]}]}],"credential_sets":[{"options":[["pid_mdoc"],["pid_sd_jwt"]]}]}""",
            Dcql.AnyOf(MdocPid(), SdJwtPid()));
    }

    [Fact]
    public void A_set_that_is_not_required_says_so_and_a_required_one_leaves_the_default_unwritten()
    {
        // SPEC: OpenID4VP 1.0 section 6.2, required: "If omitted, the default value is true."
        var query = Dcql.Query(
            [MdocPid(), SdJwtPid(), SdJwtPid("extra")],
            new DcqlCredentialSet { Options = [["pid_mdoc"], ["pid_sd_jwt"]] },
            new DcqlCredentialSet { Options = [["extra"]], Required = false });

        using var document = JsonDocument.Parse(query);
        var sets = document.RootElement.GetProperty("credential_sets");
        Assert.False(sets[0].TryGetProperty("required", out _));
        Assert.False(sets[1].GetProperty("required").GetBoolean());
    }

    [Fact]
    public void Without_sets_no_credential_sets_member_is_written()
    {
        using var document = JsonDocument.Parse(Dcql.Query([MdocPid(), SdJwtPid()]));

        Assert.False(document.RootElement.TryGetProperty("credential_sets", out _));
        Assert.Equal(2, document.RootElement.GetProperty("credentials").GetArrayLength());
    }

    [Fact]
    public void Two_credential_queries_with_one_id_are_refused()
    {
        // SPEC: OpenID4VP 1.0 section 6.1, id: "Within the Authorization Request, the same id MUST NOT be present
        // more than once."
        var e = Assert.Throws<ArgumentException>(() => Dcql.AnyOf(MdocPid("pid"), SdJwtPid("pid")));

        Assert.Equal("credentials", e.ParamName);
    }

    [Theory]
    [InlineData("")]
    [InlineData("pid mdoc")]
    [InlineData("pid.mdoc")]
    [InlineData("pidé")]
    public void A_credential_query_id_section_6_1_does_not_allow_is_refused(string id)
    {
        Assert.Equal("id", Assert.Throws<ArgumentException>(() => MdocPid(id)).ParamName);
    }

    [Fact]
    public void An_option_naming_an_id_no_credential_query_carries_is_refused()
    {
        var e = Assert.Throws<ArgumentException>(() => Dcql.Query(
            [MdocPid(), SdJwtPid()],
            new DcqlCredentialSet { Options = [["pid_mdoc"], ["pid_sd_jwt"], ["mdl"]] }));

        Assert.Equal("credentialSets", e.ParamName);
        Assert.Contains("'mdl'", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_set_with_no_options_or_an_empty_option_is_refused()
    {
        Assert.Throws<ArgumentException>(() => Dcql.Query([MdocPid()], new DcqlCredentialSet { Options = [] }));
        Assert.Throws<ArgumentException>(() => Dcql.Query([MdocPid()], new DcqlCredentialSet { Options = [["pid_mdoc"], []] }));
    }

    [Fact]
    public void A_credential_query_no_option_names_is_refused_because_it_would_never_be_asked_for()
    {
        var e = Assert.Throws<ArgumentException>(() => Dcql.Query(
            [MdocPid(), SdJwtPid()],
            new DcqlCredentialSet { Options = [["pid_mdoc"]] }));

        Assert.Contains("'pid_sd_jwt'", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnyOf_needs_two_alternatives_and_Query_needs_one_credential()
    {
        Assert.Throws<ArgumentException>(() => Dcql.AnyOf(MdocPid()));
        Assert.Throws<ArgumentException>(() => Dcql.Query([]));
    }

    [Fact]
    public void A_credential_query_is_validated_by_the_single_credential_rules()
    {
        // A three-segment mdoc path, refused by section 7.2 as MdocByPath refuses it.
        Assert.Throws<ArgumentException>(() =>
            DcqlCredentialQuery.Mdoc("pid_mdoc", PidDocType, [new DcqlClaim { Path = [PidDocType, "a", "b"] }]));
        Assert.Throws<ArgumentException>(() => DcqlCredentialQuery.SdJwtVc("pid_sd_jwt", [], [new DcqlClaim { Path = ["a"] }]));
    }

    [Fact]
    public void A_query_built_from_the_same_entry_twice_does_not_share_its_json()
    {
        var pid = MdocPid();
        var first = JsonNode.Parse(Dcql.AnyOf(pid, SdJwtPid()))!;
        var second = JsonNode.Parse(Dcql.AnyOf(pid, SdJwtPid()))!;

        Assert.Equal(first.ToJsonString(), second.ToJsonString());
    }

    [Fact]
    public void ClientMetadata_for_both_formats_advertises_both_once()
    {
        using var document = JsonDocument.Parse(ClientMetadata.BuildForFormats(["mso_mdoc", "dc+sd-jwt", "mso_mdoc"]));
        var formats = document.RootElement.GetProperty("vp_formats_supported");

        Assert.Equal(["mso_mdoc", "dc+sd-jwt"], formats.EnumerateObject().Select(p => p.Name));
        Assert.Equal(
            JsonDocument.Parse(ClientMetadata.Build("mso_mdoc")).RootElement.GetProperty("vp_formats_supported").GetProperty("mso_mdoc").GetRawText(),
            formats.GetProperty("mso_mdoc").GetRawText());
        Assert.Equal(
            JsonDocument.Parse(ClientMetadata.Build("dc+sd-jwt")).RootElement.GetProperty("vp_formats_supported").GetProperty("dc+sd-jwt").GetRawText(),
            formats.GetProperty("dc+sd-jwt").GetRawText());
    }

    [Fact]
    public void ClientMetadata_for_one_format_through_the_list_is_the_single_format_metadata()
    {
        var jwk = new JsonObject { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = "x", ["y"] = "y", ["kid"] = "1" };

        Assert.Equal(ClientMetadata.Build("mso_mdoc", jwk), ClientMetadata.BuildForFormats(["mso_mdoc"], jwk));
    }

    [Theory]
    [InlineData("jwt_vc_json")]
    [InlineData("vc+sd-jwt")]
    public void ClientMetadata_for_a_format_it_does_not_know_is_refused(string format)
    {
        Assert.Throws<ArgumentException>(() => ClientMetadata.BuildForFormats(["mso_mdoc", format]));
    }
}
