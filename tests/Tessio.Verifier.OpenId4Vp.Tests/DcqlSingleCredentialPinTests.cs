namespace Tessio.Verifier.OpenId4Vp.Tests;

/// <summary>
/// The JSON every single-credential builder emits, pinned character for character. Every request this
/// library has sent comes through these builders, so a change in what they emit would reach every wallet
/// at once. Several Credential Queries in one query share the code that writes a Credential Query, and
/// these pins hold the single-credential shape to what it was before that code was shared.
/// </summary>
public sealed class DcqlSingleCredentialPinTests
{
    [Fact]
    public void SdJwtVc_ByName()
    {
        Assert.Equal(
            """{"credentials":[{"id":"credential","format":"dc+sd-jwt","meta":{"vct_values":["https://issuer.example/vct/pid"]},"claims":[{"path":["given_name"]},{"path":["age_over_18"]}]}]}""",
            Dcql.SdJwtVc("https://issuer.example/vct/pid", "given_name", "age_over_18"));
    }

    [Fact]
    public void SdJwtVc_ByName_WithNoClaims_KeepsTheEmptyArray()
    {
        Assert.Equal(
            """{"credentials":[{"id":"credential","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1","urn:eudi:pid:de:1"]},"claims":[]}]}""",
            Dcql.SdJwtVc(["urn:eudi:pid:1", "urn:eudi:pid:de:1"]));
    }

    [Fact]
    public void AgeOver()
    {
        Assert.Equal(
            """{"credentials":[{"id":"credential","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["age_over_18"]}]}]}""",
            Dcql.AgeOver(18, "urn:eudi:pid:1"));
    }

    [Fact]
    public void SdJwtVcByPath_WithClaimSets()
    {
        Assert.Equal(
            """{"credentials":[{"id":"credential","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"id":"over","path":["age_equal_or_over","18"]},{"id":"birth","path":["birthdate"]}],"claim_sets":[["over"],["birth"]]}]}""",
            Dcql.SdJwtVcByPath(
                ["urn:eudi:pid:1"],
                [new DcqlClaim { Id = "over", Path = ["age_equal_or_over", "18"] }, new DcqlClaim { Id = "birth", Path = ["birthdate"] }],
                ["over"],
                ["birth"]));
    }

    [Fact]
    public void Mdoc_ByName()
    {
        Assert.Equal(
            """{"credentials":[{"id":"credential","format":"mso_mdoc","meta":{"doctype_value":"eu.europa.ec.av.1"},"claims":[{"path":["eu.europa.ec.av.1","age_over_18"]}]}]}""",
            Dcql.Mdoc("eu.europa.ec.av.1", "eu.europa.ec.av.1", "age_over_18"));
    }

    [Fact]
    public void MdocByPath_WithIntentToRetainAndClaimSets()
    {
        Assert.Equal(
            """{"credentials":[{"id":"credential","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claims":[{"id":"a","path":["org.iso.18013.5.1","age_over_18"],"intent_to_retain":false},{"id":"b","path":["org.iso.18013.5.1","birth_date"],"intent_to_retain":true}],"claim_sets":[["a"],["b"]]}]}""",
            Dcql.MdocByPath(
                "org.iso.18013.5.1.mDL",
                [
                    new DcqlClaim { Id = "a", Path = ["org.iso.18013.5.1", "age_over_18"], IntentToRetain = false },
                    new DcqlClaim { Id = "b", Path = ["org.iso.18013.5.1", "birth_date"], IntentToRetain = true },
                ],
                ["a"],
                ["b"]));
    }
}
