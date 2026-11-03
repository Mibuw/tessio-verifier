using System.Text.Json.Nodes;
using Tessio.Verifier.Core;

namespace Tessio.Verifier.OpenId4Vp.Tests;

/// <summary>
/// The signature algorithms a request advertises for mdoc. The values are written out here on purpose, so a change
/// to what wallets are told is a change to this file too.
/// </summary>
public sealed class ClientMetadataAlgorithmTests
{
    [Theory]
    [InlineData("issuerauth_alg_values")]
    [InlineData("deviceauth_alg_values")]
    public void AnMdocRequest_AdvertisesEs256AndEsp256(string member)
    {
        // SPEC: OpenID4VP 1.0 Appendix B.2.2. A header of -9 matches only -9, and -9 matches a -7 header on P-256
        // too, so a list of -7 alone turns away a credential signed under -9.
        var metadata = JsonNode.Parse(ClientMetadata.Build("mso_mdoc"))!;

        var values = metadata["vp_formats_supported"]!["mso_mdoc"]![member]!.AsArray().Select(v => (int)v!).ToArray();

        Assert.Equal([-7, -9], values);
    }

    [Fact]
    public void AnMdocRequest_AdvertisesTheListTheVerifiersOwn()
    {
        var metadata = JsonNode.Parse(ClientMetadata.Build("mso_mdoc"))!;

        var values = metadata["vp_formats_supported"]!["mso_mdoc"]!["issuerauth_alg_values"]!.AsArray().Select(v => (int)v!);

        Assert.Equal(CoseAlgorithms.Advertised, values);
    }
}
