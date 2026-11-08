// What belongs in this file: one Credential Query to place beside others in a single DCQL query. The query
// around it, and the credential sets that relate its entries, are Dcql's job.
using System.Text.Json.Nodes;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// One Credential Query, with an id of its own, for a DCQL query that asks for several credentials:
/// pass it to <see cref="Dcql.Query"/> or <see cref="Dcql.AnyOf"/>.
/// </summary>
/// <remarks>
/// <para>
/// The id is what ties the request to the answer. The wallet keys each presentation in <c>vp_token</c> by the
/// id of the Credential Query it answers (OpenID4VP 1.0 section 8.1), so the verifier reads that presentation
/// in this entry's format and checks it against this entry's type. Pick an id that says which alternative it
/// is, such as <c>pid_mdoc</c> and <c>pid_sd_jwt</c>, because the verification result reports it.
/// </para>
/// <para>
/// Validated when it is made, by the rules the single-credential builders apply to theirs: the claims, the
/// claim sets and the type are checked here, and the id by section 6.1.
/// </para>
/// </remarks>
// SPEC: OpenID4VP 1.0 section 6.1, Credential Query.
public sealed class DcqlCredentialQuery
{
    private readonly JsonObject _json;

    private DcqlCredentialQuery(JsonObject json)
    {
        _json = json;
        Id = json["id"]!.GetValue<string>();
    }

    /// <summary>The Credential Query id, which keys this entry's answer in <c>vp_token</c>.</summary>
    public string Id { get; }

    /// <summary>
    /// An SD-JWT VC Credential Query of ANY of <paramref name="vctValues"/>, requesting <paramref name="claims"/>
    /// by path, as <see cref="Dcql.SdJwtVcByPath"/> builds it but under the id <paramref name="id"/>.
    /// </summary>
    /// <param name="id">The Credential Query id: letters, digits, underscore and hyphen, unique in the query.</param>
    /// <param name="vctValues">Credential types to accept. At least one, any of which matches.</param>
    /// <param name="claims">Every claim the entry may ask for, each addressed by path. At least one.</param>
    /// <param name="claimSets">
    /// Each entry is a list of <see cref="DcqlClaim.Id"/> values, and ORDER IS THE PREFERENCE. Pass none to
    /// request every claim.
    /// </param>
    /// <exception cref="ArgumentException">The id, a type, a claim or a claim set breaks a rule the specification states.</exception>
    public static DcqlCredentialQuery SdJwtVc(
        string id, IReadOnlyList<string> vctValues, IReadOnlyList<DcqlClaim> claims, params string[][] claimSets) =>
        new(Dcql.SdJwtVcCredential(id, vctValues, claims, claimSets, allowEmptyClaims: false));

    /// <summary>
    /// An mdoc Credential Query of document type <paramref name="docType"/>, requesting <paramref name="claims"/>
    /// by path, as <see cref="Dcql.MdocByPath"/> builds it but under the id <paramref name="id"/>.
    /// </summary>
    /// <param name="id">The Credential Query id: letters, digits, underscore and hyphen, unique in the query.</param>
    /// <param name="docType">The mdoc document type, which becomes <c>meta.doctype_value</c>.</param>
    /// <param name="claims">
    /// Every claim the entry may ask for, each path the full <c>[namespace, element]</c> of section 7.2. At least one.
    /// </param>
    /// <param name="claimSets">
    /// Each entry is a list of <see cref="DcqlClaim.Id"/> values, and ORDER IS THE PREFERENCE. Pass none to
    /// request every claim.
    /// </param>
    /// <exception cref="ArgumentException">The id, the type, a claim or a claim set breaks a rule the specification states.</exception>
    public static DcqlCredentialQuery Mdoc(
        string id, string docType, IReadOnlyList<DcqlClaim> claims, params string[][] claimSets) =>
        new(Dcql.MdocCredential(id, docType, claims, claimSets, allowEmptyClaims: false));

    /// <summary>A copy of the entry's JSON, so a query built from it cannot change this one.</summary>
    internal JsonObject ToJson() => (JsonObject)_json.DeepClone();
}
