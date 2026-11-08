using System.Text.Json.Nodes;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// Builders for OpenID4VP DCQL (Digital Credentials Query Language) queries, producing the JSON string
/// expected by <see cref="PresentationRequestOptions.DcqlQueryJson"/>.
/// </summary>
/// <remarks>
/// <para>
/// Two levels of builder, and the difference is how a claim is ADDRESSED, not how many credential types
/// a query accepts. The <c>params string[]</c> overloads name claims, which assumes every claim sits at
/// the top level of its credential. The <see cref="DcqlClaim"/> overloads address claims by PATH and
/// accept claim sets, which is what a nested claim or a preference order over alternatives needs. Both
/// levels can name several credential types in one query.
/// </para>
/// <para>
/// This used to tell callers to hand-write the JSON for a nested path or a claim set. A builder that
/// covers only the easy shape does not prevent the hard one, it only decides where the hard one gets
/// written: in a caller, where the path the query asks for sits apart from the code that reads the
/// answer back, and nothing compares the two. Still hand-written, because nothing asks for it yet:
/// claim value constraints.
/// </para>
/// <para>
/// Several Credential Queries in one query, offered as alternatives or required together, are built by
/// <see cref="Query"/> and <see cref="AnyOf"/> from <see cref="DcqlCredentialQuery"/> entries.
/// </para>
/// </remarks>
// SPEC: OpenID4VP 1.0 uses DCQL, not Presentation Exchange.
public static partial class Dcql
{
    // SPEC: SD-JWT VC credential format identifier is "dc+sd-jwt" (not the legacy "vc+sd-jwt").
    internal const string SdJwtVcFormat = "dc+sd-jwt";
    internal const string MdocFormat = "mso_mdoc";

    /// <summary>The credential id this builder puts on a single-credential query.</summary>
    /// <remarks>
    /// Nothing on the verify side REQUIRES this value. <c>WalletResponseParser.ExtractCredentials</c>
    /// enumerates every property of the <c>vp_token</c> object whatever its key, per OpenID4VP 1.0
    /// section 8.1, so a query using other ids parses fine. Said the other way because the previous
    /// wording said the pipeline "expects" it, which reads as a constraint that is not there.
    /// </remarks>
    public const string DefaultCredentialId = "credential";

    /// <summary>
    /// A query for a single SD-JWT VC credential of type <paramref name="vct"/>, requesting each of
    /// <paramref name="claims"/> by selective disclosure. Each entry is a top-level claim name.
    /// </summary>
    public static string SdJwtVc(string vct, params string[] claims)
    {
        ArgumentException.ThrowIfNullOrEmpty(vct);
        return SdJwtVc([vct], claims);
    }

    /// <summary>
    /// A query for a single SD-JWT VC credential of ANY of <paramref name="vctValues"/>, requesting each
    /// of <paramref name="claims"/> by selective disclosure. Use this where one credential entry should
    /// accept several types, for example a base PID type and a member state's own.
    /// </summary>
    /// <remarks>
    /// SPEC: OpenID4VP 1.0 §B.3.5 defines <c>vct_values</c> as "A non-empty array of strings that
    /// specifies allowed values for the type of the requested Verifiable Credential", so an empty list
    /// is refused here rather than emitted. The verifier accepts a credential whose <c>vct</c> is any
    /// member of the array it sent.
    /// </remarks>
    public static string SdJwtVc(IReadOnlyList<string> vctValues, params string[] claims)
    {
        ArgumentNullException.ThrowIfNull(claims);

        // allowEmptyClaims, and only here. §6.1 says `claims` is "a non-empty array", so the path-based
        // builders refuse an empty one. This overload has emitted "claims": [] since it shipped and is
        // consumed outside this repository, so it keeps doing so.
        return SdJwtVcQuery(vctValues, DcqlClaimsQuery.TopLevel(claims), [], allowEmptyClaims: true);
    }

    /// <summary>
    /// A query for a single SD-JWT VC credential of ANY of <paramref name="vctValues"/>, requesting
    /// <paramref name="claims"/> by path, optionally preferring one combination of them over another.
    /// </summary>
    /// <param name="vctValues">Credential types to accept. At least one, any of which matches.</param>
    /// <param name="claims">Every claim the query may ask for, each addressed by path.</param>
    /// <param name="claimSets">
    /// Each entry is a list of <see cref="DcqlClaim.Id"/> values, and ORDER IS THE PREFERENCE. Pass
    /// none to request every claim.
    /// </param>
    /// <remarks>
    /// SPEC: OpenID4VP 1.0 section 6.4.1. With both <c>claims</c> and <c>claim_sets</c> present the
    /// verifier requests ONE combination, the wallet SHOULD return the first option it can satisfy,
    /// and if it can satisfy none it MUST NOT return any claims. That is what expresses "this claim,
    /// or failing that this one", which no list of claims alone can say.
    /// </remarks>
    public static string SdJwtVcByPath(
        IReadOnlyList<string> vctValues, IReadOnlyList<DcqlClaim> claims, params string[][] claimSets)
        => SdJwtVcQuery(vctValues, claims, claimSets, allowEmptyClaims: false);

    private static string SdJwtVcQuery(
        IReadOnlyList<string> vctValues,
        IReadOnlyList<DcqlClaim> claims,
        string[][] claimSets,
        bool allowEmptyClaims)
        => SingleCredential(SdJwtVcCredential(DefaultCredentialId, vctValues, claims, claimSets, allowEmptyClaims));

    /// <summary>
    /// One SD-JWT VC Credential Query object, validated. The single-credential builders and
    /// <see cref="DcqlCredentialQuery.SdJwtVc"/> share it, so a Credential Query is written one way.
    /// </summary>
    internal static JsonObject SdJwtVcCredential(
        string id,
        IReadOnlyList<string> vctValues,
        IReadOnlyList<DcqlClaim> claims,
        string[][] claimSets,
        bool allowEmptyClaims)
    {
        ArgumentNullException.ThrowIfNull(vctValues);
        if (vctValues.Count == 0)
        {
            throw new ArgumentException("A DCQL query needs at least one vct value.", nameof(vctValues));
        }

        var values = new JsonArray();
        foreach (var vct in vctValues)
        {
            ArgumentException.ThrowIfNullOrEmpty(vct);
            values.Add(vct);
        }

        return CredentialObject(
            id,
            SdJwtVcFormat,
            new JsonObject { ["vct_values"] = values },
            DcqlClaimsQuery.ClaimsArray(claims, claimSets, isMdoc: false, allowEmptyClaims),
            DcqlClaimsQuery.ClaimSetsArray(claimSets));
    }

    /// <summary>
    /// A query for a single mdoc credential of document type <paramref name="docType"/>, requesting
    /// <paramref name="claims"/> by path, optionally preferring one combination of them over another.
    /// </summary>
    /// <param name="docType">The mdoc document type, which becomes <c>meta.doctype_value</c>.</param>
    /// <param name="claims">
    /// Every claim the query may ask for. Each path is the full <c>[namespace, element]</c> of §7.2,
    /// because a caller spanning two namespaces cannot say so through a single namespace parameter.
    /// <see cref="Mdoc(string, string, string[])"/> keeps that parameter and builds these paths for
    /// you, since a caller naming elements in one namespace cannot have that problem.
    /// </param>
    /// <param name="claimSets">
    /// Each entry is a list of <see cref="DcqlClaim.Id"/> values, and ORDER IS THE PREFERENCE. Pass
    /// none to request every claim.
    /// </param>
    public static string MdocByPath(
        string docType, IReadOnlyList<DcqlClaim> claims, params string[][] claimSets)
        => MdocQuery(docType, claims, claimSets, allowEmptyClaims: false);

    private static string MdocQuery(
        string docType, IReadOnlyList<DcqlClaim> claims, string[][] claimSets, bool allowEmptyClaims)
        => SingleCredential(MdocCredential(DefaultCredentialId, docType, claims, claimSets, allowEmptyClaims));

    /// <summary>
    /// One mdoc Credential Query object, validated. The single-credential builders and
    /// <see cref="DcqlCredentialQuery.Mdoc"/> share it, so a Credential Query is written one way.
    /// </summary>
    internal static JsonObject MdocCredential(
        string id, string docType, IReadOnlyList<DcqlClaim> claims, string[][] claimSets, bool allowEmptyClaims)
    {
        ArgumentException.ThrowIfNullOrEmpty(docType);

        return CredentialObject(
            id,
            MdocFormat,
            new JsonObject { ["doctype_value"] = docType },
            DcqlClaimsQuery.ClaimsArray(claims, claimSets, isMdoc: true, allowEmptyClaims),
            DcqlClaimsQuery.ClaimSetsArray(claimSets));
    }

    /// <summary>
    /// Convenience for the common age check: a single SD-JWT VC credential of type <paramref name="vct"/>
    /// requesting the boolean <c>age_over_{age}</c> claim.
    /// </summary>
    public static string AgeOver(int age, string vct)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(age);
        return SdJwtVc(vct, $"age_over_{age}");
    }

    /// <summary>
    /// A query for a single mdoc credential of document type <paramref name="docType"/>, requesting each
    /// of <paramref name="elements"/> from <paramref name="nameSpace"/> (mdoc DCQL paths are
    /// <c>[namespace, element]</c>).
    /// </summary>
    // SPEC: OpenID4VP 1.0 §B.2.3 gives an mdoc query meta.doctype_value. The two-element claim path is
    // §7.2, NOT Annex B.2: "A claims path pointer into an mdoc contains two elements of type string.
    // The first element refers to a namespace and the second element refers to a data element
    // identifier." Annex B.2 defines the mdoc format's own parameters and says nothing about path shape.
    public static string Mdoc(string docType, string nameSpace, params string[] elements)
    {
        ArgumentException.ThrowIfNullOrEmpty(nameSpace);
        ArgumentNullException.ThrowIfNull(elements);

        // allowEmptyClaims for the same compatibility reason as the SD-JWT VC overload above.
        return MdocQuery(
            docType,
            [.. elements.Select(element => new DcqlClaim { Path = [nameSpace, element] })],
            [],
            allowEmptyClaims: true);
    }

    private static string SingleCredential(JsonObject credential)
    {
        var query = new JsonObject { ["credentials"] = new JsonArray(credential) };
        return query.ToJsonString(JsonDefaults.Relaxed);
    }

    /// <summary>A Credential Query object, its members in the order every builder has always written them.</summary>
    private static JsonObject CredentialObject(
        string id, string format, JsonObject meta, JsonArray claims, JsonArray? claimSets)
    {
        // SPEC: OpenID4VP 1.0 section 6.1, id: "The value MUST be a non-empty string consisting of
        // alphanumeric, underscore (_), or hyphen (-) characters."
        if (!DcqlClaimsQuery.IsWellFormedId(id))
        {
            throw new ArgumentException(
                $"'{id}' is not a usable Credential Query id. Only letters, digits, underscore and hyphen are "
                + "allowed, and it cannot be empty (OpenID4VP 1.0 section 6.1).",
                nameof(id));
        }

        var credential = new JsonObject
        {
            ["id"] = id,
            ["format"] = format,
            ["meta"] = meta,
            ["claims"] = claims,
        };

        // Omitted rather than emitted empty. Section 6.4.1 gives claim_sets a meaning, "request one of
        // these combinations", and an empty array would say every combination is unacceptable.
        if (claimSets is not null)
        {
            credential["claim_sets"] = claimSets;
        }

        return credential;
    }
}
