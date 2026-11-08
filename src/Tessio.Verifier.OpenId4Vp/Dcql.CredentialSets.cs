// What belongs here: a DCQL query asking for several Credential Queries at once, and the credential_sets that
// say which combinations of them answer it. One Credential Query on its own is DcqlCredentialQuery's job.
using System.Text.Json.Nodes;

namespace Tessio.Verifier.OpenId4Vp;

public static partial class Dcql
{
    /// <summary>
    /// A query asking for one of <paramref name="alternatives"/>, whichever the wallet holds: for example a PID as
    /// an mdoc or as an SD-JWT VC. One credential set lists each Credential Query as an option of its own.
    /// </summary>
    /// <param name="alternatives">At least two Credential Queries with distinct ids.</param>
    /// <remarks>
    /// <para>
    /// SPEC: OpenID4VP 1.0 section 6.2: each option is "a list of Credential Query identifiers representing one set
    /// of Credentials that satisfies the use case", and section 6.4.2 has the wallet "return presentations of a set
    /// of Credentials that match to one of the options". The specification gives the order of options no meaning:
    /// a preference order is stated only for <c>claim_sets</c> (section 6.4.1), and section 6.4.3 expects the
    /// wallet to let its user choose when several options can be satisfied.
    /// </para>
    /// <para>
    /// One query rather than one request per credential, because some wallets answer only one request of several
    /// handed to a single Digital Credentials API call. The answer verifies in the format of the Credential Query
    /// its <c>vp_token</c> key names, and the verification result reports that id.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentException">Fewer than two alternatives are given, or two share an id.</exception>
    public static string AnyOf(params DcqlCredentialQuery[] alternatives)
    {
        ArgumentNullException.ThrowIfNull(alternatives);
        if (alternatives.Length < 2)
        {
            throw new ArgumentException(
                "Alternatives need at least two Credential Queries. For one, use a single-credential builder.",
                nameof(alternatives));
        }

        foreach (var alternative in alternatives)
        {
            ArgumentNullException.ThrowIfNull(alternative, nameof(alternatives));
        }

        return Query(
            alternatives,
            new DcqlCredentialSet { Options = [.. alternatives.Select(static alternative => (IReadOnlyList<string>)[alternative.Id])] });
    }

    /// <summary>
    /// A query asking for <paramref name="credentials"/>, with <paramref name="credentialSets"/> saying which
    /// combinations of them answer it. With no credential sets every Credential Query is requested.
    /// </summary>
    /// <param name="credentials">The Credential Queries, at least one, each with an id no other carries.</param>
    /// <param name="credentialSets">
    /// The credential sets. Each set's options are lists of Credential Query ids; the wallet answers a set with every
    /// credential of one option. A set is required unless <see cref="DcqlCredentialSet.Required"/> is false.
    /// </param>
    /// <remarks>
    /// <para>
    /// SPEC: OpenID4VP 1.0 section 6.4.2: "If credential_sets is not provided, the Verifier requests presentations
    /// for all Credentials in credentials to be returned. Otherwise, the Verifier requests presentations of
    /// Credentials to be returned satisfying all of the Credential Set Queries in the credential_sets array where
    /// the required attribute is true or omitted, and optionally, any of the other Credential Set Queries."
    /// </para>
    /// <para>
    /// A Credential Query that no option names is refused. That is this library's rule, inferred from section 6.4.2
    /// rather than stated there, by the reasoning that refuses a claim no claim set names: with credential sets
    /// present the verifier requests only what they list, so such an entry is never asked for, and nothing about the
    /// JSON would show it.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentException">
    /// No credential is given, two share an id, a credential set or option is empty or names an id no Credential
    /// Query carries, or a Credential Query is in no option.
    /// </exception>
    public static string Query(IReadOnlyList<DcqlCredentialQuery> credentials, params DcqlCredentialSet[] credentialSets)
    {
        ArgumentNullException.ThrowIfNull(credentials);
        ArgumentNullException.ThrowIfNull(credentialSets);

        // SPEC: OpenID4VP 1.0 section 6, credentials: "REQUIRED. A non-empty array of Credential Queries".
        if (credentials.Count == 0)
        {
            throw new ArgumentException("A DCQL query needs at least one Credential Query.", nameof(credentials));
        }

        var ids = new HashSet<string>(StringComparer.Ordinal);
        var entries = new JsonArray();
        foreach (var credential in credentials)
        {
            ArgumentNullException.ThrowIfNull(credential, nameof(credentials));

            // SPEC: OpenID4VP 1.0 section 6.1, id: "Within the Authorization Request, the same id MUST NOT be
            // present more than once."
            if (!ids.Add(credential.Id))
            {
                throw new ArgumentException(
                    $"Two Credential Queries share the id '{credential.Id}' (OpenID4VP 1.0 section 6.1).", nameof(credentials));
            }

            entries.Add(credential.ToJson());
        }

        var query = new JsonObject { ["credentials"] = entries };

        // Omitted rather than emitted empty. Section 6 makes credential_sets "A non-empty array" when present.
        if (credentialSets.Length == 0)
        {
            return query.ToJsonString(JsonDefaults.Relaxed);
        }

        var options = new List<IReadOnlyList<IReadOnlyList<string>>>(credentialSets.Length);
        foreach (var set in credentialSets)
        {
            ArgumentNullException.ThrowIfNull(set, nameof(credentialSets));
            ArgumentNullException.ThrowIfNull(set.Options, nameof(credentialSets));
            options.Add(set.Options);
        }

        if (DcqlCredentialSetRules.Problem(ids, options) is { } problem)
        {
            throw new ArgumentException(problem, nameof(credentialSets));
        }

        var named = options.SelectMany(static set => set).SelectMany(static option => option).ToHashSet(StringComparer.Ordinal);
        if (credentials.FirstOrDefault(credential => !named.Contains(credential.Id)) is { } unnamed)
        {
            throw new ArgumentException(
                $"The Credential Query '{unnamed.Id}' is in no credential set option, so this query would never ask for "
                + "it. This library refuses that, reading OpenID4VP 1.0 section 6.4.2. Add it to an option, or remove it.",
                nameof(credentialSets));
        }

        var sets = new JsonArray();
        foreach (var set in credentialSets)
        {
            var entry = new JsonObject
            {
                ["options"] = new JsonArray([.. set.Options.Select(option => (JsonNode)new JsonArray([.. option.Select(id => (JsonNode)id)]))]),
            };

            // Written only when false. SPEC: OpenID4VP 1.0 section 6.2, required: "If omitted, the default value is true."
            if (!set.Required)
            {
                entry["required"] = false;
            }

            sets.Add(entry);
        }

        query["credential_sets"] = sets;
        return query.ToJsonString(JsonDefaults.Relaxed);
    }
}

/// <summary>
/// One Credential Set Query: the combinations of Credential Queries, by id, that each answer one use case.
/// </summary>
/// <remarks>
/// Pass it to <see cref="Dcql.Query"/>. For the common case, one credential out of several alternatives,
/// <see cref="Dcql.AnyOf"/> builds the set for you.
/// </remarks>
// SPEC: OpenID4VP 1.0 section 6.2, Credential Set Query.
public sealed record DcqlCredentialSet
{
    /// <summary>
    /// The options, at least one. Each is a non-empty list of Credential Query ids, and the wallet answers the set
    /// with every credential of one option.
    /// </summary>
    /// <remarks>
    /// SPEC: OpenID4VP 1.0 section 6.2, options: "A non-empty array, where each value in the array is a list of
    /// Credential Query identifiers representing one set of Credentials that satisfies the use case. The value of
    /// each element in the options array is a non-empty array of identifiers which reference elements in
    /// credentials."
    /// </remarks>
    public required IReadOnlyList<IReadOnlyList<string>> Options { get; init; }

    /// <summary>
    /// Whether the use case needs this set answered. True by default, as the specification's default is, and
    /// written into the query only when false.
    /// </summary>
    /// <remarks>
    /// SPEC: OpenID4VP 1.0 section 6.2, required: "A boolean which indicates whether this set of Credentials is
    /// required to satisfy the particular use case at the Verifier. If omitted, the default value is true."
    /// </remarks>
    public bool Required { get; init; } = true;
}
