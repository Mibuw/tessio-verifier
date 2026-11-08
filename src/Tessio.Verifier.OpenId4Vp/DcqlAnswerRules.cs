// What belongs in this file: what a DCQL query says about the vp_token that answers it. Which key names which
// Credential Query, in which format each presentation is read, how many presentations a key may carry, and which
// combinations of keys answer the query. Reading the vp_token itself is WalletResponseParser's job.
using System.Text.Json;
using Tessio.Verifier.Core;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// The rules a DCQL query sets for its answer, read from the query, and applied to the presentations a
/// <c>vp_token</c> carried.
/// </summary>
// SPEC: OpenID4VP 1.0 section 8.1 (vp_token), section 6.4.2 (Selecting Credentials) and section 8.6 (VP Token
// Validation): "Check that the set of Presentations returned satisfies all requirements defined in the
// Verifier's request as described in Section 6.4."
internal sealed class DcqlAnswerRules
{
    private readonly Dictionary<string, Entry> _credentials;
    private readonly string[] _ids;
    private readonly CredentialSet[]? _sets;

    private DcqlAnswerRules(Dictionary<string, Entry> credentials, string[] ids, CredentialSet[]? sets)
    {
        _credentials = credentials;
        _ids = ids;
        _sets = sets;
    }

    /// <summary>
    /// Where the Credential Query <paramref name="id"/> stands in the query's <c>credentials</c> array, so results can
    /// be ordered by the request rather than by the wallet's choice of key order. -1 for an id the query lacks.
    /// </summary>
    internal int Position(string id) => Array.IndexOf(_ids, id);

    /// <summary>
    /// Whether two of the distinct Credential Queries in <paramref name="ids"/> may both be needed in one answer: with
    /// no credential sets every entry is requested; with sets, two ids are needed together when one option names
    /// both, or when they sit in options of different sets, each of which may have to be satisfied. Ids that appear
    /// only as different options of one set are alternatives, and an answer needs only one of them.
    /// </summary>
    internal bool AnyTwoMayBeNeededTogether(IReadOnlyList<string> ids)
    {
        var distinct = ids.Distinct(StringComparer.Ordinal).ToList();
        if (distinct.Count < 2)
        {
            return false;
        }

        if (_sets is null)
        {
            return true;
        }

        for (var i = 0; i < distinct.Count; i++)
        {
            for (var j = i + 1; j < distinct.Count; j++)
            {
                var (a, b) = (distinct[i], distinct[j]);
                if (_sets.Any(set => set.Options.Any(option => option.Contains(a) && option.Contains(b))))
                {
                    return true;
                }

                var setsOfA = _sets.Where(set => set.Options.Any(option => option.Contains(a))).ToList();
                var setsOfB = _sets.Where(set => set.Options.Any(option => option.Contains(b))).ToList();
                if (setsOfA.Any(setA => setsOfB.Any(setB => !ReferenceEquals(setA, setB))))
                {
                    return true;
                }
            }
        }

        return false;
    }

    /// <summary>One Credential Query: its format, null when the query names none, and whether it allows several.</summary>
    private sealed record Entry(string? Format, bool Multiple);

    /// <summary>One Credential Set Query.</summary>
    private sealed record CredentialSet(IReadOnlyList<IReadOnlyList<string>> Options, bool Required);

    /// <summary>The rules of <paramref name="dcqlQueryJson"/>, or null when it is not a query they can be read from.</summary>
    internal static DcqlAnswerRules? TryRead(string dcqlQueryJson)
    {
        try
        {
            using var document = JsonDocument.Parse(dcqlQueryJson);
            return TryRead(document.RootElement);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// The rules of a DCQL query, or null when it is not one they can be read from: no Credential Query, one without
    /// a well-formed id of its own, credential sets that break section 6.2, or, in a query asking for several
    /// credentials, an entry naming no <c>format</c>.
    /// </summary>
    /// <remarks>
    /// A missing <c>format</c> on the only entry of a query without credential sets is read as null rather than
    /// refused. OpenID4VP 1.0 section 6.1 makes it REQUIRED, but such a query has always been verified in the format
    /// the caller configured, and still is. With several entries that fallback would read every unformatted answer
    /// in one format whichever entry it answers, so the query is refused instead.
    /// </remarks>
    internal static DcqlAnswerRules? TryRead(JsonElement query)
    {
        if (query.ValueKind != JsonValueKind.Object
            || !query.TryGetProperty("credentials", out var credentials)
            || credentials.ValueKind != JsonValueKind.Array
            || credentials.GetArrayLength() == 0)
        {
            return null;
        }

        var entries = new Dictionary<string, Entry>(StringComparer.Ordinal);
        var ids = new List<string>();
        foreach (var credential in credentials.EnumerateArray())
        {
            // SPEC: OpenID4VP 1.0 section 6.1, id: REQUIRED, well formed, and "Within the Authorization Request, the same id MUST
            // NOT be present more than once." The answer is keyed by it, so without it there is nothing to key by.
            if (credential.ValueKind != JsonValueKind.Object
                || !credential.TryGetProperty("id", out var idElement)
                || idElement.ValueKind != JsonValueKind.String
                || idElement.GetString() is not { } id
                || !DcqlClaimsQuery.IsWellFormedId(id)
                || entries.ContainsKey(id)
                || !TryReadFormat(credential, out var format)
                || !TryReadBoolean(credential, "multiple", false, out var multiple))
            {
                return null;
            }

            entries.Add(id, new Entry(format, multiple));
            ids.Add(id);
        }

        var hasSets = query.TryGetProperty("credential_sets", out var setsElement);
        if ((ids.Count > 1 || hasSets) && entries.Values.Any(static entry => entry.Format is null))
        {
            return null;
        }

        if (!hasSets)
        {
            return new DcqlAnswerRules(entries, [.. ids], null);
        }

        // SPEC: OpenID4VP 1.0 section 6, credential_sets: "OPTIONAL. A non-empty array of Credential Set Queries".
        if (setsElement.ValueKind != JsonValueKind.Array || setsElement.GetArrayLength() == 0)
        {
            return null;
        }

        var sets = new List<CredentialSet>();
        foreach (var setElement in setsElement.EnumerateArray())
        {
            if (setElement.ValueKind != JsonValueKind.Object
                || !setElement.TryGetProperty("options", out var optionsElement)
                || TryReadOptions(optionsElement) is not { } options
                || !TryReadBoolean(setElement, "required", true, out var required))
            {
                return null;
            }

            sets.Add(new CredentialSet(options, required));
        }

        return DcqlCredentialSetRules.Problem(entries.Keys.ToHashSet(StringComparer.Ordinal), [.. sets.Select(static s => s.Options)]) is null
            ? new DcqlAnswerRules(entries, [.. ids], [.. sets])
            : null;
    }

    private static bool TryReadFormat(JsonElement credential, out string? format)
    {
        format = null;
        if (!credential.TryGetProperty("format", out var element))
        {
            return true;
        }

        format = element.ValueKind == JsonValueKind.String ? element.GetString() : null;
        return format is { Length: > 0 };
    }

    private static bool TryReadBoolean(JsonElement owner, string name, bool fallback, out bool value)
    {
        value = fallback;
        if (!owner.TryGetProperty(name, out var element))
        {
            return true;
        }

        if (element.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            return false;
        }

        value = element.GetBoolean();
        return true;
    }

    /// <summary>The options as lists of ids, or null when one is not an array of strings.</summary>
    private static List<IReadOnlyList<string>>? TryReadOptions(JsonElement options)
    {
        if (options.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var read = new List<IReadOnlyList<string>>();
        foreach (var option in options.EnumerateArray())
        {
            if (option.ValueKind != JsonValueKind.Array
                || option.EnumerateArray().Any(static id => id.ValueKind != JsonValueKind.String))
            {
                return null;
            }

            read.Add([.. option.EnumerateArray().Select(static id => id.GetString()!)]);
        }

        return read;
    }

    /// <summary>
    /// The presentations with each one's Credential Query id and format taken from the query, after checking that
    /// together they answer it.
    /// </summary>
    /// <param name="credentials">
    /// What the parser read: each presentation with the <c>vp_token</c> key it arrived under, or with none when the
    /// <c>vp_token</c> was a bare presentation or array rather than an object.
    /// </param>
    /// <exception cref="WalletResponseException">The presentations do not answer the query.</exception>
    internal List<PresentedCredential> Apply(IReadOnlyList<PresentedCredential> credentials)
    {
        var mapped = Map(credentials);
        CheckSelection(mapped.Select(static credential => credential.CredentialQueryId!));
        return mapped;
    }

    /// <summary>
    /// The presentations with each one's Credential Query id and format taken from the query, after checking each key
    /// names a Credential Query and carries no more presentations than that entry allows. Whether the keys together
    /// answer the query is <see cref="CheckSelection"/>'s question, asked separately so a verifier can ask it again
    /// of the presentations that verified.
    /// </summary>
    /// <exception cref="WalletResponseException">A key names no Credential Query, or carries too many presentations.</exception>
    internal List<PresentedCredential> Map(IReadOnlyList<PresentedCredential> credentials)
    {
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        var applied = new List<PresentedCredential>(credentials.Count);
        foreach (var credential in credentials)
        {
            // A bare presentation is read as the answer to the only Credential Query there is, as it always was.
            // With several there is no telling which one it answers, and reading it as any would be a guess.
            var id = credential.CredentialQueryId
                ?? (_ids.Length == 1
                    ? _ids[0]
                    : throw new WalletResponseException(
                        "The vp_token is not keyed by Credential Query id, and the request has several Credential Queries."));

            // SPEC: OpenID4VP 1.0 section 8.1: vp_token holds "entries where the key is the id value used for a Credential Query in
            // the DCQL query". The key is the sender's, so it is not quoted.
            if (!_credentials.TryGetValue(id, out var entry))
            {
                throw new WalletResponseException(
                    "The vp_token carries a presentation under a key that names no Credential Query in the request.");
            }

            // SPEC: OpenID4VP 1.0 section 8.1: "When multiple is omitted, or set to false, the array MUST contain only one
            // Presentation."
            counts[id] = counts.GetValueOrDefault(id) + 1;
            if (!entry.Multiple && counts[id] > 1)
            {
                throw new WalletResponseException(
                    $"The vp_token carries several presentations for the Credential Query '{id}', which does not allow multiple.");
            }

            // The format of the Credential Query the key names, not a guess from the presentation's shape. Only the
            // single entry of a query asking for one credential may name none (TryRead), and it keeps the format the
            // parser was configured with, as it always did.
            applied.Add(credential with { CredentialQueryId = id, Format = entry.Format ?? credential.Format });
        }

        return applied;
    }

    /// <summary>Whether the Credential Queries in <paramref name="answeredIds"/> are a combination the query requested.</summary>
    /// <exception cref="WalletResponseException">They are not.</exception>
    internal void CheckSelection(IEnumerable<string> answeredIds)
    {
        var answered = answeredIds.ToHashSet(StringComparer.Ordinal);

        // SPEC: OpenID4VP 1.0 section 6.4.2: "If credential_sets is not provided, the Verifier requests presentations for all
        // Credentials in credentials to be returned." and "If the Wallet cannot deliver all non-optional Credentials
        // requested by the Verifier according to these rules, it MUST NOT return any Credential(s)."
        if (_sets is null)
        {
            if (_ids.FirstOrDefault(id => !answered.Contains(id)) is { } missing)
            {
                throw new WalletResponseException(
                    $"The response does not answer the Credential Query '{missing}', and a query with no credential_sets "
                    + "requests every one (OpenID4VP 1.0 section 6.4.2).");
            }

            return;
        }

        // SPEC: OpenID4VP 1.0 section 6.4.2: the request is for presentations "satisfying all of the Credential Set Queries in the
        // credential_sets array where the required attribute is true or omitted, and optionally, any of the other
        // Credential Set Queries", and "To satisfy a Credential Set Query, the Wallet MUST return presentations of a
        // set of Credentials that match to one of the options inside the Credential Set Query."
        var requested = new HashSet<string>(StringComparer.Ordinal);
        foreach (var set in _sets)
        {
            var satisfied = set.Options.Where(option => option.All(answered.Contains)).ToList();
            if (set.Required && satisfied.Count == 0)
            {
                throw new WalletResponseException(
                    "The response satisfies no option of a required credential set (OpenID4VP 1.0 section 6.4.2).");
            }

            foreach (var option in satisfied)
            {
                requested.UnionWith(option);
            }
        }

        // This verifier's own reading, not a sentence of the specification: a presentation outside every option it
        // completes answers nothing the request asked for, such as half of an option naming two, so the response
        // is refused rather than verified with a credential nobody requested riding along.
        if (answered.FirstOrDefault(id => !requested.Contains(id)) is { } stray)
        {
            throw new WalletResponseException(
                $"The response answers the Credential Query '{stray}' outside any credential set option it completes.");
        }
    }
}
