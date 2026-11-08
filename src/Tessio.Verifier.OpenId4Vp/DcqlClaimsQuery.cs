// What belongs in this file: turning claim declarations into the `claims` and `claim_sets` JSON a DCQL
// credential entry carries, and refusing a request the specification says is malformed. Nothing about
// the credential entry around them, which is Dcql's job.
//
// EVERY RULE BELOW THAT COMES FROM THE SPECIFICATION CITES ITS CLAUSE, and that is not decoration. The
// plain null and empty-string guards cite nothing, because they are ordinary argument checks rather
// than protocol rules, and that distinction IS the point: a refusal that is not an argument check
// answers to a clause, so the clause goes in the comment.
//
// The reason to insist on it: a list of rules assembled by imagining what a careless caller gets wrong
// is not the same list as §6.1, §6.3 and §7.2, and the difference is invisible from inside. Every rule
// those sections carry fails the same silent way when a builder omits it. The query serialises perfectly,
// the wallet answers with no claims, and that reads as the holder having nothing to offer rather than as
// a malformed request. So a PROTOCOL rule with no citation is one somebody invented. Add the citation, or
// do not add the rule.

using System.Text.Json.Nodes;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// The claims half of a DCQL credential query.
/// </summary>
/// <remarks>
/// Separate from <see cref="Dcql"/> because the validation below is most of the code and none of the
/// subject. <see cref="Dcql"/> answers "what does a query for this credential look like"; this answers
/// "is this a well-formed request at all", which is a question with its own rules and its own failure
/// modes.
/// </remarks>
// SPEC: OpenID4VP 1.0 §6.1 (Credential Query, which defines the `claims` and `claim_sets` members),
// §6.3 (Claims Query, which defines each entry) and §6.4.1 (Selecting Claims, which defines what a
// wallet does with them).
internal static class DcqlClaimsQuery
{
    /// <summary>A top-level path per claim name, which is the SD-JWT VC shape.</summary>
    internal static DcqlClaim[] TopLevel(string[] names) =>
        [.. names.Select(name => new DcqlClaim { Path = [name] })];

    /// <summary>
    /// The <c>claims</c> array, validated against the specification and against the claim sets that
    /// will reference it.
    /// </summary>
    /// <param name="claims">The claims to emit.</param>
    /// <param name="claimSets">The sets that will reference them, empty when there are none.</param>
    /// <param name="isMdoc">
    /// Whether the credential is an mdoc, which changes what a path may look like and whether
    /// <see cref="DcqlClaim.IntentToRetain"/> means anything.
    /// </param>
    /// <param name="allowEmptyClaims">
    /// Whether an empty list may be emitted as <c>"claims": []</c>.
    /// <para>
    /// §6.1 says <c>claims</c> is "A non-empty array", so this is false for every builder that is free
    /// to refuse. It is true ONLY for the name-based overloads, which have emitted an empty array since
    /// they shipped, to callers outside this repository. A new builder with no caller has no
    /// compatibility to keep, so it does not inherit the wart.
    /// </para>
    /// </param>
    internal static JsonArray ClaimsArray(
        IReadOnlyList<DcqlClaim> claims, string[][] claimSets, bool isMdoc, bool allowEmptyClaims)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(claimSets);

        var needsIds = claimSets.Length > 0;

        // SPEC: §6.1. `claims` is "A non-empty array of objects as defined in [§6.3]". With claim sets
        // it is additionally incoherent, because a set would reference something that is not there, and
        // §6.4.1 adds "claim_sets MUST NOT be present if claims is absent".
        if (claims.Count == 0 && (needsIds || !allowEmptyClaims))
        {
            throw new ArgumentException(
                needsIds
                    ? "A query with claim sets needs at least one claim for them to reference."
                    : "A DCQL query needs at least one claim (OpenID4VP 1.0 section 6.1).",
                nameof(claims));
        }

        var seenIds = new HashSet<string>(StringComparer.Ordinal);
        var array = new JsonArray();

        foreach (var claim in claims)
        {
            ArgumentNullException.ThrowIfNull(claim);

            // SPEC: §6.3. `path` is "REQUIRED ... a non-empty array representing a claims path pointer".
            if (claim.Path is null || claim.Path.Count == 0)
            {
                throw new ArgumentException("A DCQL claim needs at least one path segment.", nameof(claims));
            }

            // SPEC: §7.2. "A claims path pointer into an mdoc contains two elements of type string. The
            // first element refers to a namespace and the second element refers to a data element
            // identifier." §7.2.1 step 1 makes the consequence normative on the WALLET: "If the claims
            // path pointer does not contain exactly two components or one of the components is not a
            // string then abort processing and return an error." So a one or three segment mdoc path is
            // a query every conformant wallet must refuse, and refusing it here is the difference
            // between a stack trace naming the mistake and a wallet returning nothing.
            if (isMdoc && claim.Path.Count != 2)
            {
                throw new ArgumentException(
                    "An mdoc claim path has exactly two segments, [namespace, element], and this one has "
                    + $"{claim.Path.Count} (OpenID4VP 1.0 section 7.2).",
                    nameof(claims));
            }

            var path = new JsonArray();
            foreach (var segment in claim.Path)
            {
                ArgumentException.ThrowIfNullOrEmpty(segment, nameof(claims));
                path.Add(segment);
            }

            var entry = new JsonObject();
            if (claim.Id is not null)
            {
                // SPEC: §6.3. The id "MUST be a non-empty string consisting of alphanumeric,
                // underscore (_), or hyphen (-) characters".
                if (!IsWellFormedId(claim.Id))
                {
                    throw new ArgumentException(
                        $"'{claim.Id}' is not a usable claim id. Only letters, digits, underscore and "
                        + "hyphen are allowed, and it cannot be empty (OpenID4VP 1.0 section 6.3).",
                        nameof(claims));
                }

                // SPEC: §6.3. "Within the particular claims array, the same id MUST NOT be present
                // more than once."
                if (!seenIds.Add(claim.Id))
                {
                    throw new ArgumentException(
                        $"Two claims share the id '{claim.Id}', so a claim set naming it is ambiguous.",
                        nameof(claims));
                }

                entry["id"] = claim.Id;
            }
            else if (needsIds)
            {
                // SPEC: §6.3. The id is "REQUIRED if claim_sets is present in the Credential Query".
                throw new ArgumentException(
                    "Every claim needs an id when the query has claim sets, because a set references "
                    + "claims by id.",
                    nameof(claims));
            }

            entry["path"] = path;

            if (claim.IntentToRetain is { } retain)
            {
                // SPEC: §B.2.4 scopes intent_to_retain to ISO mdoc. Emitting it on an SD-JWT VC claim
                // would invent a parameter the specification does not define for that format.
                if (!isMdoc)
                {
                    throw new ArgumentException(
                        "intent_to_retain is an mdoc parameter (OpenID4VP 1.0 B.2.4) and has no meaning "
                        + "on an SD-JWT VC claim.",
                        nameof(claims));
                }

                entry["intent_to_retain"] = retain;
            }

            array.Add(entry);
        }

        ValidateSets(claimSets, seenIds);
        return array;
    }

    /// <summary>
    /// Both directions of the relationship between claim sets and claims.
    /// </summary>
    /// <remarks>
    /// The reverse direction is the one that is easy to miss and expensive to diagnose. §6.4.1: "If both
    /// claims and claim_sets are present, the Verifier requests one combination of the claims listed in
    /// claim_sets." So a claim NO set references is never requested. A caller who adds a fallback claim
    /// and forgets to add its set has built a query whose fallback cannot fire, and a holder who can
    /// only satisfy that fallback returns nothing at all. Nothing about the JSON looks wrong.
    /// </remarks>
    private static void ValidateSets(string[][] claimSets, HashSet<string> declaredIds)
    {
        var referenced = new HashSet<string>(StringComparer.Ordinal);

        foreach (var set in claimSets)
        {
            ArgumentNullException.ThrowIfNull(set);

            // SPEC: §6.1. `claim_sets` is "A non-empty array containing arrays of identifiers", so a
            // set with nothing in it describes a combination of no claims.
            if (set.Length == 0)
            {
                throw new ArgumentException("A claim set cannot be empty.", nameof(claimSets));
            }

            foreach (var id in set)
            {
                // Checked before the lookup. A null id is not absent from the declared ids, it is not
                // an id at all, and reporting it as "references ''" reads as an empty string and sends
                // the reader to the wrong claim.
                ArgumentException.ThrowIfNullOrEmpty(id, nameof(claimSets));

                if (!declaredIds.Contains(id))
                {
                    throw new ArgumentException(
                        $"Claim set references '{id}', which no claim in this query carries.",
                        nameof(claimSets));
                }

                referenced.Add(id);
            }
        }

        // ONLY when there are sets. With none, §6.4.1 says "If claims is present, but claim_sets is
        // absent, the Verifier requests all claims listed in claims", so nothing is unreachable and an
        // id is merely decorative: §6.3 gives it as "REQUIRED if claim_sets is present in the Credential
        // Query; OPTIONAL otherwise". Running the check unconditionally refused every id on a query with
        // no sets, which is a conformant query this builder had no business rejecting.
        if (claimSets.Length == 0)
        {
            return;
        }

        foreach (var declared in declaredIds)
        {
            if (!referenced.Contains(declared))
            {
                throw new ArgumentException(
                    $"The claim '{declared}' is in no claim set, so this query would never ask for it "
                    + "(OpenID4VP 1.0 section 6.4.1). Add it to a set, or remove it.",
                    nameof(claimSets));
            }
        }
    }

    /// <summary>The <c>claim_sets</c> array, or null when the query has none.</summary>
    /// <remarks>
    /// Shapes the JSON only. Whether the ids reference anything is <see cref="ClaimsArray"/>'s question,
    /// because only it holds the claims to check them against. Guards its own arguments all the way
    /// down rather than relying on that method running first, which is true today and is a property of
    /// argument evaluation order rather than of anything stated.
    /// </remarks>
    internal static JsonArray? ClaimSetsArray(string[][] claimSets)
    {
        ArgumentNullException.ThrowIfNull(claimSets);

        if (claimSets.Length == 0)
        {
            return null;
        }

        var sets = new JsonArray();
        foreach (var set in claimSets)
        {
            ArgumentNullException.ThrowIfNull(set);

            var ids = new JsonArray();
            foreach (var id in set)
            {
                ArgumentException.ThrowIfNullOrEmpty(id, nameof(claimSets));
                ids.Add(id);
            }

            sets.Add(ids);
        }

        return sets;
    }

    /// <summary>
    /// Whether a claim id is one §6.3 allows: non-empty, and letters, digits, underscore or hyphen only.
    /// §6.1 states the same rule in the same words for a Credential Query id, so that check uses this too.
    /// </summary>
    /// <remarks>
    /// ASCII letters and digits specifically. §6.3 says "alphanumeric", and the surrounding grammar is
    /// ASCII, so accepting any Unicode letter would emit an id this library considers fine and a strict
    /// wallet may not.
    /// </remarks>
    internal static bool IsWellFormedId(string? id) =>
        id is { Length: > 0 } &&
        id.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-');
}
