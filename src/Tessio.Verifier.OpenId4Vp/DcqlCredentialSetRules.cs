// What belongs in this file: the rules a DCQL query's credential_sets must keep, in the one copy both the
// builder (Dcql.Query) and the response reader (DcqlAnswerRules) apply. Every rule cites its clause, for the
// reason DcqlClaimsQuery gives.
namespace Tessio.Verifier.OpenId4Vp;

/// <summary>Whether a query's credential sets are well formed against its Credential Query ids.</summary>
// SPEC: OpenID4VP 1.0 section 6 (credential_sets) and section 6.2 (Credential Set Query).
internal static class DcqlCredentialSetRules
{
    /// <summary>
    /// Null when every set is well formed, otherwise why not. <paramref name="sets"/> holds each set's options.
    /// </summary>
    internal static string? Problem(
        IReadOnlySet<string> credentialIds, IReadOnlyList<IReadOnlyList<IReadOnlyList<string>>> sets)
    {
        foreach (var options in sets)
        {
            // SPEC: OpenID4VP 1.0 section 6.2, options: "REQUIRED A non-empty array".
            if (options.Count == 0)
            {
                return "A credential set needs at least one option (OpenID4VP 1.0 section 6.2).";
            }

            foreach (var option in options)
            {
                // SPEC: OpenID4VP 1.0 section 6.2: "The value of each element in the options array is a non-empty array of
                // identifiers which reference elements in credentials."
                if (option is null || option.Count == 0)
                {
                    return "Every credential set option needs at least one Credential Query id (OpenID4VP 1.0 section 6.2).";
                }

                foreach (var id in option)
                {
                    if (id is null || !credentialIds.Contains(id))
                    {
                        return $"A credential set option names '{id}', which no Credential Query in this query carries "
                            + "(OpenID4VP 1.0 section 6.2).";
                    }
                }
            }
        }

        return null;
    }
}
