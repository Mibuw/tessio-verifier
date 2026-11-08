using Tessio.Verifier.Core;
using Tessio.Verifier.Core.Mdoc;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore;

// What belongs in this file: whether a response acknowledges the request's transaction data in the presentations
// that must carry it. Reading each presentation's own transaction data is VerifyAgainstAsync's.

public sealed partial class WalletResponseVerifier
{
    /// <summary>
    /// A refusal when some <c>transaction_data</c> object is not acknowledged by a presentation that verified and
    /// answers one of the Credential Queries it names, or null when every one is.
    /// </summary>
    /// <remarks>
    /// <para>
    /// SPEC: OpenID4VP 1.0 section 5.1, transaction_data, credential_ids: "REQUIRED. Non-empty array of strings each
    /// referencing a Credential requested by the Verifier that can be used to authorize this transaction. The string
    /// matches the id field in the DCQL Credential Query." Section 8.4: "The Wallet that received the transaction_data
    /// parameter in the request MUST include a representation or reference to the data in the respective Credential
    /// presentation."
    /// So the binding belongs to the presentations of the entries an object names, and a set satisfied by another
    /// entry does not carry it.
    /// </para>
    /// <para>
    /// Only an SD-JWT VC presentation counts. Its Key Binding JWT's hashes are checked against every transaction
    /// data string by <c>SdJwtVcVerifier</c>; this library checks no transaction data in an mdoc, so an mdoc answer
    /// can never acknowledge it. <see cref="RequestParameters.AreRecoverable(PresentationRequest)"/> refuses a
    /// request that names an mdoc entry, and this holds a caller of VerifyAsync that did not ask to the same rule.
    /// </para>
    /// </remarks>
    private static VerificationResult? TransactionDataUnacknowledged(
        IReadOnlyList<IReadOnlyList<string>> transactionDataIds,
        List<(PresentedCredential Credential, VerificationResult Result)> verified)
    {
        var acknowledging = verified
            .Where(static v => !string.Equals(v.Credential.Format, MdocVerifier.Format, StringComparison.Ordinal))
            .Select(static v => v.Credential.CredentialQueryId!)
            .ToHashSet(StringComparer.Ordinal);

        return transactionDataIds.All(ids => ids.Any(acknowledging.Contains))
            ? null
            : Invalid(ErrorCodes.TransactionDataMissing,
                "A transaction_data object is not acknowledged by a verified SD-JWT VC presentation answering one of "
                + "the Credential Queries its credential_ids name.");
    }
}
