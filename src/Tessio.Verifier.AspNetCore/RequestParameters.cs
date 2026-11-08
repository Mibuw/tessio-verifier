using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Core.Mdoc;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Reads the parameters of an issued authorization request back out of it. The verifier derives
/// per-session expectations from here so it never has to consult the process-wide
/// <see cref="VerifierOptions"/>: the request carries the response_uri, response_mode, transaction data,
/// and the requested credential format / <c>vct</c> / docType in its DCQL. The frozen
/// <see cref="PresentationRequest"/> contract does not retain these, but the request itself always does.
/// </summary>
/// <remarks>
/// <para>
/// A request delivers those parameters in one of two encodings, and this reads either. A JAR request
/// carries them as claims in the signed request object. An EU Age Verification request has no request
/// object at all and carries them as plain query parameters on the authorization request URI. The signed
/// object wins where both are present, because it is the copy whose integrity is protected.
/// </para>
/// <para>
/// A request sent through the Digital Credentials API is a third form: its parameters are members of the data
/// object the page passes to the API or the claims of the JWS in that object's <c>request</c> member when it
/// is signed. The overloads taking a <see cref="DcApiPresentationRequest"/> read it, through the same readers.
/// </para>
/// <para>
/// Reading only the request object is what made an AV session unverifiable. Every accessor returned
/// null, so the credential format fell back to <c>dc+sd-jwt</c> and an mdoc age attestation was parsed
/// as an SD-JWT VC, with no docType compared and no response_uri for the device transcript.
/// </para>
/// </remarks>
internal static class RequestParameters
{
    // SPEC: OpenID4VP 1.0 §5.1 defines dcql_query as "A JSON object containing a DCQL query" and
    // client_metadata as "A JSON object containing the Verifier metadata values", and §5.1 states: "In
    // the context of an authorization request according to RFC6749, parameters containing objects are
    // transferred as JSON-serialized strings". So in a query string these two carry JSON and every other
    // parameter carries a plain string.
    //
    // transaction_data is deliberately absent. §5.1 defines it as a "Non-empty array of strings", not an
    // object, so the sentence above does not settle how it is encoded here, and no builder in this
    // library puts it in a query string. FromQuery refuses a request that carries one rather than
    // guessing: guessing wrong would drop a binding the wallet's Key Binding JWT must acknowledge.
    private static readonly string[] JsonValued = ["dcql_query", "client_metadata"];

    /// <summary>The base64url transaction_data strings from the request, or null.</summary>
    public static IReadOnlyList<string>? TryGetTransactionData(PresentationRequest request) =>
        Read(request, TransactionDataOf);

    /// <inheritdoc cref="TryGetTransactionData(PresentationRequest)"/>
    public static IReadOnlyList<string>? TryGetTransactionData(DcApiPresentationRequest request) =>
        Read(request, TransactionDataOf);

    private static IReadOnlyList<string>? TransactionDataOf(JsonElement root)
    {
        if (!root.TryGetProperty("transaction_data", out var td) || td.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var entries = td.EnumerateArray()
            .Where(static e => e.ValueKind == JsonValueKind.String)
            .Select(static e => e.GetString()!)
            .ToList();
        return entries.Count > 0 ? entries : null;
    }

    /// <summary>
    /// The <c>credential_ids</c> of each transaction data object, in order, or null when any object cannot be read:
    /// not base64url, not a JSON object, or without a non-empty array of non-empty strings there.
    /// </summary>
    // SPEC: OpenID4VP 1.0 section 5.1, transaction_data: "Non-empty array of strings, where each string is a
    // base64url-encoded JSON object", whose credential_ids is "REQUIRED. Non-empty array of strings each referencing
    // a Credential requested by the Verifier".
    public static IReadOnlyList<IReadOnlyList<string>>? TransactionDataCredentialIds(IReadOnlyList<string> transactionData)
    {
        var all = new List<IReadOnlyList<string>>(transactionData.Count);
        foreach (var entry in transactionData)
        {
            try
            {
                using var document = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(entry));
                if (document.RootElement.ValueKind != JsonValueKind.Object
                    || !document.RootElement.TryGetProperty("credential_ids", out var ids)
                    || ids.ValueKind != JsonValueKind.Array
                    || ids.GetArrayLength() == 0
                    || !ids.EnumerateArray().All(IsTypeIdentifier))
                {
                    return null;
                }

                all.Add([.. ids.EnumerateArray().Select(static id => id.GetString()!)]);
            }
            catch (Exception e) when (e is FormatException or JsonException or ArgumentException)
            {
                return null;
            }
        }

        return all;
    }

    /// <summary>The request's <c>response_uri</c>, or null.</summary>
    public static string? TryGetResponseUri(PresentationRequest request) =>
        Read(request, root => TryGetString(root, "response_uri"));

    /// <summary>The request's <c>response_mode</c> (e.g. <c>direct_post</c> or <c>direct_post.jwt</c>), or null.</summary>
    public static string? TryGetResponseMode(PresentationRequest request) =>
        Read(request, ResponseModeOf);

    /// <inheritdoc cref="TryGetResponseMode(PresentationRequest)"/>
    public static string? TryGetResponseMode(DcApiPresentationRequest request) =>
        Read(request, ResponseModeOf);

    private static string? ResponseModeOf(JsonElement root) => TryGetString(root, "response_mode");

    /// <summary>
    /// Whether this request asked for an encrypted response, <c>direct_post.jwt</c>. The one place that
    /// decides it: the mdoc session transcript, the callback's mode check and the mock wallet all ask
    /// here, so they cannot disagree about what one request demanded.
    /// </summary>
    public static bool AsksForEncryptedResponse(PresentationRequest request) =>
        string.Equals(TryGetResponseMode(request), "direct_post.jwt", StringComparison.Ordinal);

    /// <summary>
    /// Whether a Digital Credentials API request asked for an encrypted response, <c>dc_api.jwt</c>, read from
    /// the request the wallet saw. The one place that decides it for this transport, for the reason above.
    /// </summary>
    public static bool AsksForEncryptedResponse(DcApiPresentationRequest request) =>
        string.Equals(TryGetResponseMode(request), "dc_api.jwt", StringComparison.Ordinal);

    /// <summary>
    /// The credential format the request's DCQL asks for (<c>dcql_query.credentials[0].format</c>, e.g.
    /// <c>dc+sd-jwt</c> or <c>mso_mdoc</c>), or null. Lets the callback parse per session instead of from a
    /// process-wide format pin.
    /// </summary>
    public static string? TryGetRequestedFormat(PresentationRequest request) =>
        Read(request, RequestedFormatOf);

    /// <inheritdoc cref="TryGetRequestedFormat(PresentationRequest)"/>
    public static string? TryGetRequestedFormat(DcApiPresentationRequest request) =>
        Read(request, RequestedFormatOf);

    private static string? RequestedFormatOf(JsonElement root) =>
        TryGetFirstCredential(root, out var credential) ? TryGetString(credential, "format") : null;

    /// <summary>
    /// Every SD-JWT VC type the request's DCQL query accepts
    /// (<c>dcql_query.credentials[0].meta.vct_values</c>), or null for a non-SD-JWT request. These are the
    /// types the session asked for, so the verifier enforces them per session rather than from options.
    /// </summary>
    /// <remarks>
    /// The whole array, not its first entry. SPEC: OpenID4VP 1.0 §B.3.5 defines <c>vct_values</c> as "A
    /// non-empty array of strings that specifies allowed values for the type of the requested Verifiable
    /// Credential", and §8.6 requires a Verifier to "validate that the returned Credential(s) meet all
    /// criteria defined in the query". Reading <c>[0]</c> compares against one member of the allowed set
    /// rather than against the criterion the query states, so it refuses a credential the request
    /// permitted.
    /// <para>
    /// <paramref name="credentialQueryId"/> names the Credential Query whose types to read, for a query asking for
    /// several; null reads the first, as before.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<string>? TryGetExpectedVctValues(PresentationRequest request, string? credentialQueryId = null) =>
        Read(request, root => ExpectedVctValuesOf(root, credentialQueryId));

    /// <inheritdoc cref="TryGetExpectedVctValues(PresentationRequest, string?)"/>
    public static IReadOnlyList<string>? TryGetExpectedVctValues(DcApiPresentationRequest request, string? credentialQueryId = null) =>
        Read(request, root => ExpectedVctValuesOf(root, credentialQueryId));

    private static List<string>? ExpectedVctValuesOf(JsonElement root, string? credentialQueryId)
    {
        if (!TryGetCredential(root, credentialQueryId, out var credential)
            || !credential.TryGetProperty("meta", out var meta)
            || !meta.TryGetProperty("vct_values", out var vctValues)
            || vctValues.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var values = vctValues.EnumerateArray()
            .Where(IsTypeIdentifier)
            .Select(static v => v.GetString()!)
            .ToList();
        return values.Count > 0 ? values : null;
    }

    /// <summary>
    /// Whether a <c>vct_values</c> element is a credential type this verifier can compare against.
    /// </summary>
    /// <remarks>
    /// One owner for the question, because two callers ask it: <see cref="StatesAQueryAndItsType"/> decides
    /// whether the request states a type at all, and <see cref="ExpectedVctValuesOf"/> decides
    /// which types the verifier will accept. If those two disagreed, a list containing the empty string
    /// would pass the first and put the empty string into the second, so a credential asserting an
    /// empty <c>vct</c> would be accepted by a request that never meant to allow one.
    /// <para>
    /// SPEC: OpenID4VP 1.0 §B.3.5 requires every element to be "a valid type identifier as defined in
    /// [I-D.ietf-oauth-sd-jwt-vc]", and the empty string is not one. The kind test is load-bearing
    /// rather than defensive: <c>GetString()</c> THROWS on a number or an object, and a hand-written
    /// query can carry either.
    /// </para>
    /// </remarks>
    private static bool IsTypeIdentifier(JsonElement value) =>
        value.ValueKind == JsonValueKind.String && value.GetString() is { Length: > 0 };

    /// <summary>
    /// The requested mdoc document type from the request's DCQL query
    /// (<c>dcql_query.credentials[0].meta.doctype_value</c>), or null for a non-mdoc request.
    /// <paramref name="credentialQueryId"/> names the Credential Query to read instead of the first.
    /// </summary>
    public static string? TryGetExpectedDocType(PresentationRequest request, string? credentialQueryId = null) =>
        Read(request, root => ExpectedDocTypeOf(root, credentialQueryId));

    /// <inheritdoc cref="TryGetExpectedDocType(PresentationRequest, string?)"/>
    public static string? TryGetExpectedDocType(DcApiPresentationRequest request, string? credentialQueryId = null) =>
        Read(request, root => ExpectedDocTypeOf(root, credentialQueryId));

    private static string? ExpectedDocTypeOf(JsonElement root, string? credentialQueryId) =>
        TryGetCredential(root, credentialQueryId, out var credential) && credential.TryGetProperty("meta", out var meta)
            ? TryGetString(meta, "doctype_value")
            : null;

    /// <summary>
    /// What the request's DCQL query says about the <c>vp_token</c> that answers it, or null when the query cannot
    /// be read that way (see <see cref="AreRecoverable(PresentationRequest)"/> for when that refuses the request).
    /// </summary>
    public static DcqlAnswerRules? TryGetAnswerRules(PresentationRequest request) =>
        Read(request, AnswerRulesOf);

    /// <inheritdoc cref="TryGetAnswerRules(PresentationRequest)"/>
    public static DcqlAnswerRules? TryGetAnswerRules(DcApiPresentationRequest request) =>
        Read(request, AnswerRulesOf);

    private static DcqlAnswerRules? AnswerRulesOf(JsonElement root) =>
        root.TryGetProperty("dcql_query", out var query) ? DcqlAnswerRules.TryRead(query) : null;

    /// <summary>
    /// The response-encryption public JWK this request advertised in <c>client_metadata.jwks</c>, as
    /// raw JSON. Null when the request carries none (direct_post).
    /// </summary>
    /// <remarks>
    /// This is the honest source for anything that needs "the key the wallet saw": the mock wallet
    /// encrypts to it and the verifier derives the mdoc session-transcript thumbprint from it. Reading
    /// it from a process-wide singleton instead is how key reuse survived until the conformance suite
    /// flagged it.
    /// </remarks>
    public static string? TryGetEncryptionJwkJson(PresentationRequest request) =>
        Read(request, EncryptionJwkJsonOf);

    /// <inheritdoc cref="TryGetEncryptionJwkJson(PresentationRequest)"/>
    public static string? TryGetEncryptionJwkJson(DcApiPresentationRequest request) =>
        Read(request, EncryptionJwkJsonOf);

    private static string? EncryptionJwkJsonOf(JsonElement root) =>
        root.TryGetProperty("client_metadata", out var cm)
        && cm.TryGetProperty("jwks", out var jwks)
        && jwks.TryGetProperty("keys", out var keys)
        && keys.ValueKind == JsonValueKind.Array
        && keys.GetArrayLength() > 0
            ? keys[0].GetRawText()
            : null;

    /// <summary>
    /// The RFC 7638 thumbprint of the encryption JWK this request advertised, from its <c>kid</c>. Null
    /// when the request advertised no key.
    /// </summary>
    public static byte[]? TryGetEncryptionKeyThumbprint(PresentationRequest request)
    {
        if (TryGetEncryptionJwkJson(request) is not { } jwkJson)
        {
            return null;
        }

        using var jwk = JsonDocument.Parse(jwkJson);
        return jwk.RootElement.TryGetProperty("kid", out var kid) && kid.GetString() is { Length: > 0 } value
            ? Base64UrlEncoder.DecodeBytes(value)
            : null;
    }

    /// <summary>
    /// The RFC 7638 SHA-256 thumbprint of the encryption JWK a Digital Credentials API request advertised,
    /// computed from the key itself. Null when the request advertised no key.
    /// </summary>
    /// <remarks>
    /// Computed, not read from the <c>kid</c> as the redirect overload does. That shortcut holds only because
    /// this library's own builders set the <c>kid</c> to the thumbprint, and over this transport a host builds
    /// the metadata for a wallet that may want a <c>kid</c> of its own choosing.
    /// </remarks>
    // SPEC: OpenID4VP 1.0 Annex B.2.6.2: "For the Response Mode dc_api.jwt, the third element MUST be the JWK
    // SHA-256 Thumbprint as defined in [RFC7638], encoded as a Byte String, of the Verifier's public key used to
    // encrypt the response."
    public static byte[]? TryGetEncryptionKeyThumbprint(DcApiPresentationRequest request) =>
        TryGetEncryptionJwkJson(request) is { } jwkJson ? new JsonWebKey(jwkJson).ComputeJwkThumbprint() : null;

    /// <summary>
    /// Whether this request's parameters can be recovered, in either encoding. False means nothing a
    /// wallet returns can be checked against what was asked for: not the credential format, not the
    /// <c>vct</c>, not the docType.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The DCQL is the test rather than "did anything parse", because a request object that parses but
    /// carries no query leaves every expectation null just as surely as no request object at all.
    /// </para>
    /// <para>
    /// A query that parses but does not say which credential TYPE it asked for is the same failure one
    /// level deeper, so it is refused here too. Both format profiles require the entry to state one:
    /// OpenID4VP 1.0 §B.3.5 makes <c>vct_values</c> REQUIRED and non-empty, and §B.2.3 makes
    /// <c>doctype_value</c> REQUIRED. Without it the verifier SKIPS the type comparison rather than
    /// failing it, so a well-signed credential of any type verifies, which is the one outcome this
    /// predicate exists to prevent.
    /// </para>
    /// <para>
    /// It judges only that, not conformance generally. §6.1 also makes <c>format</c> REQUIRED, and a
    /// query omitting it is accepted here anyway: the response still routes to the SD-JWT verifier,
    /// which compares the <c>vct</c> the query does carry, so the check is real and refusing would
    /// reject a session that verifies correctly. Widening this predicate into a conformance check is a
    /// different job with a different blast radius.
    /// </para>
    /// <para>
    /// A query asking for several credentials is held to two more things. Every Credential Query must state its
    /// type, not just the first, because an answer under any of them is checked against that one's type. And the
    /// query must be readable as <see cref="DcqlAnswerRules"/>: each entry with a well-formed id of its own, its
    /// credential sets well formed. SPEC: OpenID4VP 1.0 section 8.1 keys each answer by "the id value used for a
    /// Credential Query", so without readable ids no answer can be matched to the entry it must be checked
    /// against. A single-credential query without readable ids is still accepted, as it always was: every answer
    /// is checked against its one entry.
    /// </para>
    /// </remarks>
    public static bool AreRecoverable(PresentationRequest request) =>
        Read(request, StatesAQueryAndItsType);

    /// <summary>
    /// Whether a Digital Credentials API request's parameters can be recovered, by the same test as
    /// <see cref="AreRecoverable(PresentationRequest)"/>.
    /// </summary>
    public static bool AreRecoverable(DcApiPresentationRequest request) =>
        Read(request, StatesAQueryAndItsType);

    private static bool StatesAQueryAndItsType(JsonElement root)
    {
        if (!TryGetCredentials(root, out var query, out var credentials)
            || !credentials.EnumerateArray().All(static credential =>
                credential.ValueKind == JsonValueKind.Object && StatesTheCredentialType(credential)))
        {
            return false;
        }

        var rules = DcqlAnswerRules.TryRead(query);
        if (rules is null)
        {
            return !SeveralCredentialsOf(root);
        }

        return TransactionDataOf(root) is not { } transactionData || TransactionDataIsCheckable(root, rules, transactionData);
    }

    /// <summary>
    /// Whether every transaction data object names only Credential Queries of this request whose answer this library
    /// can check transaction data in: SD-JWT VC, whose Key Binding JWT carries the hashes. An mdoc entry is refused,
    /// because nothing here checks transaction data in an mdoc, so an mdoc answer could never acknowledge it. So is an
    /// object naming two entries an answer may need together (<see cref="NamesEntriesNeededTogether"/>).
    /// </summary>
    // SPEC: OpenID4VP 1.0 section 5.1, credential_ids: "The string matches the id field in the DCQL Credential Query."
    private static bool TransactionDataIsCheckable(JsonElement root, DcqlAnswerRules rules, IReadOnlyList<string> transactionData) =>
        TransactionDataCredentialIds(transactionData) is { } all
        && !NamesEntriesNeededTogether(rules, all)
        && all.SelectMany(static ids => ids).All(id =>
            TryGetCredential(root, id, out var credential)
            && !string.Equals(TryGetString(credential, "format"), MdocVerifier.Format, StringComparison.Ordinal));

    /// <summary>
    /// Whether some transaction data object names two Credential Queries an answer may need together.
    /// </summary>
    /// <remarks>
    /// SPEC: OpenID4VP 1.0 section 5.1, credential_ids: "If there is more than one element in the array, the Wallet
    /// MUST use only one of the referenced Credentials for transaction authorization." So a conforming wallet
    /// acknowledges the object in one presentation, and this library cannot tell which: it checks each SD-JWT VC
    /// presentation against every object naming its entry, so the other one fails and is discarded. Where only one
    /// of the named entries is ever needed, as for alternatives, that costs nothing. Where both may be needed, a valid
    /// answer would be refused, so the request is refused instead, as this library's limit.
    /// </remarks>
    public static bool NamesEntriesNeededTogether(DcqlAnswerRules rules, IReadOnlyList<IReadOnlyList<string>> transactionDataIds) =>
        transactionDataIds.Any(rules.AnyTwoMayBeNeededTogether);

    /// <summary>
    /// Whether the request's DCQL query asks for more than one Credential Query or carries <c>credential_sets</c>,
    /// so that an answer can be matched to the entry it must be checked against only by its id.
    /// </summary>
    public static bool AsksForSeveralCredentials(PresentationRequest request) =>
        Read(request, SeveralCredentialsOf);

    /// <inheritdoc cref="AsksForSeveralCredentials(PresentationRequest)"/>
    public static bool AsksForSeveralCredentials(DcApiPresentationRequest request) =>
        Read(request, SeveralCredentialsOf);

    private static bool SeveralCredentialsOf(JsonElement root) =>
        TryGetCredentials(root, out var query, out var credentials)
        && (credentials.GetArrayLength() > 1 || query.TryGetProperty("credential_sets", out _));

    /// <summary>
    /// Whether the DCQL entry states the credential type the matching verifier will compare against.
    /// </summary>
    /// <remarks>
    /// The split mirrors how <see cref="WalletResponseVerifier"/> routes a response: the mdoc verifier
    /// for <c>mso_mdoc</c> and the SD-JWT verifier for EVERYTHING else, including a query whose
    /// <c>format</c> is missing or unrecognised. So the question is not "which formats do we know" but
    /// "which expectation will be read", and each branch here asks for the one its verifier uses. A
    /// third routing branch needs a third branch here, or its requests arrive with nothing to compare.
    /// </remarks>
    private static bool StatesTheCredentialType(JsonElement credential)
    {
        if (!credential.TryGetProperty("meta", out var meta))
        {
            return false;
        }

        // Non-empty on both branches, not merely present. SPEC: §B.2.3 requires doctype_value to be "a
        // valid doctype identifier" and §B.3.5 requires the same of every vct value, and the empty
        // string is neither. An empty one also compares against nothing useful: the verifier would
        // refuse every credential with a mismatch naming '' rather than refusing the request, which
        // reads to the holder as their wallet's fault.
        return string.Equals(TryGetString(credential, "format"), MdocVerifier.Format, StringComparison.Ordinal)
            ? TryGetString(meta, "doctype_value") is { Length: > 0 }
            : meta.TryGetProperty("vct_values", out var vctValues)
                && vctValues.ValueKind == JsonValueKind.Array
                && vctValues.EnumerateArray().Any(IsTypeIdentifier);
    }

    private static bool TryGetFirstCredential(JsonElement root, out JsonElement credential) =>
        TryGetCredential(root, credentialQueryId: null, out credential);

    /// <summary>
    /// The Credential Query whose id is <paramref name="credentialQueryId"/>, or the first when that is null.
    /// </summary>
    private static bool TryGetCredential(JsonElement root, string? credentialQueryId, out JsonElement credential)
    {
        credential = default;
        if (!TryGetCredentials(root, out _, out var credentials))
        {
            return false;
        }

        if (credentialQueryId is null)
        {
            credential = credentials[0];
            return true;
        }

        foreach (var entry in credentials.EnumerateArray())
        {
            if (entry.ValueKind == JsonValueKind.Object
                && string.Equals(TryGetString(entry, "id"), credentialQueryId, StringComparison.Ordinal))
            {
                credential = entry;
                return true;
            }
        }

        return false;
    }

    /// <summary>The request's <c>dcql_query</c> and its non-empty <c>credentials</c> array.</summary>
    private static bool TryGetCredentials(JsonElement root, out JsonElement query, out JsonElement credentials)
    {
        credentials = default;
        return root.TryGetProperty("dcql_query", out query)
            && query.ValueKind == JsonValueKind.Object
            && query.TryGetProperty("credentials", out credentials)
            && credentials.ValueKind == JsonValueKind.Array
            && credentials.GetArrayLength() > 0;
    }

    private static string? TryGetString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static T? Read<T>(PresentationRequest request, Func<JsonElement, T?> read)
    {
        ArgumentNullException.ThrowIfNull(request);

        using var root = TryReadRoot(request);
        return root is null ? default : read(root.RootElement);
    }

    private static T? Read<T>(DcApiPresentationRequest request, Func<JsonElement, T?> read)
    {
        ArgumentNullException.ThrowIfNull(request);

        using var root = TryReadRoot(request);
        return root is null ? default : read(root.RootElement);
    }

    /// <summary>
    /// A Digital Credentials API request's parameters as one JSON object: the <c>data</c> object itself when
    /// unsigned, the payload of its <c>request</c> JWS when signed. Null when neither yields an object.
    /// </summary>
    // SPEC: OpenID4VP 1.0 Appendix A.3.1 (parameters as members of the data object) and A.3.2.1 (a signed
    // request is "the value of the request claim in the data element").
    private static JsonDocument? TryReadRoot(DcApiPresentationRequest request)
    {
        JsonDocument data;
        try
        {
            data = JsonDocument.Parse(request.DataJson);
        }
        catch (JsonException)
        {
            return null;
        }

        if (data.RootElement.ValueKind != JsonValueKind.Object)
        {
            data.Dispose();
            return null;
        }

        if (!data.RootElement.TryGetProperty("request", out var requestObject))
        {
            return data;
        }

        using (data)
        {
            return requestObject.ValueKind == JsonValueKind.String ? FromRequestObject(requestObject.GetString()!) : null;
        }
    }

    /// <summary>
    /// The request's parameters as one JSON object, from the signed request object where there is one and
    /// from the query string otherwise. Null when neither encoding yields anything readable.
    /// </summary>
    private static JsonDocument? TryReadRoot(PresentationRequest request) =>
        FromRequestObject(request.SignedRequestObject) ?? FromQuery(request.AuthorizationRequestUri);

    private static JsonDocument? FromRequestObject(string requestObject)
    {
        var parts = requestObject.Split('.');
        if (parts.Length < 2)
        {
            return null;
        }

        try
        {
            return JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(parts[1]));
        }
        catch (Exception e) when (e is FormatException or JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// The parameters of a plain-parameter request, as the same JSON shape a request object would carry.
    /// Requires <c>dcql_query</c>: without it there is no request to check a response against, and every
    /// caller here would read null from a URI that merely happened to have a query string.
    /// </summary>
    private static JsonDocument? FromQuery(Uri authorizationRequestUri)
    {
        var query = QueryHelpers.ParseQuery(authorizationRequestUri.Query);
        if (!query.TryGetValue("dcql_query", out var dcql) || dcql.Count != 1 || string.IsNullOrEmpty(dcql[0]))
        {
            return null;
        }

        // See JsonValued: this encoding of transaction_data is not settled, and reading it wrong would
        // drop a binding rather than fail. Report the whole request as unreadable instead, which a host
        // surfaces as a refusal it can act on.
        if (query.ContainsKey("transaction_data"))
        {
            return null;
        }

        try
        {
            var root = new JsonObject();
            foreach (var (name, values) in query)
            {
                // A parameter given twice makes the request ambiguous, and picking either value would be
                // a guess about what the wallet saw. Refuse the whole request, as the dcql_query check
                // above already does, rather than reading a parameter this session may not have sent.
                if (values.Count > 1)
                {
                    return null;
                }

                if (values[0] is not { Length: > 0 } value)
                {
                    continue;
                }

                root[name] = JsonValued.Contains(name, StringComparer.Ordinal)
                    ? JsonNode.Parse(value)
                    : JsonValue.Create(value);
            }

            return JsonDocument.Parse(root.ToJsonString());
        }
        catch (JsonException)
        {
            // A JSON-valued parameter that is not JSON. Unreadable is unreadable: report it as such
            // rather than returning the half of the request that did parse.
            return null;
        }
    }
}
