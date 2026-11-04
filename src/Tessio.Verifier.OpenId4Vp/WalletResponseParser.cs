using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Core;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// Parses wallet authorization responses — <c>direct_post</c> (cleartext form) and
/// <c>direct_post.jwt</c> (encrypted JWE in the <c>response</c> form parameter) — and extracts the
/// presented credentials from <c>vp_token</c>. A response returned through the Digital Credentials API
/// is read by <see cref="ParseDcApiAsync"/>.
/// </summary>
// SPEC: OpenID4VP 1.0 §8.2 (direct_post) and §8.3 (direct_post.jwt).
public sealed partial class WalletResponseParser : IPresentationResponseParser
{
    private readonly WalletResponseParserOptions _options;

    /// <summary>Creates the parser.</summary>
    public WalletResponseParser(WalletResponseParserOptions? options = null) =>
        _options = options ?? new WalletResponseParserOptions();

    /// <inheritdoc />
    /// <remarks>
    /// This contract returns credentials only, so an Authorization Error Response is thrown here as a
    /// <see cref="WalletResponseException"/>, as it always was. <see cref="ParseDetailedAsync"/> returns it.
    /// </remarks>
    public async Task<IReadOnlyList<PresentedCredential>> ParseAsync(
        WalletResponseData response, CancellationToken ct = default)
    {
        var parsed = await ParseDetailedAsync(response, ct).ConfigureAwait(false);
        return parsed.Error is null
            ? parsed.Credentials
            : throw new WalletResponseException("The wallet answered with an Authorization Error Response, not a presentation.");
    }

    /// <summary>
    /// Parses the response including the <c>state</c> needed for session correlation. Prefer this
    /// over <see cref="ParseAsync"/> when hosting the wallet callback: for <c>direct_post.jwt</c>
    /// the state travels inside the encrypted JWT. With <see cref="WalletResponseParserOptions.ReadErrorResponses"/>
    /// on, an Authorization Error Response, in the clear or sealed, is returned with
    /// <see cref="ParsedWalletResponse.Error"/> set rather than thrown.
    /// </summary>
    /// <exception cref="WalletResponseException">
    /// The response is malformed in any part its sender controls, or cannot be decrypted with the configured
    /// key. A caller that answers this exception as an invalid response has answered every such response.
    /// </exception>
    public async Task<ParsedWalletResponse> ParseDetailedAsync(
        WalletResponseData response, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(response);

        // SPEC: OpenID4VP 1.0 §8.2 — the wallet POSTs application/x-www-form-urlencoded.
        if (!response.ContentType.Contains("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            throw new WalletResponseException(
                $"Unsupported wallet response content type '{response.ContentType}'; expected application/x-www-form-urlencoded.");
        }

        string vpTokenJson;
        string? state;
        var encrypted = false;
        if (response.Form.TryGetValue("response", out var jwtValues))
        {
            // direct_post.jwt: the whole authorization response rides inside one (encrypted) JWT. SPEC: OpenID4VP 1.0
            // section 8.3: "The payload of the encrypted JWT response MUST include the contents of the response as
            // defined in Section 8.1 as top-level JSON members." No text gives a cleartext answer beside it a role,
            // and none forbids one. Refusing the pair is this verifier's own choice, as on the Digital Credentials API
            // path, because reading one answer would let the other ride along unread. Other parameters beside it,
            // such as `state`, are ignored: the response is correlated by the state sealed inside it.
            if (CleartextAnswerParameters.FirstOrDefault(response.Form.ContainsKey) is { } beside)
            {
                throw new WalletResponseException(
                    $"The wallet response carries an encrypted 'response' beside a cleartext '{beside}'.");
            }

            var claims = await UnwrapResponseJwtAsync(SingleValue(jwtValues, "response")).ConfigureAwait(false);
            if (claims.Error is { } sealedError)
            {
                return new ParsedWalletResponse { Credentials = [], State = claims.State, Error = sealedError, Encrypted = true };
            }

            vpTokenJson = claims.VpTokenJson!;
            state = claims.State;
            encrypted = true;
        }
        else if (response.Form.TryGetValue("vp_token", out var vpValues))
        {
            vpTokenJson = SingleValue(vpValues, "vp_token");
            state = FormState(response.Form);
        }
        else if (_options.ReadErrorResponses && response.Form.TryGetValue("error", out var errorValues))
        {
            // SPEC: OpenID4VP 1.0 section 8.5, an Authorization Error Response. Read only when the form carries no
            // presentation, so an `error` field cannot hide one from the verifier, and only when the caller asked
            // for it (WalletResponseParserOptions.ReadErrorResponses).
            return new ParsedWalletResponse
            {
                Credentials = [],
                State = FormState(response.Form),
                Error = ErrorCode(SingleValue(errorValues, "error")),
            };
        }
        else
        {
            throw new WalletResponseException("The wallet response carries neither 'vp_token', 'response' nor 'error'.");
        }

        return new ParsedWalletResponse
        {
            Credentials = ExtractCredentials(vpTokenJson),
            State = state,
            Encrypted = encrypted,
        };
    }

    /// <summary>
    /// The cleartext parameters that answer a request, a presentation or an error, and so cannot stand beside an
    /// encrypted <c>response</c> on either transport.
    /// </summary>
    private static readonly string[] CleartextAnswerParameters = ["vp_token", "error"];

    private static string? FormState(IReadOnlyDictionary<string, IReadOnlyList<string>> form) =>
        form.TryGetValue("state", out var values) ? SingleValue(values, "state") : null;

    /// <summary>The longest error code accepted. RFC 6749 sets none; the codes it and OpenID4VP define are far shorter.</summary>
    private const int MaxErrorCodeLength = 64;

    // SPEC: RFC 6749 section 4.1.2.1: values for the "error" parameter "MUST NOT include characters outside the
    // set %x20-21 / %x23-5B / %x5D-7E". Enforced because the code is written into results and logs.
    private static string ErrorCode(string value) =>
        value.Length is > 0 and <= MaxErrorCodeLength && value.All(c => c is >= '\x20' and <= '\x7E' and not '"' and not '\\')
            ? value
            : throw new WalletResponseException(
                "The wallet's error code is empty or too long, or uses characters RFC 6749 section 4.1.2.1 does not allow.");

    private static string SingleValue(IReadOnlyList<string> values, string name) =>
        values.Count == 1
            ? values[0]
            : throw new WalletResponseException($"The '{name}' form parameter must appear exactly once (found {values.Count}).");

    /// <summary>
    /// What a decrypted response carries: a <c>vp_token</c>, or, when the caller opted in, the code of an
    /// Authorization Error Response. Exactly one of the two is set.
    /// </summary>
    private readonly record struct ResponseClaims(string? VpTokenJson, string? State, string? Error);

    private async Task<ResponseClaims> UnwrapResponseJwtAsync(string responseJwt)
    {
        // Through CompactJwt, which is where this library states what a malformed token looks like.
        // Written inline this named one of the constructor's two complaints and let the other escape the
        // parser, so a caller that had correctly wrapped this in a WalletResponseException handler could
        // still meet an exception it had no reason to expect.
        if (!CompactJwt.TryParse(responseJwt, out var jwe))
        {
            throw new WalletResponseException("The response parameter is not a well-formed JWT/JWE.");
        }

        // SPEC: OpenID4VP 1.0 §8.3: "To encrypt the Authorization Response, implementations MUST use an
        // unsigned, encrypted JWT". A response parameter that is not a JWE is therefore not a
        // direct_post.jwt response. It is refused here, before the handler below, which does not require
        // a signature.
        if (!jwe.IsEncrypted)
        {
            throw new WalletResponseException(
                "The response parameter is not encrypted. OpenID4VP 1.0 §8.3 requires an unsigned, encrypted JWT (a JWE).");
        }

        // Before any key is looked up: these rules hold whatever the key, and a response that breaks them
        // should not cost a key store lookup.
        JweHeaderRules.Enforce(jwe);

        // Keys are ephemeral per authorization request, so the resolver picks the session's key by the
        // kid the wallet echoes from our client_metadata. The fixed key remains for single-key callers.
        var decryptionKey = _options.ResponseDecryptionKeyResolver is { } resolve
            ? resolve(jwe.Kid is { Length: > 0 } kid ? kid : null)
            : _options.ResponseDecryptionKey;

        if (decryptionKey is null)
        {
            throw new WalletResponseException(_options.ResponseDecryptionKeyResolver is null
                ? "Received an encrypted wallet response but no ResponseDecryptionKey is configured."
                : "The encrypted wallet response names no known response-encryption key: its kid matches "
                  + "no live session, so the session may have expired or the response may be a replay.");
        }

        // SPEC: OpenID4VP 1.0 §8.3 — the response JWT is encrypted to the verifier's client_metadata
        // key (JARM). HAIP profiles it as encrypted-only, so no wallet signature is required here.
        // ECDH-ES (what HAIP wallets send) needs our own receive side; IdentityModel only ships the
        // sender half. Everything else (dir, RSA-OAEP, …) goes through the library handler.
        if (EcdhEsJweDecryptor.CanHandle(jwe))
        {
            var plaintext = EcdhEsJweDecryptor.Decrypt(jwe, decryptionKey);
            return ExtractResponseClaims(NormalizeDecryptedPayload(plaintext), DecryptedSource);
        }

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(responseJwt, new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            RequireSignedTokens = false,
            TokenDecryptionKey = decryptionKey,
        }).ConfigureAwait(false);

        if (!result.IsValid)
        {
            throw new WalletResponseException(
                "The encrypted wallet response could not be decrypted with the configured key, or its content is not a readable JWT.",
                result.Exception);
        }

        // Read by the same ExtractResponseClaims as the ECDH-ES route, from the decrypted token's own payload,
        // so the response parameters are read one way whichever key decrypted them. The handler's typed
        // claims would be a second reading of the same JSON, free to disagree with the first.
        if (result.SecurityToken is not JsonWebToken { InnerToken: { } inner })
        {
            throw new WalletResponseException("The encrypted wallet response decrypted to no token.");
        }

        return ExtractResponseClaims(Base64UrlEncoder.Decode(inner.EncodedPayload), DecryptedSource);
    }

    /// <summary>What <see cref="ExtractResponseClaims"/> calls a payload that arrived encrypted.</summary>
    private const string DecryptedSource = "decrypted wallet response";

    /// <summary>
    /// A decrypted response is either the response-parameter JSON directly, or a nested (typically
    /// unsigned — the JWE's AEAD provides integrity) JWT whose payload carries the parameters.
    /// </summary>
    private static string NormalizeDecryptedPayload(string plaintext)
    {
        if (plaintext.TrimStart().StartsWith('{'))
        {
            return plaintext;
        }

        // The plaintext is attacker-reachable despite arriving from a decryption: ECDH-ES is anonymous
        // key agreement, so anyone holding the client_metadata public key can encrypt a payload of their
        // choosing to it. The nested JWT here is therefore untrusted input like any other.
        if (!CompactJwt.TryParse(plaintext, out var nested))
        {
            throw new WalletResponseException("The decrypted wallet response is neither JSON nor a nested JWT.");
        }

        return Base64UrlEncoder.Decode(nested.EncodedPayload);
    }

    /// <summary>
    /// Reads the response parameters from a JSON object: a decrypted payload or the cleartext object a
    /// Digital Credentials API response returns. <paramref name="source"/> names it in the messages.
    /// </summary>
    private ResponseClaims ExtractResponseClaims(string payloadJson, string source)
    {
        // A decrypted payload is untrusted input (see NormalizeDecryptedPayload), and so is a cleartext one,
        // so a payload that only looks like JSON is a malformed response, answered like every other, not an
        // exception that escapes the parser. StrictJson holds it to the credential's rules: a parameter named
        // twice, such as a second vp_token or response beside the one verified, has no single meaning, and a
        // name or string that is not valid text would fail whichever later read unescapes it.
        using var document = ParseResponseJson(payloadJson, source);
        // The response parameters are members of an object, and the reads below need one.
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new WalletResponseException($"The {source} is not a JSON object.");
        }

        var state = document.RootElement.TryGetProperty("state", out var stateProp)
                    && stateProp.ValueKind == JsonValueKind.String
            ? stateProp.GetString()
            : null;

        if (!document.RootElement.TryGetProperty("vp_token", out var vpToken))
        {
            // SPEC: OpenID4VP 1.0 section 5.6: "Both successful and error responses SHOULD be returned using the
            // supplied Response Mode", so under direct_post.jwt a wallet should seal its Authorization Error
            // Response here. No section defines that payload, so it is read as the cleartext form's fields and
            // under that form's rules: only with a vp_token absent, only when the caller opted in, and only a code
            // RFC 6749 allows.
            if (_options.ReadErrorResponses && document.RootElement.TryGetProperty("error", out var error))
            {
                return new ResponseClaims(null, state, error.ValueKind == JsonValueKind.String
                    ? ErrorCode(error.GetString()!)
                    : throw new WalletResponseException($"The {source}'s error is not a string."));
            }

            throw new WalletResponseException($"The {source} carries no vp_token claim.");
        }

        var vpTokenJson = vpToken.ValueKind == JsonValueKind.String ? vpToken.GetString()! : vpToken.GetRawText();
        return new ResponseClaims(vpTokenJson, state, null);
    }

    private List<PresentedCredential> ExtractCredentials(string vpTokenJson)
    {
        JsonElement root;
        try
        {
            using var document = StrictJson.ParseDocument(vpTokenJson);
            root = document.RootElement.Clone();
        }
        catch (JsonException) when (IsNotJson(vpTokenJson))
        {
            // A bare compact serialization (not JSON) is a single presentation string.
            return [MakeCredential(vpTokenJson)];
        }
        catch (JsonException e)
        {
            // JSON that breaks StrictJson's rules is not a presentation string either, so it is not read as one.
            throw new WalletResponseException($"The vp_token in the wallet response is not JSON with {StrictJson.Accepts}.", e);
        }

        // SPEC: OpenID4VP 1.0 §8.1 — vp_token is a JSON object mapping each DCQL Credential Query id
        // to an array of one or more presentations. Strings and single values are handled leniently
        // for pre-final wallets.
        var credentials = new List<PresentedCredential>();
        switch (root.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var query in root.EnumerateObject())
                {
                    CollectPresentations(query.Value, credentials);
                }

                break;
            case JsonValueKind.Array or JsonValueKind.String:
                CollectPresentations(root, credentials);
                break;
            default:
                throw new WalletResponseException("vp_token is neither a JSON object, an array, nor a string.");
        }

        if (credentials.Count == 0)
        {
            throw new WalletResponseException("vp_token contains no presentations.");
        }

        return credentials;
    }

    private void CollectPresentations(JsonElement element, List<PresentedCredential> credentials)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.String:
                credentials.Add(MakeCredential(element.GetString()!));
                break;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    CollectPresentations(item, credentials);
                }

                break;
            default:
                throw new WalletResponseException($"Unsupported presentation value of kind {element.ValueKind} in vp_token.");
        }
    }

    /// <summary>
    /// Parses a wallet response's JSON under <see cref="StrictJson"/>, the rules the library's credential and
    /// response JSON is held to. A refusal is a malformed response. The form a redirect wallet posts already
    /// refuses a repeated field (<see cref="SingleValue"/>), so this holds the JSON forms to the same rule. The
    /// refusal's own message is fixed text, so the sender's text does not reach it.
    /// </summary>
    private static JsonDocument ParseResponseJson(string json, string source)
    {
        try
        {
            return StrictJson.ParseDocument(json);
        }
        catch (JsonException e)
        {
            throw new WalletResponseException($"The {source} is not JSON with {StrictJson.Accepts}.", e);
        }
    }

    /// <summary>
    /// True only for text that is not JSON at all, which is how a bare compact presentation arrives. JSON that
    /// breaks StrictJson's rules is JSON, and a string that is not valid UTF-16 is not a presentation either.
    /// </summary>
    private static bool IsNotJson(string text)
    {
        try
        {
            using var _ = JsonDocument.Parse(text);
            return false;
        }
        catch (JsonException)
        {
            return true;
        }
        catch (ArgumentException)
        {
            // A string that is not valid UTF-16, which a host's own form reading can hand over.
            return false;
        }
    }

    private PresentedCredential MakeCredential(string presentation) => new()
    {
        Format = _options.PresentationFormat,
        RawValue = presentation,
    };
}
