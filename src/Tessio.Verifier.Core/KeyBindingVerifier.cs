using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.Core;

/// <summary>
/// Verifies the Key Binding JWT (KB-JWT) of an SD-JWT presentation: typ, signature against the
/// holder's <c>cnf</c> key, audience, nonce, and the <c>sd_hash</c> binding to the presented credential.
/// </summary>
// SPEC: RFC 9901 §4.3 (KB-JWT requirements) and §4.3.1 (sd_hash computation).
internal static class KeyBindingVerifier
{
    public static async Task<List<VerificationError>> VerifyAsync(
        string kbJwt,
        SecurityKey holderKey,
        VerificationContext context,
        string presentationWithoutKbJwt,
        DateTimeOffset now,
        TimeSpan maxAge,
        TimeSpan clockSkew,
        CancellationToken ct,
        TransactionDataExpectation? transactionData = null)
    {
        var errors = new List<VerificationError>();

        if (!CompactJwt.TryParse(kbJwt, out var token))
        {
            errors.Add(Error(ErrorCodes.KeyBindingInvalid, "The KB-JWT is not a well-formed JWT."));
            return errors;
        }

        // SPEC: RFC 9901 §4.3 — typ MUST be "kb+jwt" and alg MUST NOT be "none".
        if (!string.Equals(token.Typ, SdJwtConstants.KbJwtTyp, StringComparison.Ordinal))
        {
            errors.Add(Error(ErrorCodes.KeyBindingInvalid, $"KB-JWT typ is '{token.Typ}'; expected '{SdJwtConstants.KbJwtTyp}'."));
        }

        if (!SdJwtConstants.AllowedAlgorithms.Contains(token.Alg))
        {
            errors.Add(Error(ErrorCodes.AlgorithmNotAllowed, $"KB-JWT algorithm '{token.Alg}' is not permitted."));
            return errors; // Do not attempt signature validation with a forbidden algorithm.
        }

        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(kbJwt, new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            RequireSignedTokens = true,
            IssuerSigningKey = holderKey,
        }).ConfigureAwait(false);

        if (!validation.IsValid)
        {
            errors.Add(Error(ErrorCodes.KeyBindingInvalid, "The KB-JWT signature does not verify against the credential's cnf key."));
            return errors;
        }

        // Read as the issuer-signed payload is, so a repeated member has no meaning to pick, and so a claim's
        // JSON type can be checked: the handler's claims give a string "1700000000" and the number alike.
        JsonObject payload;
        try
        {
            payload = (JsonObject)StrictJson.Parse(Base64UrlEncoder.DecodeBytes(token.EncodedPayload))!;
        }
        catch (JsonException)
        {
            errors.Add(Error(ErrorCodes.KeyBindingInvalid, $"The KB-JWT payload is not JSON with {StrictJson.Accepts}."));
            return errors;
        }

        // SPEC: RFC 9901 §4.3 — aud, nonce, and iat are REQUIRED; nonce/aud bind the presentation
        // to this verifier's challenge (replay protection).
        if (!token.Audiences.Contains(context.Audience, StringComparer.Ordinal))
        {
            errors.Add(Error(ErrorCodes.AudienceMismatch, "The KB-JWT aud does not match this verifier."));
        }

        var nonce = token.TryGetClaim("nonce", out var nonceClaim) ? nonceClaim.Value : null;
        if (!string.Equals(nonce, context.Nonce, StringComparison.Ordinal))
        {
            errors.Add(Error(ErrorCodes.NonceMismatch, "The KB-JWT nonce does not match the challenge issued for this session."));
        }

        // SPEC: RFC 9901 §4.3 — iat is REQUIRED. Its freshness is verifier policy, and it matters:
        // a presentation is made in response to this verifier's live request, so an iat far in the
        // past is stale or replayed, and one far in the future is a wrong or spoofed clock. Checking
        // only its presence, as this once did, accepts both. The conformance suite skews iat by a year
        // each way and expects rejection.
        if (!payload.TryGetPropertyValue("iat", out var iatNode))
        {
            errors.Add(Error(ErrorCodes.KeyBindingInvalid, "The KB-JWT is missing the required iat claim."));
        }
        else if (UnixTime.TryFromNumericDate(iatNode, out var iat))
        {
            var oldest = maxAge == Timeout.InfiniteTimeSpan ? DateTimeOffset.MinValue : now - maxAge - clockSkew;
            if (iat < oldest)
            {
                errors.Add(Error(ErrorCodes.KeyBindingInvalid, "The KB-JWT iat is too far in the past; the presentation is stale."));
            }
            else if (iat > now + clockSkew)
            {
                errors.Add(Error(ErrorCodes.KeyBindingInvalid, "The KB-JWT iat is in the future beyond the tolerated clock skew."));
            }
        }
        else
        {
            errors.Add(Error(ErrorCodes.KeyBindingInvalid, "The KB-JWT iat is not a numeric timestamp."));
        }

        // SPEC: RFC 9901 §4.3.1 — sd_hash = base64url(sha-256(US-ASCII(<presentation without KB-JWT>))),
        // using the credential's _sd_alg hash (sha-256 enforced earlier in the pipeline).
        var expectedSdHash = Base64UrlEncoder.Encode(
            SHA256.HashData(Encoding.ASCII.GetBytes(presentationWithoutKbJwt)));
        var sdHash = token.TryGetClaim("sd_hash", out var sdHashClaim) ? sdHashClaim.Value : null;
        if (!string.Equals(sdHash, expectedSdHash, StringComparison.Ordinal))
        {
            errors.Add(Error(ErrorCodes.SdHashMismatch, "The KB-JWT sd_hash does not match the presented credential and disclosures."));
        }

        if (transactionData is not null)
        {
            CheckTransactionData(token, transactionData, errors);
        }

        return errors;
    }

    // SPEC: OpenID4VP 1.0 Annex B.3.3.1 — transaction_data_hashes is a non-empty array of
    // base64url hashes, each computed over the transaction_data request string as received (no
    // base64url decoding before hashing). transaction_data_hashes_alg is REQUIRED in the response
    // iff the request constrained it; the default hash is sha-256.
    private static void CheckTransactionData(
        JsonWebToken token, TransactionDataExpectation expectation, List<VerificationError> errors)
    {
        if (!token.TryGetPayloadValue<string[]>("transaction_data_hashes", out var hashes) || hashes.Length == 0)
        {
            errors.Add(Error(ErrorCodes.TransactionDataMissing,
                "The request carried transaction_data, but the KB-JWT has no transaction_data_hashes."));
            return;
        }

        token.TryGetPayloadValue<string>("transaction_data_hashes_alg", out var alg);
        if (expectation.AllowedHashAlgorithms is { Count: > 0 } allowed)
        {
            if (alg is null || !allowed.Contains(alg, StringComparer.Ordinal))
            {
                errors.Add(Error(ErrorCodes.TransactionDataAlgUnsupported,
                    $"The KB-JWT transaction_data_hashes_alg '{alg ?? "(absent)"}' is not one the request allows."));
                return;
            }
        }
        else if (alg is not null && !string.Equals(alg, "sha-256", StringComparison.Ordinal))
        {
            errors.Add(Error(ErrorCodes.TransactionDataAlgUnsupported,
                $"The request did not constrain the hash algorithm, so sha-256 is required; the KB-JWT declares '{alg}'."));
            return;
        }

        if (HashFor(alg ?? "sha-256") is not { } hash)
        {
            errors.Add(Error(ErrorCodes.TransactionDataAlgUnsupported,
                $"The transaction data hash algorithm '{alg}' is not supported."));
            return;
        }

        if (hashes.Length != expectation.TransactionData.Count)
        {
            errors.Add(Error(ErrorCodes.TransactionDataHashMismatch,
                $"The KB-JWT carries {hashes.Length} transaction data hash(es); the request sent {expectation.TransactionData.Count}."));
            return;
        }

        for (var i = 0; i < hashes.Length; i++)
        {
            var expected = Base64UrlEncoder.Encode(hash(Encoding.ASCII.GetBytes(expectation.TransactionData[i])));
            if (!string.Equals(hashes[i], expected, StringComparison.Ordinal))
            {
                errors.Add(Error(ErrorCodes.TransactionDataHashMismatch,
                    $"transaction_data_hashes[{i}] does not match the transaction data sent in the request."));
            }
        }
    }

    private static Func<byte[], byte[]>? HashFor(string alg) => alg switch
    {
        "sha-256" => SHA256.HashData,
        "sha-384" => SHA384.HashData,
        "sha-512" => SHA512.HashData,
        _ => null,
    };

    private static VerificationError Error(string code, string message) => new() { Code = code, Message = message };
}
