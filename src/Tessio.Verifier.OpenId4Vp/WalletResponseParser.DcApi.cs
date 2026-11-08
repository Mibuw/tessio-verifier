// What belongs in this file: reading an OpenID4VP response returned through the Digital Credentials API,
// the object a page receives as DigitalCredential.data. The decryption and the reading of the response
// parameters are the redirect flow's own, in WalletResponseParser.cs, so both transports read a response
// one way.
using System.Text.Json;

namespace Tessio.Verifier.OpenId4Vp;

public sealed partial class WalletResponseParser
{
    /// <summary>
    /// Parses an OpenID4VP response returned through the Digital Credentials API: the JSON of the
    /// <c>data</c> member of the <c>DigitalCredential</c> the browser hands the page, which the page
    /// forwards to the verifier.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Under response mode <c>dc_api.jwt</c> the object carries one <c>response</c> member holding the JWE,
    /// decrypted with the same key resolution as <c>direct_post.jwt</c>. Under <c>dc_api</c> it carries the
    /// response parameters themselves. An Authorization Error Response is returned only when
    /// <see cref="WalletResponseParserOptions.ReadErrorResponses"/> is on, as for the other modes.
    /// </para>
    /// <para>
    /// <see cref="ParsedWalletResponse.State"/> is always null: <c>state</c> is not defined for this transport, so
    /// a value a wallet sends is not one the verifier asked for. The response is bound to its request by the
    /// origin and nonce instead, which verification checks.
    /// </para>
    /// <para>
    /// The caller still compares <see cref="ParsedWalletResponse.Encrypted"/> with the response mode its request
    /// asked for, as with <see cref="ParseDetailedAsync"/>.
    /// </para>
    /// </remarks>
    /// <param name="dataJson">The JSON text of the <c>data</c> object.</param>
    /// <param name="ct">Cancellation.</param>
    /// <exception cref="WalletResponseException">
    /// The object is malformed in any part its sender controls or cannot be decrypted.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// <see cref="WalletResponseParserOptions.DcqlQueryJson"/> was changed after construction to something the parser
    /// cannot read as a DCQL query.
    /// </exception>
    // SPEC: OpenID4VP 1.0 Appendix A.4: "the OpenID4VP Response parameters as defined for the Response Type are
    // represented as an object within the data property", and Appendix A.2: "For Response Mode dc_api.jwt, the
    // Wallet includes the response parameter, which contains an encrypted JWT encapsulating the Authorization
    // Response". A.2 also: "since the state parameter is not defined for the DC API, the Verifier cannot expect
    // it to be included in the response".
    public async Task<ParsedWalletResponse> ParseDcApiAsync(string dataJson, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(dataJson);
        var rules = AnswerRules();

        string? sealedResponse;
        using (var document = ParseResponseJson(dataJson, DcApiSource))
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new WalletResponseException($"The {DcApiSource} is not a JSON object.");
            }

            sealedResponse = SealedResponse(root);
        }

        if (sealedResponse is not null)
        {
            var claims = await UnwrapResponseJwtAsync(sealedResponse).ConfigureAwait(false);
            return claims.Error is { } sealedError
                ? new ParsedWalletResponse { Credentials = [], Error = sealedError, Encrypted = true }
                : new ParsedWalletResponse { Credentials = ExtractCredentials(claims.VpTokenJson!, rules), Encrypted = true };
        }

        var cleartext = ExtractResponseClaims(dataJson, DcApiSource);
        return cleartext.Error is { } error
            ? new ParsedWalletResponse { Credentials = [], Error = error }
            : new ParsedWalletResponse { Credentials = ExtractCredentials(cleartext.VpTokenJson!, rules) };
    }

    /// <summary>What the messages call the object this transport returns.</summary>
    private const string DcApiSource = "Digital Credentials API response";

    /// <summary>
    /// The JWE of a <c>dc_api.jwt</c> response, or null when the object carries no <c>response</c> member.
    /// </summary>
    private static string? SealedResponse(JsonElement root)
    {
        if (!root.TryGetProperty("response", out var response))
        {
            return null;
        }

        // An encrypted response and cleartext parameters beside it cannot both be the answer, and choosing one
        // would let the other ride along unread, so the pair is refused.
        if (CleartextAnswerParameters.Any(name => root.TryGetProperty(name, out _)))
        {
            throw new WalletResponseException(
                $"The {DcApiSource} carries an encrypted response beside cleartext response parameters.");
        }

        return response.ValueKind == JsonValueKind.String
            ? response.GetString()!
            : throw new WalletResponseException($"The {DcApiSource}'s response member is not a string.");
    }
}
