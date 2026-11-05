using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Core;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// Signs OpenID4VP request objects (RFC 9101): the JOSE header and the certificate chain rules, for every
/// builder that sends a signed request, whether to a redirect wallet or through the Digital Credentials API.
/// </summary>
/// <remarks>
/// One signer, deliberately, for the reason <see cref="RequestObjectClaims"/> is one assembler: a header rule
/// added to one builder and missed in another would make the two transports disagree about what a signed
/// request is, and nothing would notice until a wallet refused one of them.
/// </remarks>
internal sealed class RequestObjectSigner
{
    // Taken once, here, so the credentials and chain that were checked are the ones every request uses,
    // whatever is assigned to the caller's options afterwards. The chain is kept as its encoded x5c values,
    // so a certificate the caller disposes later cannot break signing.
    private readonly SigningCredentials _signingCredentials;
    private readonly string[]? _x5c;

    /// <summary>Checks the chain against the key and keeps both.</summary>
    /// <exception cref="ArgumentException">
    /// <paramref name="chain"/> breaks a path rule, or a certificate in it or the key cannot be read. Also when the
    /// leaf does not hold the signing key's public half.
    /// </exception>
    public RequestObjectSigner(
        SigningCredentials signingCredentials, IReadOnlyList<X509Certificate2>? chain, string parameterName,
        bool allowSelfSignedSigner = false)
    {
        ArgumentNullException.ThrowIfNull(signingCredentials);
        _signingCredentials = signingCredentials;
        _x5c = chain is null ? null : CheckChain(chain, signingCredentials.Key, parameterName, allowSelfSignedSigner);
    }

    /// <summary>The path rules, then that the leaf holds the signing key; returns the x5c values to send.</summary>
    // SPEC: RFC 7515 §4.1.6 — x5c is base64 (not base64url) DER, leaf certificate first.
    private static string[] CheckChain(
        IReadOnlyList<X509Certificate2> chain, SecurityKey key, string parameterName, bool allowSelfSignedSigner)
    {
        var path = chain.ToArray();
        try
        {
            ReaderCertificatePath.Check(path, parameterName, "x5c", allowSelfSignedSigner);

            // Only an ECDsaSecurityKey's public half can be read here. With the remote-signing pattern of
            // going-live.md that is the public half the caller declared, not the key that actually signs;
            // any other SecurityKey type is not compared at all. The options' remarks say both.
            if (key is ECDsaSecurityKey { ECDsa: { } ecdsa })
            {
                using var leafKey = path[0].GetECDsaPublicKey();
                if (leafKey is null
                    || !leafKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(ecdsa.ExportSubjectPublicKeyInfo()))
                {
                    throw new ArgumentException(
                        "The first certificate in SigningCertificateChain does not hold the public half of the signing "
                        + "key. The wallet verifies the request object against that certificate, so this pair would "
                        + "sign requests no wallet can verify.",
                        parameterName);
                }
            }
        }
        catch (Exception e) when (e is CryptographicException or NotSupportedException or InvalidOperationException)
        {
            // A disposed or malformed certificate, or a key provider that will not export, surfaces as
            // whatever the platform throws; a caller handles one documented type instead.
            throw new ArgumentException(
                $"The signing key or a certificate in SigningCertificateChain cannot be read: {e.Message}", parameterName, e);
        }

        return path.Select(c => Convert.ToBase64String(c.RawData)).ToArray();
    }

    /// <summary>Signs <paramref name="payload"/> as a request object issued at <paramref name="issuedAt"/>.</summary>
    public string Sign(JsonObject payload, DateTimeOffset issuedAt)
    {
        ArgumentNullException.ThrowIfNull(payload);

        // SPEC: OpenID4VP 1.0 §5 / RFC 9101: "Verifiers MUST include the typ Header Parameter in Request Objects with the
        // value oauth-authz-req+jwt".
        var headers = new Dictionary<string, object> { ["typ"] = "oauth-authz-req+jwt" };

        // SPEC: ETSI TS 119 472-2 V1.2.1 (2026-03) §6.4.2 OIDFVP-HAIP-REDIRECTS_RO-03, which CIR (EU) 2026/1731
        // applies and does not adapt: "The JWS Protected Header of the JWS signature on the RO shall incorporate
        // the iat header parameter." Same instant as the payload's iat, so the two cannot disagree.
        headers["iat"] = issuedAt.ToUnixTimeSeconds();

        // Required in practice: a wallet using the x509_san_dns client_id scheme has no other way to
        // obtain the certificate whose SAN it must match, so it rejects a signed request that omits this
        // as a malformed JAR, before any trust decision is reached. Observed with the EC reference wallet
        // as "InvalidJarJwt(cause=Missing x5c)". The chain was checked and encoded when this was created.
        if (_x5c is { } x5c)
        {
            headers["x5c"] = x5c;
        }

        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        return handler.CreateToken(payload.ToJsonString(JsonDefaults.Relaxed), _signingCredentials, headers);
    }
}
