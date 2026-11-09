using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.Core;

/// <summary>
/// A JWK from outside that verifies a signature, read by its key members alone. Whatever certificates it carries
/// are dropped once the JWK is parsed and before any key is built from it, so they are never loaded and never used
/// in place of the key members.
/// </summary>
/// <remarks>
/// The keys that verify a signature are judged by their key members: a holder key bound by <c>cnf.jwk</c>, and an
/// issuer key from JWT VC Issuer Metadata, trusted through the metadata's origin. Neither is judged by a
/// certificate inside it. Dropped from the parsed key rather than from the JSON, because the parser reads the
/// member's name in any case, so only the parsed list is certain to hold every certificate the JWK carries.
/// </remarks>
// SPEC: RFC 7517 section 4.7, "The key in the first certificate MUST match the public key represented by other
// members of the JWK. Use of this member is OPTIONAL." RFC 7518 section 6.3.1 and 6.2.1 make the key members
// themselves required ("MUST be present"), so a JWK whose only key is in a certificate yields no key here.
internal static class JwkKeyMembers
{
    /// <summary>
    /// The key the JWK in <paramref name="json"/> names by its key members, built from them alone. Returned as that
    /// key rather than as the JWK, so a signature check identifies it by the key itself and never by the JWK it
    /// came from.
    /// </summary>
    /// <exception cref="ArgumentException">The JSON is not a JWK, or its key members make no key.</exception>
    public static SecurityKey Key(string json)
    {
        var key = new JsonWebKey(json);
        key.X5c.Clear();
        return JsonWebKeyConverter.TryConvertToSecurityKey(key, out var built)
            ? built
            : throw new ArgumentException("The JWK's key members make no key.", nameof(json));
    }

    /// <summary>
    /// The signing keys the JWK Set in <paramref name="json"/> names, each built from its key members alone. A JWK
    /// that makes no signing key is left out rather than handed on as the JWK, whatever the process-wide default.
    /// </summary>
    /// <exception cref="ArgumentException">The JSON is not a JWK Set.</exception>
    public static List<SecurityKey> SigningKeys(string json)
    {
        var set = new JsonWebKeySet(json) { SkipUnresolvedJsonWebKeys = true };
        foreach (var key in set.Keys)
        {
            key.X5c.Clear();
        }

        return set.GetSigningKeys().ToList();
    }
}
