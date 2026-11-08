using System.Text.Json.Nodes;
using Tessio.Verifier.Core;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// Builder for the OpenID4VP <c>client_metadata</c> object, producing the JSON string expected by
/// <see cref="PresentationRequestOptions.ClientMetadataJson"/>.
/// </summary>
/// <remarks>
/// One builder, deliberately. This object used to be assembled independently by the library and by a
/// consuming application, which is invisible to a duplicate detector because the two versions were
/// structurally different while meaning the same thing. They drifted, and the OpenID Foundation
/// conformance suite found the consumer advertising values HAIP rejects long after the library had been
/// fixed. Anything that sends a presentation request should call this rather than hand-rolling the object.
/// </remarks>
// SPEC: OpenID4VP 1.0 §5.1, narrowed by openid/OpenID4VP#233 to exactly three members. HAIP 1.0 §5
// constrains the encryption values further.
public static class ClientMetadata
{
    // SPEC: RFC 7518. ES256 is the signature algorithm EUDI issuers and wallets use. For mdoc, which names
    // algorithms by COSE identifier, the advertised list is CoseAlgorithms.Advertised, owned beside the
    // verifiers that must accept every value on it.
    private const string Es256 = "ES256";

    /// <summary>
    /// Builds <c>client_metadata</c> for a request in the given credential format.
    /// </summary>
    /// <param name="credentialFormat"><c>dc+sd-jwt</c> or <c>mso_mdoc</c>.</param>
    /// <param name="responseEncryptionJwk">
    /// The public half of the response-encryption key, for <c>direct_post.jwt</c>. Null for
    /// <c>direct_post</c>, where there is nothing for the wallet to encrypt to. HAIP requires
    /// encrypted responses, so in practice this is supplied.
    /// </param>
    /// <returns>The <c>client_metadata</c> JSON.</returns>
    public static string Build(string credentialFormat, JsonObject? responseEncryptionJwk = null) =>
        Build(credentialFormat, responseEncryptionJwk, additionalMembers: null);

    /// <summary>
    /// Builds <c>client_metadata</c> as <see cref="Build(string, JsonObject?)"/> does, adding members a particular
    /// wallet asks for beside the standard ones.
    /// </summary>
    /// <param name="credentialFormat"><c>dc+sd-jwt</c> or <c>mso_mdoc</c>.</param>
    /// <param name="responseEncryptionJwk">The public half of the response-encryption key, or null.</param>
    /// <param name="additionalMembers">
    /// Members to add, such as a wallet's own relying party metadata. Each value is copied. A member this builder
    /// writes itself cannot be replaced from here, so a caller cannot weaken what the standard members advertise.
    /// </param>
    /// <returns>The <c>client_metadata</c> JSON.</returns>
    /// <exception cref="ArgumentException">A name in <paramref name="additionalMembers"/> is one this builder writes.</exception>
    // SPEC: OpenID4VP 1.0 §5.1: "Other metadata parameters MUST be ignored unless a profile of this specification
    // explicitly defines them as usable in the client_metadata parameter." So an additional member is for a wallet
    // or profile that defines it, and every other wallet ignores it. The standard members stay the three the class
    // header names, written only by this builder.
    public static string Build(
        string credentialFormat,
        JsonObject? responseEncryptionJwk,
        IReadOnlyDictionary<string, JsonNode?>? additionalMembers)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialFormat);
        return WithAdditionalMembers(Standard(VpFormatsSupported(credentialFormat), responseEncryptionJwk), additionalMembers);
    }

    private static string WithAdditionalMembers(
        JsonObject metadata, IReadOnlyDictionary<string, JsonNode?>? additionalMembers)
    {
        foreach (var (name, value) in additionalMembers ?? new Dictionary<string, JsonNode?>())
        {
            if (metadata.ContainsKey(name) || StandardMemberNames.Contains(name))
            {
                throw new ArgumentException(
                    $"client_metadata member '{name}' is written by this builder and cannot be replaced.",
                    nameof(additionalMembers));
            }

            metadata[name] = value?.DeepClone();
        }

        return metadata.ToJsonString(JsonDefaults.Relaxed);
    }

    /// <summary>
    /// Builds <c>client_metadata</c> for a request whose DCQL query asks for credentials in several formats, such as
    /// one built by <see cref="Dcql.AnyOf"/> offering a PID as an mdoc or as an SD-JWT VC.
    /// <c>vp_formats_supported</c> lists every format given, each once.
    /// </summary>
    /// <param name="credentialFormats">The formats the query names, at least one: <c>dc+sd-jwt</c>, <c>mso_mdoc</c> or both.</param>
    /// <param name="responseEncryptionJwk">The public half of the response-encryption key, or null.</param>
    /// <param name="additionalMembers">Members to add, as for <see cref="Build(string, JsonObject?, IReadOnlyDictionary{string, JsonNode?}?)"/>.</param>
    /// <returns>The <c>client_metadata</c> JSON.</returns>
    /// <exception cref="ArgumentException">
    /// No format is given, a format is neither of the two, or a name in <paramref name="additionalMembers"/> is one
    /// this builder writes.
    /// </exception>
    /// <remarks>
    /// SPEC: OpenID4VP 1.0 section 11.1, vp_formats_supported: "An object containing a list of name/value pairs,
    /// where the name is a Credential Format Identifier and the value defines format-specific parameters that a
    /// Verifier supports." A wallet holding only the format left out would find the request asks for nothing it can
    /// answer in. A format other than the two is refused here rather than advertised as SD-JWT VC, as the single
    /// format builder does with anything that is not <c>mso_mdoc</c>.
    /// </remarks>
    public static string BuildForFormats(
        IReadOnlyList<string> credentialFormats,
        JsonObject? responseEncryptionJwk = null,
        IReadOnlyDictionary<string, JsonNode?>? additionalMembers = null)
    {
        ArgumentNullException.ThrowIfNull(credentialFormats);
        if (credentialFormats.Count == 0)
        {
            throw new ArgumentException("client_metadata needs at least one credential format.", nameof(credentialFormats));
        }

        var formats = new JsonObject();
        foreach (var format in credentialFormats)
        {
            if (format is not (Dcql.SdJwtVcFormat or Dcql.MdocFormat))
            {
                throw new ArgumentException(
                    $"'{format}' is not a credential format this builder advertises: dc+sd-jwt or mso_mdoc.",
                    nameof(credentialFormats));
            }

            if (!formats.ContainsKey(format))
            {
                formats[format] = VpFormatsSupported(format)[format]!.DeepClone();
            }
        }

        return WithAdditionalMembers(Standard(formats, responseEncryptionJwk), additionalMembers);
    }

    /// <summary>Every member the standard builder may write, whether or not this call writes it.</summary>
    private static readonly HashSet<string> StandardMemberNames =
        ["vp_formats_supported", "jwks", "encrypted_response_enc_values_supported"];

    private static JsonObject Standard(JsonObject vpFormatsSupported, JsonObject? responseEncryptionJwk)
    {
        // Neither client_id nor client_name belongs here, and both used to. client_id is an
        // authorization request parameter. client_name was a display name for the consent screen, and
        // dropping it is the safer behaviour rather than a loss: under an x509 client identifier the
        // wallet takes the verifier's identity from the certificate, which is authenticated, whereas a
        // name asserted in metadata is not and would let anyone put someone else's brand on a consent
        // screen.
        var metadata = new JsonObject
        {
            // SPEC: OpenID4VP 1.0 Appendix B.2.2 (mdoc) and B.3.4 (SD-JWT VC) — REQUIRED, keyed by
            // credential format. Without it a wallet cannot learn which signature algorithms we accept,
            // and the EC reference wallet refuses the request outright.
            ["vp_formats_supported"] = vpFormatsSupported,
        };

        if (responseEncryptionJwk is not null)
        {
            // SPEC: OpenID4VP 1.0 §8.3 — the wallet encrypts a direct_post.jwt response to a key from
            // client_metadata.jwks (use=enc).
            metadata["jwks"] = new JsonObject { ["keys"] = new JsonArray(responseEncryptionJwk.DeepClone()) };

            // SPEC: HAIP 1.0 §5 requires BOTH of these. Advertising only A128CBC-HS256, as both copies
            // of this code once did, offers neither required value.
            metadata["encrypted_response_enc_values_supported"] = new JsonArray("A128GCM", "A256GCM");
        }

        return metadata;
    }

    /// <summary>The signature algorithms we accept, keyed by credential format.</summary>
    private static JsonObject VpFormatsSupported(string credentialFormat) =>
        credentialFormat == "mso_mdoc"
            ? new JsonObject
            {
                ["mso_mdoc"] = new JsonObject
                {
                    ["issuerauth_alg_values"] = AlgValues(CoseAlgorithms.Advertised),
                    ["deviceauth_alg_values"] = AlgValues(CoseAlgorithms.Advertised),
                },
            }
            : new JsonObject
            {
                ["dc+sd-jwt"] = new JsonObject
                {
                    ["sd-jwt_alg_values"] = new JsonArray(Es256),
                    ["kb-jwt_alg_values"] = new JsonArray(Es256),
                },
            };

    private static JsonArray AlgValues(IReadOnlyList<int> algorithms) =>
        new([.. algorithms.Select(static alg => (JsonNode)alg)]);
}
