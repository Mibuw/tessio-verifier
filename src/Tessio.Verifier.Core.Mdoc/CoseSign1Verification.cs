using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Verifies a COSE_Sign1 signature, adding ESP256 (-9) to what the platform verifies. Every COSE_Sign1 signature
/// this library checks itself goes through here. (A zero knowledge proof's issuer signature is checked inside
/// the proof, not here.)
/// </summary>
/// <remarks>
/// SPEC: HAIP 1.0 section 7 has verifiers support "ECDSA with P-256 and SHA-256 (… COSE algorithm identifier
/// -7 or -9, as applicable)" for the deviceSignature and for status information. RFC 9864 registers -9 as
/// "ESP256 … ECDSA using P-256 curve and SHA-256". The
/// platform's COSE implementation does not know -9 ("COSE algorithm '-9' is unknown"), so for it the
/// Sig_structure of RFC 9052 section 4.4 is built here and the signature checked directly. Every other
/// algorithm is left to the platform, as before.
/// </remarks>
internal static class CoseSign1Verification
{
    private const string P256Oid = "1.2.840.10045.3.1.7";

    /// <summary>The message's protected alg, or null when it carries none as an integer.</summary>
    internal static int? Algorithm(CoseSign1Message message) =>
        message.ProtectedHeaders.TryGetValue(CoseHeaderLabel.Algorithm, out var alg) && TryInt32(alg, out var value)
            ? value
            : null;

    /// <summary>
    /// Verifies a signature over the message's own (embedded) content. False for a message that carries none,
    /// which the platform would answer with an InvalidOperationException no caller expects.
    /// </summary>
    internal static bool VerifyEmbedded(CoseSign1Message message, AsymmetricAlgorithm key) =>
        message.Content is { } content
        && (Algorithm(message) == CoseAlgorithms.Esp256 ? VerifyEsp256(message, key, content.Span) : message.VerifyEmbedded(key));

    /// <summary>
    /// Verifies a signature over <paramref name="content"/>, which the message must not carry itself. False for
    /// one that does, which the platform would answer with an InvalidOperationException no caller expects.
    /// </summary>
    internal static bool VerifyDetached(CoseSign1Message message, AsymmetricAlgorithm key, byte[] content) =>
        message.Content is null
        && (Algorithm(message) == CoseAlgorithms.Esp256 ? VerifyEsp256(message, key, content) : message.VerifyDetached(key, content));

    // SPEC: RFC 9052 section 4.4, Sig_structure = [ context : "Signature1", body_protected, external_aad : bstr,
    // payload : bstr ] for a COSE_Sign1, with no sign_protected and an empty external_aad here. RFC 9053 section
    // 2.1 encodes the ECDSA signature as r || s, which is the IEEE P1363 form VerifyData reads by default.
    private static bool VerifyEsp256(CoseSign1Message message, AsymmetricAlgorithm key, ReadOnlySpan<byte> content)
    {
        if (key is not ECDsa ecdsa || ecdsa.ExportParameters(includePrivateParameters: false).Curve.Oid?.Value != P256Oid)
        {
            // ESP256 names its curve. A P-384 or RSA key is not the algorithm the header declares.
            return false;
        }

        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartArray(4);
        writer.WriteTextString("Signature1");
        writer.WriteByteString(message.RawProtectedHeaders.Span);
        writer.WriteByteString([]);
        writer.WriteByteString(content);
        writer.WriteEndArray();

        return ecdsa.VerifyData(writer.Encode(), message.Signature.Span, HashAlgorithmName.SHA256);
    }

    private static bool TryInt32(CoseHeaderValue value, out int result)
    {
        try
        {
            result = value.GetValueAsInt32();
            return true;
        }
        catch (InvalidOperationException)
        {
            result = 0;
            return false;
        }
    }
}
