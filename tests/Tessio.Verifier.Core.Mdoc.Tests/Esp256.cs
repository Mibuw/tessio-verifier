using System.Formats.Cbor;
using System.Security.Cryptography;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// Re-signs a COSE_Sign1 under ESP256 (-9), which the platform cannot sign: the protected alg becomes -9 and
/// the signature is made over the new Sig_structure. Every other header, the payload and the tag are kept.
/// </summary>
/// <remarks>
/// It builds the Sig_structure the way the library's verifier does, so a mistake shared by both would cancel
/// out. <c>CoseSign1VerificationTests.TheTestSigner_MatchesThePlatform</c> guards that: under -7 this signer's
/// output must verify with the platform's own COSE implementation.
/// </remarks>
internal static class Esp256
{
    public static byte[] Resign(byte[] coseSign1, ECDsa key, byte[]? detachedContent = null, int alg = -9) =>
        Resign(coseSign1, key, detachedContent, w => w.WriteInt32(alg));

    /// <summary>Re-signs with alg written as text, which COSE allows only for registered names; for refusal tests.</summary>
    public static byte[] ResignWithTextAlg(byte[] coseSign1, ECDsa key, string alg) =>
        Resign(coseSign1, key, null, w => w.WriteTextString(alg));

    private static byte[] Resign(byte[] coseSign1, ECDsa key, byte[]? detachedContent, Action<CborWriter> writeAlg)
    {
        var reader = new CborReader(coseSign1, CborConformanceMode.Lax);
        var tagged = reader.PeekState() == CborReaderState.Tag;
        if (tagged)
        {
            reader.ReadTag();
        }

        reader.ReadStartArray();
        var protectedBytes = reader.ReadByteString();
        var unprotected = reader.ReadEncodedValue();
        byte[]? payload = null;
        if (reader.PeekState() == CborReaderState.Null)
        {
            reader.ReadNull();
        }
        else
        {
            payload = reader.ReadByteString();
        }

        reader.ReadByteString();
        reader.ReadEndArray();

        var newProtected = WithAlg(protectedBytes, writeAlg);
        var signature = key.SignData(
            SigStructure(newProtected, payload ?? detachedContent ?? throw new ArgumentException("A detached message needs its content.")),
            HashAlgorithmName.SHA256);

        var writer = new CborWriter(CborConformanceMode.Lax);
        if (tagged)
        {
            writer.WriteTag((CborTag)18);
        }

        writer.WriteStartArray(4);
        writer.WriteByteString(newProtected);
        writer.WriteEncodedValue(unprotected.Span);
        if (payload is null)
        {
            writer.WriteNull();
        }
        else
        {
            writer.WriteByteString(payload);
        }

        writer.WriteByteString(signature);
        writer.WriteEndArray();
        return writer.Encode();
    }

    /// <summary>
    /// Signs an embedded COSE_Sign1 with these exact protected and unprotected header maps, for shapes the platform
    /// refuses to sign, such as a crit naming a label that is not in the protected bucket. It signs with ECDSA and
    /// SHA-256 under <paramref name="key"/>, so the alg the caller writes into the protected map must say so.
    /// </summary>
    public static byte[] SignWithHeaders(byte[] protectedMap, byte[] unprotectedMap, byte[] payload, ECDsa key)
    {
        var signature = key.SignData(SigStructure(protectedMap, payload), HashAlgorithmName.SHA256);
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteTag((CborTag)18);
        writer.WriteStartArray(4);
        writer.WriteByteString(protectedMap);
        writer.WriteEncodedValue(unprotectedMap);
        writer.WriteByteString(payload);
        writer.WriteByteString(signature);
        writer.WriteEndArray();
        return writer.Encode();
    }

    // RFC 9052 section 4.4, for a COSE_Sign1: [ "Signature1", body_protected, external_aad, payload ].
    private static byte[] SigStructure(byte[] protectedBytes, byte[] content)
    {
        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartArray(4);
        w.WriteTextString("Signature1");
        w.WriteByteString(protectedBytes);
        w.WriteByteString([]);
        w.WriteByteString(content);
        w.WriteEndArray();
        return w.Encode();
    }

    private static byte[] WithAlg(byte[] protectedBytes, Action<CborWriter> writeAlg)
    {
        var reader = new CborReader(protectedBytes, CborConformanceMode.Lax);
        var count = reader.ReadStartMap() ?? throw new InvalidOperationException("Expected a definite-length map.");
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(count);
        for (var i = 0; i < count; i++)
        {
            var key = reader.ReadEncodedValue();
            var value = reader.ReadEncodedValue();
            writer.WriteEncodedValue(key.Span);
            if (key.Span.SequenceEqual(new byte[] { 0x01 }))
            {
                writeAlg(writer);
            }
            else
            {
                writer.WriteEncodedValue(value.Span);
            }
        }

        reader.ReadEndMap();
        writer.WriteEndMap();
        return writer.Encode();
    }
}
