using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// ESP256 (-9, RFC 9864) is verified by the library itself, because the platform does not know it. These pin
/// that verification against the platform's own -7, against tampering and against a key on the wrong curve.
/// </summary>
public class CoseSign1VerificationTests
{
    private static readonly byte[] Payload = [1, 2, 3, 4];

    private static byte[] SignedUnder(int alg, ECDsa key, bool detached = false)
    {
        var platform = detached
            ? CoseSign1Message.SignDetached(Payload, new CoseSigner(key, HashAlgorithmName.SHA256))
            : CoseSign1Message.SignEmbedded(Payload, new CoseSigner(key, HashAlgorithmName.SHA256));
        return Esp256.Resign(platform, key, detached ? Payload : null, alg);
    }

    [Fact]
    public void TheTestSigner_MatchesThePlatform()
    {
        // Under -7 the test signer's Sig_structure must be one the platform accepts. Otherwise the -9 tests below
        // would only show that the library and the test signer agree with each other.
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var message = CoseMessage.DecodeSign1(SignedUnder(-7, key));

        Assert.True(message.VerifyEmbedded(key));
    }

    [Fact]
    public void AnEsp256Signature_Verifies()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var message = CoseMessage.DecodeSign1(SignedUnder(CoseAlgorithms.Esp256, key));

        Assert.Equal(CoseAlgorithms.Esp256, CoseSign1Verification.Algorithm(message));
        Assert.True(CoseSign1Verification.VerifyEmbedded(message, key, [1]));
    }

    [Fact]
    public void ADetachedEsp256Signature_Verifies_OnlyOverItsContent()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var message = CoseMessage.DecodeSign1(SignedUnder(CoseAlgorithms.Esp256, key, detached: true));

        Assert.True(CoseSign1Verification.VerifyDetached(message, key, Payload, [1]));
        Assert.False(CoseSign1Verification.VerifyDetached(message, key, [9, 9, 9], [1]));
    }

    [Fact]
    public void AnEsp256Signature_ByAnotherKey_Fails()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var message = CoseMessage.DecodeSign1(SignedUnder(CoseAlgorithms.Esp256, signer));

        Assert.False(CoseSign1Verification.VerifyEmbedded(message, other, [1]));
    }

    [Fact]
    public void Esp256_OnAKeyOffP256_Fails()
    {
        // ESP256 names its curve. A P-384 key signing over SHA-256 is not the algorithm the header declares.
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var message = CoseMessage.DecodeSign1(SignedUnder(CoseAlgorithms.Esp256, key));

        Assert.False(CoseSign1Verification.VerifyEmbedded(message, key, [1]));
    }

    private static CoseSign1Message SignedWithCritical(ECDsa key, Action<CoseSigner> headers)
    {
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        headers(signer);
        return CoseMessage.DecodeSign1(CoseSign1Message.SignEmbedded(Payload, signer));
    }

    private static CoseHeaderValue CborArray(Action<CborWriter> items)
    {
        var writer = new CborWriter();
        writer.WriteStartArray(null);
        items(writer);
        writer.WriteEndArray();
        return CoseHeaderValue.FromEncodedValue(writer.Encode());
    }

    [Fact]
    public void AnUnknownCriticalHeader_FailsVerification_EvenWhenTheCallerDoesNotAskFirst()
    {
        // The platform verifies this signature (it ignores crit). The choke point does not, so a caller that skips
        // CriticalHeadersUnderstood still cannot accept it.
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var message = SignedWithCritical(key, s =>
        {
            s.ProtectedHeaders.Add(CoseHeaderLabel.CriticalHeaders, CborArray(w => w.WriteInt32(99)));
            s.ProtectedHeaders.Add(new CoseHeaderLabel(99), CoseHeaderValue.FromInt32(0));
        });

        Assert.True(message.VerifyEmbedded(key));
        Assert.False(CoseSign1Verification.VerifyEmbedded(message, key, [1]));
        Assert.True(CoseSign1Verification.VerifyEmbedded(message, key, [1, 99]));
    }

    // A COSE_Sign1 signed by hand with alg -7, for header shapes the platform refuses to sign.
    private static byte[] HandSigned(ECDsa key, Action<CborWriter> extraProtected, int extraCount, Action<CborWriter> unprotected, int unprotectedCount)
    {
        var protectedMap = new CborWriter();
        protectedMap.WriteStartMap(1 + extraCount);
        protectedMap.WriteInt32(1);
        protectedMap.WriteInt32(CoseAlgorithms.Es256);
        extraProtected(protectedMap);
        protectedMap.WriteEndMap();
        var unprotectedMap = new CborWriter();
        unprotectedMap.WriteStartMap(unprotectedCount);
        unprotected(unprotectedMap);
        unprotectedMap.WriteEndMap();
        return Esp256.SignWithHeaders(protectedMap.Encode(), unprotectedMap.Encode(), Payload, key);
    }

    private static void WriteCritical(CborWriter w, int label)
    {
        w.WriteInt32(2);
        w.WriteStartArray(1);
        w.WriteInt32(label);
        w.WriteEndArray();
    }

    [Fact]
    public void ACriticalAlg_IsUnderstood_AndVerifies()
    {
        // crit naming only alg, the one header every reader here processes. The platform cannot sign it.
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var message = CoseMessage.DecodeSign1(HandSigned(key, w => WriteCritical(w, 1), 1, static _ => { }, 0));

        Assert.True(CoseSign1Verification.CriticalHeadersUnderstood(message, [1]));
        Assert.True(CoseSign1Verification.VerifyEmbedded(message, key, [1]));
    }

    [Fact]
    public void TheDecoder_RefusesACriticalLabelMissingFromTheProtectedBucket()
    {
        // SPEC: RFC 9052 section 3.1, a crit label "for which the header parameter is not in the
        // protected-header-parameters bucket" is "a fatal error". The platform's decoder refuses it, so no such
        // message reaches CriticalHeadersUnderstood. Its own check stays in case that changes.
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var bytes = HandSigned(key, w => WriteCritical(w, 33), 1, w => { w.WriteInt32(33); w.WriteInt32(0); }, 1);

        Assert.Throws<CryptographicException>(() => CoseMessage.DecodeSign1(bytes));
    }

    public static TheoryData<string> MalformedCriticals() => ["empty array", "not an array", "a byte string entry"];

    [Theory]
    [MemberData(nameof(MalformedCriticals))]
    public void TheDecoder_RefusesAMalformedCritical(string shape)
    {
        // RFC 9052 section 3.1, "The array MUST have at least one value in it", and its entries are labels. The
        // platform's decoder refuses these too, which the comment on CriticalHeadersUnderstood relies on.
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var bytes = HandSigned(key, w =>
        {
            w.WriteInt32(2);
            switch (shape)
            {
                case "empty array":
                    w.WriteStartArray(0);
                    w.WriteEndArray();
                    break;
                case "not an array":
                    w.WriteInt32(1);
                    break;
                default:
                    w.WriteStartArray(1);
                    w.WriteByteString([1]);
                    w.WriteEndArray();
                    break;
            }
        }, 1, static _ => { }, 0);

        Assert.Throws<CryptographicException>(() => CoseMessage.DecodeSign1(bytes));
    }

    [Fact]
    public void ACriticalHeaderInTheUnprotectedBucket_IsRefused()
    {
        // SPEC: RFC 9052 section 3.1, "When present, the "crit" header parameter MUST be placed in the
        // protected-header-parameters bucket."
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var bytes = HandSigned(key, static _ => { }, 0, w => WriteCritical(w, 1), 1);

        var refused = false;
        try
        {
            refused = !CoseSign1Verification.CriticalHeadersUnderstood(CoseMessage.DecodeSign1(bytes), [1]);
        }
        catch (CryptographicException)
        {
            refused = true; // the decoder refusing it is a refusal too
        }

        Assert.True(refused);
    }

    [Fact]
    public void ACriticalTextLabel_IsRefused()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var message = SignedWithCritical(key, s =>
        {
            s.ProtectedHeaders.Add(CoseHeaderLabel.CriticalHeaders, CborArray(w => w.WriteTextString("x")));
            s.ProtectedHeaders.Add(new CoseHeaderLabel("x"), CoseHeaderValue.FromInt32(0));
        });

        Assert.False(CoseSign1Verification.CriticalHeadersUnderstood(message, [1]));
    }

    [Fact]
    public void NoCriticalHeader_IsUnderstood()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var message = SignedWithCritical(key, static _ => { });

        Assert.True(CoseSign1Verification.CriticalHeadersUnderstood(message, [1]));
    }
}
