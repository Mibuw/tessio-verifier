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
        Assert.True(CoseSign1Verification.VerifyEmbedded(message, key));
    }

    [Fact]
    public void ADetachedEsp256Signature_Verifies_OnlyOverItsContent()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var message = CoseMessage.DecodeSign1(SignedUnder(CoseAlgorithms.Esp256, key, detached: true));

        Assert.True(CoseSign1Verification.VerifyDetached(message, key, Payload));
        Assert.False(CoseSign1Verification.VerifyDetached(message, key, [9, 9, 9]));
    }

    [Fact]
    public void AnEsp256Signature_ByAnotherKey_Fails()
    {
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var message = CoseMessage.DecodeSign1(SignedUnder(CoseAlgorithms.Esp256, signer));

        Assert.False(CoseSign1Verification.VerifyEmbedded(message, other));
    }

    [Fact]
    public void Esp256_OnAKeyOffP256_Fails()
    {
        // ESP256 names its curve. A P-384 key signing over SHA-256 is not the algorithm the header declares.
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var message = CoseMessage.DecodeSign1(SignedUnder(CoseAlgorithms.Esp256, key));

        Assert.False(CoseSign1Verification.VerifyEmbedded(message, key));
    }
}
