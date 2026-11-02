using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>Outcome of issuerAuth signature verification and Document Signer key resolution.</summary>
internal sealed record IssuerAuthResolution
{
    /// <summary>Document Signer certificate subject (the mdoc issuer identifier we report).</summary>
    public required string Issuer { get; init; }

    /// <summary>DER chain from x5chain, DS certificate first, for the trust seam.</summary>
    public required ReadOnlyMemory<byte>[] CertificateChain { get; init; }
}

/// <summary>
/// Verifies the <c>issuerAuth</c> COSE_Sign1 over the MSO: algorithm allowlist, Document Signer key
/// from the <c>x5chain</c> header (RFC 9360, single certificate or array form) and the signature.
/// Chain trust is decided by the caller's <see cref="Trust.ITrustListResolver"/>.
/// </summary>
// SPEC: ISO/IEC 18013-5 §9.3.1 — issuer data authentication.
internal static class IssuerAuthVerifier
{
    // ES256, ES384, ES512, and ESP256 (-9). HAIP 1.0 section 7 requires -9 of a verifier only for the
    // deviceSignature and status information, not for issuerAuth. It is accepted here because it is the ES256
    // algorithm already on this list, under the identifier that fixes its curve (RFC 9864), so it adds a name
    // and no new cryptography.
    private static readonly int[] AllowedCoseAlgorithms = [-7, -35, -36, CoseSign1Verification.Esp256];

    public static IssuerAuthResolution Verify(byte[] issuerAuth)
    {
        CoseSign1Message message;
        try
        {
            message = CoseMessage.DecodeSign1(issuerAuth);
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException)
        {
            throw new MdocProcessingException(MdocErrorCodes.MsoInvalid, $"issuerAuth is not a valid COSE_Sign1: {e.Message}");
        }

        if (CoseSign1Verification.Algorithm(message) is not { } alg || !AllowedCoseAlgorithms.Contains(alg))
        {
            throw new MdocProcessingException(
                MdocErrorCodes.AlgorithmNotAllowed, "The issuerAuth algorithm is not on the ES256/ES384/ES512/ESP256 allowlist.");
        }

        // The MSO is the payload; DeviceResponseParser.ParseMso reads it, but only after this signature check.
        if (message.Content is null)
        {
            throw new MdocProcessingException(MdocErrorCodes.MsoInvalid, "issuerAuth carries no embedded payload.");
        }

        var chain = ReadX5Chain(message);
        var dsCertificate = chain[0];
        try
        {
            // A structurally valid certificate can still carry key bits the platform crypto layer
            // rejects (e.g. an EC point off the curve); those throw platform-specific
            // CryptographicException subtypes and must map to a typed verification error.
            AsymmetricAlgorithm key = dsCertificate.GetECDsaPublicKey() as AsymmetricAlgorithm
                ?? dsCertificate.GetRSAPublicKey() as AsymmetricAlgorithm
                ?? throw new MdocProcessingException(
                    MdocErrorCodes.IssuerKeyUnresolvable, "The Document Signer certificate carries neither an EC nor an RSA key.");

            using (key)
            {
                if (!CoseSign1Verification.VerifyEmbedded(message, key))
                {
                    throw new MdocProcessingException(
                        MdocErrorCodes.SignatureInvalid, "The issuerAuth signature does not verify against the Document Signer key.");
                }
            }

            return new IssuerAuthResolution
            {
                Issuer = dsCertificate.Subject,
                CertificateChain = chain.Select(c => new ReadOnlyMemory<byte>(c.RawData)).ToArray(),
            };
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException)
        {
            throw new MdocProcessingException(
                MdocErrorCodes.IssuerKeyUnresolvable, $"The Document Signer key is unusable: {e.Message}");
        }
        finally
        {
            foreach (var certificate in chain)
            {
                certificate.Dispose();
            }
        }
    }

    // SPEC: RFC 9360 — x5chain (header label 33) is one bstr certificate or an array of bstr,
    // end-entity first.
    private static List<X509Certificate2> ReadX5Chain(CoseSign1Message message)
    {
        var label = new CoseHeaderLabel(33);
        CoseHeaderValue value;
        if (message.UnprotectedHeaders.TryGetValue(label, out var unprotected))
        {
            value = unprotected;
        }
        else if (message.ProtectedHeaders.TryGetValue(label, out var @protected))
        {
            value = @protected;
        }
        else
        {
            throw new MdocProcessingException(
                MdocErrorCodes.IssuerKeyUnresolvable, "issuerAuth carries no x5chain header; the Document Signer key cannot be resolved.");
        }

        try
        {
            var reader = new CborReader(value.EncodedValue, CborConformanceMode.Lax);
            List<X509Certificate2> chain = [];
            if (reader.PeekState() == CborReaderState.StartArray)
            {
                reader.ReadStartArray();
                while (reader.PeekState() != CborReaderState.EndArray)
                {
                    chain.Add(LoadCertificate(reader.ReadByteString()));
                }

                reader.ReadEndArray();
            }
            else
            {
                chain.Add(LoadCertificate(reader.ReadByteString()));
            }

            if (chain.Count == 0)
            {
                throw new MdocProcessingException(MdocErrorCodes.IssuerKeyUnresolvable, "The x5chain header is empty.");
            }

            return chain;
        }
        catch (Exception e) when (CborFailure.IsMalformed(e) || e is CryptographicException)
        {
            throw new MdocProcessingException(
                MdocErrorCodes.IssuerKeyUnresolvable, $"The x5chain header is not a valid certificate chain: {e.Message}");
        }
    }

    private static X509Certificate2 LoadCertificate(byte[] der) =>
#if NET9_0_OR_GREATER
        X509CertificateLoader.LoadCertificate(der);
#else
        new(der);
#endif
}
