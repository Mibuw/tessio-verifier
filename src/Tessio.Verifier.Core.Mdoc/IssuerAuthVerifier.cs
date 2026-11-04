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

    /// <summary>DER chain from x5chain or x5u, DS certificate first, for the trust seam.</summary>
    public required ReadOnlyMemory<byte>[] CertificateChain { get; init; }

    /// <summary>
    /// The x5u resource the chain came from, for the caller to keep once the mdoc has verified in full. Null when the
    /// chain came from x5chain.
    /// </summary>
    public CertificateUrlResource? FetchedX5u { get; init; }
}

/// <summary>
/// Verifies the <c>issuerAuth</c> COSE_Sign1 over the MSO: algorithm allowlist, Document Signer certificate from
/// <c>x5chain</c> or <c>x5u</c>, bound by <c>x5t</c> when present, and the signature. Chain trust is decided by
/// the caller's <see cref="Trust.ITrustListResolver"/>.
/// </summary>
// SPEC: ISO/IEC 18013-5 section 9.3.1, issuer data authentication. CIR (EU) 2026/1731 Annex I, replacing the
// annex of CIR (EU) 2024/2977, for a PID: "The Protected Header of the CB-AdES digital signature signing a person
// identification data in ISO/IEC-mdoc format shall contain the x5u and the x5t header parameters, both specified
// in RFC 9360", and "The digest algorithm used in the x5t header parameter shall be SHA-256."
internal static class IssuerAuthVerifier
{
    // The protected header labels this verifier processes, the only ones a crit header may name. x5u is processed
    // only when x5u resolution is on, so only then may a crit header name it.
    private static readonly int[] UnderstoodLabels = [1, CoseX509.X5Chain, CoseX509.X5T];
    private static readonly int[] UnderstoodLabelsWithX5u = [1, CoseX509.X5Chain, CoseX509.X5T, CoseX509.X5U];

    // COSE algorithm identifier of SHA-256, the "COSE Algorithms" registry's Value for it.
    private const int Sha256 = -16;

    /// <param name="issuerAuth">The issuerAuth COSE_Sign1.</param>
    /// <param name="x5u">Fetches an x5u's certificate; null when x5u resolution is off (MdocVerifierOptions.ResolveX5u).</param>
    /// <param name="ct">Cancellation.</param>
    public static async Task<IssuerAuthResolution> VerifyAsync(byte[] issuerAuth, CertificateUrlFetcher? x5u, CancellationToken ct)
    {
        var message = CoseSign1Verification.Decode(issuerAuth, out var problem)
            ?? throw new MdocProcessingException(MdocErrorCodes.MsoInvalid, $"issuerAuth is not a valid COSE_Sign1: {problem}");

        if (CoseSign1Verification.Algorithm(message) is not { } alg || !CoseAlgorithms.IssuerAuth.Contains(alg))
        {
            throw new MdocProcessingException(
                MdocErrorCodes.AlgorithmNotAllowed, "The issuerAuth algorithm is not on the ES256/ES384/ES512/ESP256 allowlist.");
        }

        var understood = x5u is null ? UnderstoodLabels : UnderstoodLabelsWithX5u;
        if (!CoseSign1Verification.CriticalHeadersUnderstood(message, understood))
        {
            throw new MdocProcessingException(
                MdocErrorCodes.MsoInvalid, "issuerAuth marks a header critical that this verifier does not process.");
        }

        // The MSO is the payload; DeviceResponseParser.ParseMso reads it, but only after this signature check.
        if (message.Content is null)
        {
            throw new MdocProcessingException(MdocErrorCodes.MsoInvalid, "issuerAuth carries no embedded payload.");
        }

        var thumbprint = ReadProtectedX5T(message);
        var (der, fetched) = await ReadChainAsync(message, thumbprint, x5u, ct).ConfigureAwait(false);

        List<X509Certificate2> chain = [];
        try
        {
            foreach (var certificate in der)
            {
                // Exactly one DER certificate per entry, on every framework, so the bytes hashed for x5t and handed
                // to the trust seam are the bytes the header or the x5u carried.
                chain.Add(DerCertificate.Load(certificate.ToArray()));
            }

            var dsCertificate = chain[0];

            // SPEC: RFC 9360 section 2, x5t "identifies the end-entity X.509 certificate by a hash value", "computed
            // over the DER-encoded certificate". Whichever header carried the chain, its first certificate is that one.
            if (thumbprint is not null
                && !CryptographicOperations.FixedTimeEquals(SHA256.HashData(dsCertificate.RawData), thumbprint))
            {
                throw new MdocProcessingException(
                    MdocErrorCodes.IssuerKeyUnresolvable, "The Document Signer certificate does not match issuerAuth's x5t thumbprint.");
            }

            // A structurally valid certificate can still carry key bits the platform crypto layer
            // rejects (e.g. an EC point off the curve); those throw platform-specific
            // CryptographicException subtypes and must map to a typed verification error.
            AsymmetricAlgorithm key = dsCertificate.GetECDsaPublicKey() as AsymmetricAlgorithm
                ?? dsCertificate.GetRSAPublicKey() as AsymmetricAlgorithm
                ?? throw new MdocProcessingException(
                    MdocErrorCodes.IssuerKeyUnresolvable, "The Document Signer certificate carries neither an EC nor an RSA key.");

            using (key)
            {
                if (!CoseSign1Verification.VerifyEmbedded(message, key, understood))
                {
                    throw new MdocProcessingException(
                        MdocErrorCodes.SignatureInvalid, "The issuerAuth signature does not verify against the Document Signer key.");
                }
            }

            return new IssuerAuthResolution
            {
                Issuer = dsCertificate.Subject,
                CertificateChain = chain.Select(c => new ReadOnlyMemory<byte>(c.RawData)).ToArray(),
                FetchedX5u = fetched,
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

    // The chain, from x5chain when the message carries one, otherwise from x5u. An x5chain is used as it is, and an
    // x5u is fetched only when no x5chain is there, so a message carrying both costs no request.
    private static async Task<(ReadOnlyMemory<byte>[] Der, CertificateUrlResource? Fetched)> ReadChainAsync(
        CoseSign1Message message, byte[]? thumbprint, CertificateUrlFetcher? x5u, CancellationToken ct)
    {
        if (Header(message, CoseX509.X5Chain) is { } x5chain)
        {
            try
            {
                return (CoseX509.ReadValue(x5chain.EncodedValue, CborConformanceMode.Lax), null);
            }
            catch (Exception e) when (CborFailure.IsMalformed(e))
            {
                throw new MdocProcessingException(
                    MdocErrorCodes.IssuerKeyUnresolvable, $"The x5chain header is not a valid certificate chain: {e.Message}");
            }
        }

        if (Header(message, CoseX509.X5U) is null)
        {
            throw new MdocProcessingException(
                MdocErrorCodes.IssuerKeyUnresolvable,
                "issuerAuth carries neither an x5chain nor an x5u header; the Document Signer key cannot be resolved.");
        }

        if (x5u is null)
        {
            throw new MdocProcessingException(
                MdocErrorCodes.IssuerKeyUnresolvable,
                "issuerAuth names its Document Signer certificate by x5u, and x5u resolution is off (MdocVerifierOptions.ResolveX5u).");
        }

        // SPEC: RFC 9360 section 2, for x5u "The end-entity certificate MUST be integrity protected by COSE. This
        // can, for example, be done by sending the 'x5u' in the unprotected or protected header combined with an
        // 'x5t' in the protected header". Without it, whoever serves the URL chooses the key.
        if (thumbprint is null)
        {
            throw new MdocProcessingException(
                MdocErrorCodes.IssuerKeyUnresolvable,
                "issuerAuth's x5u is not bound by an x5t in the protected header, so the certificate it points at cannot be relied on.");
        }

        // SPEC: CIR (EU) 2026/1731 Annex I, "The Protected Header ... shall contain the x5u and the x5t header
        // parameters". RFC 9360 also allows x5u unprotected, but then anyone holding a signed issuerAuth can point it
        // at another URL without breaking the signature, so only the protected one is fetched.
        if (!message.ProtectedHeaders.TryGetValue(new CoseHeaderLabel(CoseX509.X5U), out var url))
        {
            throw new MdocProcessingException(
                MdocErrorCodes.IssuerKeyUnresolvable,
                "issuerAuth's x5u is not in the protected header, as CIR (EU) 2026/1731 Annex I requires of a PID.");
        }

        string uri;
        try
        {
            uri = url.GetValueAsString();
        }
        catch (InvalidOperationException)
        {
            throw new MdocProcessingException(MdocErrorCodes.MsoInvalid, "issuerAuth's x5u is not a text string.");
        }

        CertificateUrlResource resource;
        try
        {
            resource = await x5u.FetchAsync(uri, thumbprint, ct).ConfigureAwait(false);
        }
        catch (CertificateUrlException e)
        {
            throw new MdocProcessingException(MdocErrorCodes.IssuerKeyUnresolvable, $"issuerAuth: {e.Message}");
        }

        try
        {
            return (CoseX509.ReadUrlBody(resource.Body), resource);
        }
        catch (Exception e) when (CborFailure.IsMalformed(e))
        {
            throw new MdocProcessingException(
                MdocErrorCodes.IssuerKeyUnresolvable,
                $"The resource at issuerAuth's x5u is not a DER certificate or a COSE_X509 sequence: {e.Message}");
        }
    }

    // SPEC: RFC 9360 section 2, x5t is "an array of two elements": a hash algorithm identifier, "an integer or a
    // string", and "a binary string containing the hash value". It binds a certificate only from the protected
    // header ("The identification of the end-entity certificate MUST be integrity protected by COSE"), so one in
    // the unprotected header alone is not read. CIR 2026/1731 Annex I has a PID use SHA-256, and RFC 9360 makes
    // SHA-256 the algorithm every implementation supports; no other is accepted.
    private static byte[]? ReadProtectedX5T(CoseSign1Message message)
    {
        if (!message.ProtectedHeaders.TryGetValue(new CoseHeaderLabel(CoseX509.X5T), out var value))
        {
            return null;
        }

        try
        {
            var reader = new CborReader(value.EncodedValue, CborConformanceMode.Lax);
            if (reader.ReadStartArray() != 2)
            {
                throw new CborContentException("x5t is not a two-element array.");
            }

            if (reader.PeekState() is not (CborReaderState.NegativeInteger or CborReaderState.UnsignedInteger)
                || reader.ReadInt32() != Sha256)
            {
                throw new MdocProcessingException(
                    MdocErrorCodes.MsoInvalid, "issuerAuth's x5t does not use SHA-256 (COSE algorithm -16), the only digest accepted.");
            }

            var hash = reader.ReadByteString();
            reader.ReadEndArray();
            return hash.Length == SHA256.HashSizeInBytes
                ? hash
                : throw new CborContentException("x5t's SHA-256 hash is not 32 bytes.");
        }
        catch (Exception e) when (CborFailure.IsMalformed(e))
        {
            throw new MdocProcessingException(MdocErrorCodes.MsoInvalid, $"issuerAuth's x5t is not a valid thumbprint: {e.Message}");
        }
    }

    // A header from either bucket, the unprotected one first, as issuerAuth's x5chain has always been read.
    private static CoseHeaderValue? Header(CoseSign1Message message, int label)
    {
        var key = new CoseHeaderLabel(label);
        return message.UnprotectedHeaders.TryGetValue(key, out var unprotected) ? unprotected
            : message.ProtectedHeaders.TryGetValue(key, out var @protected) ? @protected
            : null;
    }
}
