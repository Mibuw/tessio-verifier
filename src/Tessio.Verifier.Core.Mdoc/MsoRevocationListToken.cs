using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// An MSO revocation list whose token has been decoded and whose signature verifies against the leaf of its
/// own x5chain. Whether that chain is trusted for this credential is decided afterwards
/// (<see cref="MsoRevocationTrust"/>), and the content is not read for a verdict until it is.
/// </summary>
/// <param name="CertificateChain">The protected x5chain, DER, leaf first.</param>
/// <param name="Subject">The <c>sub</c> claim, which must equal the uri the MSO referenced.</param>
/// <param name="ExpiresAt">The <c>exp</c> claim, which an MSO revocation list must carry.</param>
/// <param name="NotBefore">The <c>nbf</c> claim when present.</param>
/// <param name="TtlSeconds">The <c>ttl</c> claim when present.</param>
/// <param name="Bits">A status list's bits per entry; zero for an identifier list.</param>
/// <param name="CompressedList">A status list's <c>lst</c>; null for an identifier list.</param>
/// <param name="Identifiers">An identifier list's identifiers, uppercase hex; null for a status list.</param>
internal sealed record MsoRevocationListToken(
    ReadOnlyMemory<byte>[] CertificateChain,
    string Subject,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? NotBefore,
    long? TtlSeconds,
    int Bits,
    byte[]? CompressedList,
    IReadOnlySet<string>? Identifiers)
{
    /// <summary>The token type, and the media type it is requested as, for each kind.</summary>
    // SPEC: draft-ietf-oauth-status-list-20 section 5.2 and EAA-6.2.10.1-09 and -10.3.
    public static string TypeOf(RevocationListKind kind) => kind == RevocationListKind.StatusList
        ? "application/statuslist+cwt"
        : "application/identifierlist+cwt";

    // SPEC: EAA-6.2.10.1-08 permits "'ES256' (ECDSA with curve NIST P-256 and SHA-256)", ES384 with P-384,
    // ES512 with P-521, and the brainpool ESB256, ESB384 and ESB512. Each algorithm is held to the curve the
    // requirement names, because the platform verifies an ES256 signature over any curve's key. The platform's
    // COSE implementation does not know the ESB identifiers, so a list declaring one is refused rather than
    // accepted unread. EAA-6.2.10.1-08 names algorithms, not COSE numbers. ESP256 (-9, RFC 9864) is the same
    // "ECDSA with curve NIST P-256 and SHA-256" under the identifier that fixes its curve, and HAIP 1.0 section 7
    // has a verifier validate status information with -7 or -9.
    private static readonly Dictionary<int, string> CurveOfAlgorithm = new()
    {
        [CoseAlgorithms.Es256] = "1.2.840.10045.3.1.7", // NIST P-256
        [CoseAlgorithms.Esp256] = "1.2.840.10045.3.1.7", // NIST P-256
        [CoseAlgorithms.Es384] = "1.3.132.0.34", // NIST P-384
        [CoseAlgorithms.Es512] = "1.3.132.0.35", // NIST P-521
    };

    // SPEC: draft-ietf-oauth-status-list-20 section 5.2, the type is the media type "or the registered CoAP
    // Content-Format ID", which the IANA CoAP Content-Formats registry gives as 279 for
    // application/statuslist+cwt. No number is registered for the identifier list type.
    private const int StatusListCoapContentFormat = 279;

    // The protected header labels this decoder processes, the only ones a crit header may name.
    private static readonly int[] UnderstoodLabels = [1, 16, 33];

    private const int CoseSign1Tag = 18;
    private static readonly CoseHeaderLabel TypeLabel = new(16);
    private static readonly CoseHeaderLabel X5ChainLabel = new(CoseX509.X5Chain);

    /// <summary>
    /// The decoded token, or the reason it is not one. Never throws for anything about the bytes.
    /// </summary>
    public static (MsoRevocationListToken? Token, string? Problem) Decode(byte[] body, RevocationListKind kind)
    {
        try
        {
            return (DecodeCore(body, kind), null);
        }
        catch (InvalidListException e)
        {
            return (null, e.Message);
        }
        catch (Exception e) when (CborFailure.IsMalformed(e) || e is CryptographicException or ArgumentException)
        {
            return (null, $"The MSO revocation list is not a well-formed COSE_Sign1 CWT: {e.Message}");
        }
    }

    private static MsoRevocationListToken DecodeCore(byte[] body, RevocationListKind kind)
    {
        // SPEC: draft-ietf-oauth-status-list-20 section 5.2, "The Status List Token MUST NOT be tagged with
        // the CWT tag ... The COSE message MUST either be the tagged COSE_Sign1_Tagged (18) or
        // COSE_Mac0_Tagged (17)". EAA-6.2.10.1-08 narrows that to COSE_Sign1.
        var outer = new CborReader(body);
        if (outer.PeekState() != CborReaderState.Tag || outer.PeekTag() != (CborTag)CoseSign1Tag)
        {
            throw new InvalidListException("The MSO revocation list is not a tagged COSE_Sign1 (tag 18).");
        }

        var message = CoseSign1Verification.Decode(body, out var problem)
            ?? throw new InvalidListException($"The MSO revocation list is not a well-formed COSE_Sign1 CWT: {problem}");
        var expectedType = TypeOf(kind);

        if (CoseSign1Verification.Algorithm(message) is not { } alg || !CurveOfAlgorithm.TryGetValue(alg, out var curve))
        {
            throw new InvalidListException("The MSO revocation list's algorithm is not one of ES256, ES384, ES512 or ESP256.");
        }

        // A list naming a header this decoder does not process is refused (RFC 9052 section 3.1, quoted on the check).
        if (!CoseSign1Verification.CriticalHeadersUnderstood(message, UnderstoodLabels))
        {
            throw new InvalidListException("The MSO revocation list marks a header critical that this verifier does not process.");
        }

        // SPEC: draft-ietf-oauth-status-list-20 section 5.2, "16 (type): REQUIRED" in the protected header.
        if (!message.ProtectedHeaders.TryGetValue(TypeLabel, out var type) || !IsType(type, kind))
        {
            throw new InvalidListException($"The MSO revocation list's protected type is not '{expectedType}'.");
        }

        // SPEC: EAA-6.2.10.1-08, "the CWT shall contain the x5chain in the protected header". A copy in the
        // unprotected header as well never gets this far: the platform's decoder refuses a label in both.
        if (!message.ProtectedHeaders.TryGetValue(X5ChainLabel, out var x5chain))
        {
            throw new InvalidListException("The MSO revocation list does not carry its x5chain in the protected header.");
        }

        if (message.Content is not { } content)
        {
            throw new InvalidListException("The MSO revocation list carries no embedded claims.");
        }

        var chain = CoseX509.ReadValue(x5chain.EncodedValue, CborConformanceMode.Strict);
        VerifySignature(message, chain[0], curve);

        return MsoRevocationListClaims.Read(content.ToArray(), kind, chain);
    }

    private static void VerifySignature(CoseSign1Message message, ReadOnlyMemory<byte> leafDer, string curve)
    {
        using var leaf = DerCertificate.Load(leafDer.ToArray());
        using var key = leaf.GetECDsaPublicKey()
            ?? throw new InvalidListException("The MSO revocation list's signing certificate carries no EC key.");
        // A key on an explicit, unnamed curve has no OID at all, and is not on the named curve either.
        if (key.ExportParameters(false).Curve.Oid?.Value != curve)
        {
            throw new InvalidListException("The MSO revocation list's signing key is not on the curve its algorithm names.");
        }

        if (!CoseSign1Verification.VerifyEmbedded(message, key, UnderstoodLabels))
        {
            throw new InvalidListException("The MSO revocation list's signature does not verify.");
        }
    }

    private static bool IsType(CoseHeaderValue type, RevocationListKind kind)
    {
        var reader = new CborReader(type.EncodedValue);
        return reader.PeekState() == CborReaderState.TextString
            ? string.Equals(reader.ReadTextString(), TypeOf(kind), StringComparison.Ordinal)
            : kind == RevocationListKind.StatusList
              && reader.PeekState() == CborReaderState.UnsignedInteger
              && reader.ReadUInt64() == StatusListCoapContentFormat;
    }


    /// <summary>Why the bytes are not a usable MSO revocation list; becomes the problem <see cref="Decode"/> returns.</summary>
    internal sealed class InvalidListException(string message) : Exception(message);
}
