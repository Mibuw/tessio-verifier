using System.Formats.Cbor;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// The certificate encodings of RFC 9360: a COSE_X509 header value, and the body an <c>x5u</c> points at. One
/// reader for each, so issuerAuth and MSO revocation lists read certificates the same way. Throws the CBOR
/// reader's own exceptions (see <see cref="CborFailure"/>) for bytes that are not these shapes; callers map them.
/// </summary>
internal static class CoseX509
{
    /// <summary>COSE header label of x5chain, an ordered chain, end-entity first (RFC 9360 section 2).</summary>
    public const int X5Chain = 33;

    /// <summary>COSE header label of x5t, a hash of the end-entity certificate (RFC 9360 section 2).</summary>
    public const int X5T = 34;

    /// <summary>COSE header label of x5u, a URI for the certificate or chain (RFC 9360 section 2).</summary>
    public const int X5U = 35;

    /// <summary>
    /// A COSE_X509 value: one certificate as a byte string, or an array of them. Never empty: an empty array
    /// throws <see cref="CborContentException"/>.
    /// </summary>
    // SPEC: RFC 9360 section 2, "If a single certificate is conveyed, it is placed in a CBOR byte string. If
    // multiple certificates are conveyed, a CBOR array of byte strings is used".
    public static ReadOnlyMemory<byte>[] ReadValue(ReadOnlyMemory<byte> encoded, CborConformanceMode mode)
    {
        var reader = new CborReader(encoded, mode);
        List<ReadOnlyMemory<byte>> certificates = [];
        if (reader.PeekState() == CborReaderState.StartArray)
        {
            reader.ReadStartArray();
            while (reader.PeekState() != CborReaderState.EndArray)
            {
                certificates.Add(reader.ReadByteString());
            }

            reader.ReadEndArray();
        }
        else
        {
            certificates.Add(reader.ReadByteString());
        }

        if (reader.BytesRemaining != 0)
        {
            throw new CborContentException("A COSE_X509 value carries bytes after its certificates.");
        }

        return certificates.Count > 0
            ? [.. certificates]
            : throw new CborContentException("A COSE_X509 value holds no certificate.");
    }

    /// <summary>
    /// The body an <c>x5u</c> points at, end-entity first: one DER certificate (application/pkix-cert), or a CBOR
    /// sequence of byte strings (application/cose-x509). The two cannot be confused: a DER certificate begins
    /// with a SEQUENCE tag (0x30), which as CBOR is a negative integer, and a CBOR sequence here begins with a
    /// byte string. A PKCS#7 certs-only body, the third type RFC 9360 lists, is not read as one: it also begins
    /// with a SEQUENCE, so it comes back as a single "certificate", which the caller's strict loader refuses.
    /// </summary>
    // SPEC: RFC 9360 section 2, x5u's resource is application/pkix-cert, application/pkcs7-mime; smime-type=
    // "certs-only", or application/cose-x509, where "the data is a CBOR sequence of single-entry COSE_X509
    // structures (encoding "bstr")". RFC 2585 section 4.1 has application/pkix-cert carry one DER certificate.
    public static ReadOnlyMemory<byte>[] ReadUrlBody(byte[] body)
    {
        if (body.Length == 0)
        {
            throw new CborContentException("The certificate resource is empty.");
        }

        if (body[0] == 0x30)
        {
            return [body];
        }

        var reader = new CborReader(body, CborConformanceMode.Lax, allowMultipleRootLevelValues: true);
        List<ReadOnlyMemory<byte>> certificates = [];
        while (reader.BytesRemaining > 0)
        {
            certificates.Add(reader.ReadByteString());
        }

        return certificates.Count > 0
            ? [.. certificates]
            : throw new CborContentException("The certificate resource holds no certificate.");
    }
}
