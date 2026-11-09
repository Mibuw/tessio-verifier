using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Tessio.Verifier.Trust;

/// <summary>
/// Loads an X.509 certificate that must be exactly one certificate, with nothing around it or after it. The
/// platform loaders also accept PEM, and on .NET 8 PKCS#7 and PKCS#12 too, so there the content type is checked
/// before loading; on later frameworks the loader takes a single certificate alone. On every framework the
/// certificate's own encoding must then reproduce the input byte for byte, which refuses every wrapping and every
/// trailing byte. The bytes it is given are therefore
/// the bytes it returns, which is what a thumbprint is computed over and what the trust seam judges. The one
/// loader the library uses for a certificate that arrives from outside: a second, laxer one is where a presented
/// certificate would slip past this.
/// </summary>
// SPEC: RFC 9360 section 2, x5chain carries DER certificates; ISO/IEC 18013-5 likewise ("DER encoded").
// RFC 7515 section 4.1.6, each x5c entry is "a base64-encoded ... DER PKIX certificate value".
internal static class DerCertificate
{
    /// <exception cref="CryptographicException">The bytes are not exactly one certificate.</exception>
    public static X509Certificate2 Load(byte[] der)
    {
        // Refused here rather than handed on: on .NET 8 an empty array makes the content-type check throw an
        // ArgumentException, which nothing above expects.
        if (der.Length == 0)
        {
            throw new CryptographicException("The certificate is empty.");
        }

#if NET9_0_OR_GREATER
        var certificate = X509CertificateLoader.LoadCertificate(der);
#else
        if (X509Certificate2.GetCertContentType(der) != X509ContentType.Cert)
        {
            throw new CryptographicException("The bytes are not a single X.509 certificate.");
        }

        var certificate = new X509Certificate2(der);
#endif
        if (!certificate.RawData.AsSpan().SequenceEqual(der))
        {
            certificate.Dispose();
            throw new CryptographicException("The bytes are not exactly one DER-encoded certificate.");
        }

        return certificate;
    }
}
