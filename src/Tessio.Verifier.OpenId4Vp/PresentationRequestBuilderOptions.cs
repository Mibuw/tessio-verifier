using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>Configuration for <see cref="SignedPresentationRequestBuilder"/>.</summary>
public sealed class PresentationRequestBuilderOptions
{
    /// <summary>
    /// Key and algorithm used to sign the JAR request object. In production this key belongs to the
    /// verifier's access certificate (WRPAC); any <see cref="SigningCredentials"/> works, including
    /// keys held in Azure Key Vault or an HSM via a custom <see cref="CryptoProviderFactory"/>.
    /// </summary>
    public required SigningCredentials SigningCredentials { get; set; }

    /// <summary>
    /// Certificate chain to advertise in the JAR <c>x5c</c> header: the access certificate that holds the
    /// signing key first, then any intermediates, never the trust anchor.
    /// </summary>
    /// <remarks>
    /// OpenID4VP 1.0 section 5.9.3 requires x5c for the <c>x509_san_dns</c> and <c>x509_hash</c> client
    /// identifier prefixes: the wallet matches the client identifier against the leaf it carries and has
    /// no other way to obtain it. HAIP 1.0 section 5 requires <c>x509_hash</c> for signed requests, and
    /// for a request sent by redirect ETSI TS 119 472-2 V1.2.1 OIDFVP-HAIP-REDIRECTS_RO-01, which CIR (EU) 2026/1731
    /// applies and does not adapt, requires x5c outright.
    /// When null, requests carry no x5c, so they cannot use either x509 prefix. An empty list is refused
    /// rather than read as null.
    /// <para>
    /// <see cref="SignedPresentationRequestBuilder"/> checks the chain once, when it is created, and
    /// refuses it with an <see cref="ArgumentException"/> when: it holds a null entry; any certificate
    /// in it names itself as its issuer (a root, or a self-signed signer); a certificate is not issued
    /// by the one after it; or the first certificate is a CA (the self-issued and CA
    /// rules give way for a lone certificate when <see cref="AllowSelfSignedSigningCertificate"/> is set). Names are
    /// compared by their encoded bytes.
    /// So a path whose names differ only in case, spacing or string type is refused as unlinked, and a
    /// self-signed certificate whose issuer is encoded differently from its subject is not recognised
    /// as one; nor can an anchor that is not itself a root be recognised. When
    /// <see cref="SigningCredentials"/> holds an <see cref="ECDsaSecurityKey"/>, the first certificate
    /// must also hold its public half. That compares the public half declared in the key: with a
    /// custom <see cref="CryptoProviderFactory"/> that signs elsewhere, it does not prove the remote key
    /// is the same one. Any other <see cref="SecurityKey"/> type is not compared. Not checked at all:
    /// validity periods, revocation, the signatures along the path, key usage and extended key usage,
    /// and whether the intermediates are CAs. The wallet judges the path against its own trust list.
    /// </para>
    /// <para>
    /// The builder reads this and <see cref="SigningCredentials"/> once, when it is created: it keeps
    /// the chain as encoded bytes, so assigning a new chain or changing this list afterwards changes
    /// nothing, and disposing the certificates afterwards is safe. It keeps the
    /// <see cref="SigningCredentials"/> instance itself, so assigning new credentials afterwards changes
    /// nothing, but changing that instance or its key afterwards does. To rotate a key, create a new
    /// builder.
    /// </para>
    /// <para>
    /// Kept separate from <see cref="SigningCredentials"/> rather than read off an
    /// <c>X509SecurityKey</c>, because Microsoft.IdentityModel has no ES256 signature provider for that
    /// key type: an EC certificate can be advertised but not signed with in that form.
    /// </para>
    /// </remarks>
    public IReadOnlyList<X509Certificate2>? SigningCertificateChain { get; set; }

    /// <summary>
    /// Accepts a <see cref="SigningCertificateChain"/> of exactly one certificate that is self-signed or a CA,
    /// which the rules above otherwise refuse. For a test environment whose wallet trusts one published
    /// self-signed signing certificate, such as Google Wallet's sandbox for relying parties. False by default.
    /// </summary>
    /// <remarks>
    /// HAIP 1.0 section 5 says the certificate signing the request "MUST NOT be self-signed" and that the trust
    /// anchor "MUST NOT be included in the x5c JOSE header", and a lone self-signed certificate is both. A request
    /// signed this way is not HAIP conformant, and a production wallet will not trust it. A longer chain keeps every
    /// rule, and the check that the certificate holds the signing key still runs.
    /// </remarks>
    public bool AllowSelfSignedSigningCertificate { get; set; }

    /// <summary>
    /// When set, requests are delivered by reference: the wallet fetches the signed JAR from
    /// <c>{RequestUriBase}/{id}</c> and the hosting layer must serve it there. When null (default),
    /// requests are delivered by value inside the authorization request URI.
    /// </summary>
    public Uri? RequestUriBase { get; set; }

    /// <summary>
    /// Scheme-and-authority part of the wallet-facing authorization request URI.
    /// Defaults to the OpenID4VP universal scheme.
    /// </summary>
    public string AuthorizationEndpoint { get; set; } = "openid4vp://authorize";

    /// <summary>Request lifetime applied when the per-request options carry none. Default: 5 minutes.</summary>
    public TimeSpan DefaultRequestLifetime { get; set; } = StandardRequestLifetime;

    /// <summary>The lifetime a request gets when nothing sets one, for every builder in this package.</summary>
    internal static readonly TimeSpan StandardRequestLifetime = TimeSpan.FromMinutes(5);

    /// <summary>Time source for iat/exp; system clock when null.</summary>
    public TimeProvider? Clock { get; set; }
}
