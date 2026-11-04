using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.Core;

/// <summary>The outcome of issuer signing-key resolution.</summary>
internal sealed record IssuerKeyResolution
{
    /// <summary>
    /// The issuer's signing keys. Empty after <see cref="IssuerKeyResolver.Identify"/> on the metadata
    /// route, whose keys only <see cref="IssuerKeyResolver.FetchKeysAsync"/> reads.
    /// </summary>
    public required IReadOnlyList<SecurityKey> Keys { get; init; }

    /// <summary>"x5c" or "jwt-vc-issuer-metadata" (the contract's canonical values).</summary>
    public required string Method { get; init; }

    /// <summary>
    /// Issuer identifier. Metadata route: the <c>iss</c> claim. <c>x5c</c> route: <c>iss</c> when a
    /// subjectAltName of the end-entity certificate names it, otherwise the end-entity subject.
    /// </summary>
    public required string Issuer { get; init; }

    /// <summary>
    /// The <c>iss</c> claim when it is NOT the <see cref="Issuer"/>: an <c>x5c</c> credential whose
    /// certificate does not name it. Null otherwise.
    /// </summary>
    public string? ClaimedIssuer { get; init; }

    /// <summary>DER certificate chain from <c>x5c</c>; empty for metadata resolution.</summary>
    public required ReadOnlyMemory<byte>[] CertificateChain { get; init; }
}

/// <summary>
/// Resolves the issuer's signing key via the two SD-JWT VC mechanisms: the X.509 chain in the
/// <c>x5c</c> JOSE header, or JWT VC Issuer Metadata fetched from the <c>iss</c> HTTPS URI.
/// </summary>
// SPEC: draft-ietf-oauth-sd-jwt-vc-13 §3.5 (Issuer Signature Mechanisms) and §5 (JWT VC Issuer Metadata).
internal sealed class IssuerKeyResolver
{
    /// <summary>id-ce-subjectAltName, RFC 5280 section 4.2.1.6.</summary>
    /// <remarks>
    /// Matched as an OID rather than as a parsed extension type because this value decides whether a
    /// certificate asserts any name at all, and that answer must not depend on whether a given runtime
    /// chose to parse the extension. See <c>CertificateNamesIssuer</c>.
    /// </remarks>
    private const string SubjectAltNameOid = "2.5.29.17";

    /// <summary>GeneralName CHOICE tags, RFC 5280 section 4.2.1.6.</summary>
    private const int DnsGeneralNameTag = 2;

    /// <inheritdoc cref="DnsGeneralNameTag"/>
    private const int UriGeneralNameTag = 6;

    private readonly HttpClient _httpClient;

    public IssuerKeyResolver(HttpClient httpClient) => _httpClient = httpClient;

    /// <summary>
    /// Who signed the token, read from its own header and claims with no network access: the issuer
    /// identifier, the route, and the <c>x5c</c> chain with its key where there is one.
    /// </summary>
    /// <remarks>
    /// Separate from <see cref="FetchKeysAsync"/> so a caller can decide whether it trusts the issuer
    /// before any request is made. On the metadata route the key lives on the host the token names, and
    /// the identifier the trust seam judges is known without it.
    /// </remarks>
    public static IssuerKeyResolution Identify(JsonWebToken issuerJwt)
    {
        // The handler builds every claim to answer for one, and throws InvalidOperationException when any string
        // in the payload is not valid UTF-8. Answered here as malformed, so no caller meets an exception it did not
        // ask for, and a caller that answers malformed and unresolvable differently can tell this one apart.
        string? iss;
        try
        {
            iss = issuerJwt.TryGetClaim("iss", out var issClaim) ? issClaim.Value : null;
        }
        catch (InvalidOperationException)
        {
            throw new SdJwtProcessingException(ErrorCodes.StructureInvalid, "The token's claims are not valid Unicode text.");
        }

        var chain = ReadX5cHeader(issuerJwt);
        if (chain is not null)
        {
            return ResolveFromX5c(chain, iss);
        }

        if (iss is null)
        {
            throw new SdJwtProcessingException(
                ErrorCodes.IssuerKeyUnresolvable,
                "The credential carries neither an x5c header nor an iss claim; no key resolution mechanism applies.");
        }

        if (!Uri.TryCreate(iss, UriKind.Absolute, out var issUri) || issUri.Scheme != Uri.UriSchemeHttps)
        {
            throw new SdJwtProcessingException(
                ErrorCodes.IssuerKeyUnresolvable,
                "The iss claim is not an HTTPS URI; JWT VC Issuer Metadata resolution requires one.");
        }

        return new IssuerKeyResolution
        {
            Keys = [],
            Method = SdJwtConstants.KeyResolutionMetadata,
            Issuer = iss,
            CertificateChain = [],
        };
    }

    /// <summary>
    /// The identified issuer with its keys. The <c>x5c</c> route already has them. The metadata route
    /// fetches JWT VC Issuer Metadata from the <c>iss</c> host.
    /// </summary>
    public async Task<IssuerKeyResolution> FetchKeysAsync(IssuerKeyResolution identified, CancellationToken ct) =>
        identified.Method == SdJwtConstants.KeyResolutionMetadata
            ? identified with { Keys = await FetchMetadataKeysAsync(identified.Issuer, ct).ConfigureAwait(false) }
            : identified;

    // ---- X.509 (x5c) --------------------------------------------------------------------------

    private static List<X509Certificate2>? ReadX5cHeader(JsonWebToken issuerJwt)
    {
        // SPEC: RFC 7515 §4.1.6 — x5c is an array of base64 (standard, NOT base64url) DER certificates,
        // the first entry being the end-entity (signing) certificate. Parsed strictly, so a header naming x5c twice
        // has no chain to pick; the handler has already decoded it, so only StrictJson's own rules can refuse it.
        using var header = ParseHeader(issuerJwt.EncodedHeader);
        if (!header.RootElement.TryGetProperty("x5c", out var x5c))
        {
            return null;
        }

        try
        {
            if (x5c.ValueKind != JsonValueKind.Array || x5c.GetArrayLength() == 0)
            {
                throw new FormatException("x5c is not a non-empty array.");
            }

            return x5c.EnumerateArray()
                .Select(entry => LoadCertificate(Convert.FromBase64String(entry.GetString()
                    ?? throw new FormatException("x5c entry is not a string."))))
                .ToList();
        }
        catch (Exception e) when (e is FormatException or InvalidOperationException or CryptographicException)
        {
            throw new SdJwtProcessingException(
                ErrorCodes.IssuerKeyUnresolvable, "The x5c header is not a valid base64 DER certificate chain.");
        }
    }

    private static JsonDocument ParseHeader(string encodedHeader)
    {
        try
        {
            return StrictJson.ParseDocument(Base64UrlEncoder.DecodeBytes(encodedHeader));
        }
        catch (Exception e) when (e is JsonException or FormatException)
        {
            throw new SdJwtProcessingException(
                ErrorCodes.StructureInvalid, $"The token's JOSE header is not JSON with {StrictJson.Accepts}.");
        }
    }

    private static X509Certificate2 LoadCertificate(byte[] der) =>
#if NET9_0_OR_GREATER
        X509CertificateLoader.LoadCertificate(der);
#else
        new(der);
#endif

    private static IssuerKeyResolution ResolveFromX5c(List<X509Certificate2> certificates, string? iss)
    {
        var leaf = certificates[0];

        // SPEC: draft-ietf-oauth-sd-jwt-vc-13 section 3.5, the version HAIP 1.0 Final section 6.1.1 pins:
        // with an x5c header, "the Issuer of the Verifiable Credential is the subject of the end-entity
        // certificate". Section 3.2.2.2 makes iss OPTIONAL "when it is not conveyed by other means (e.g.,
        // the subject of the end-entity certificate of an x5c header)". Draft -19 keeps both (sections 2.5
        // and 2.2.2.3). Neither asks for iss to match a subjectAltName; that MUST was draft -09's section
        // 3.5 and was removed in -10.
        //
        // THIS USED TO REFUSE a mismatch as issuer_certificate_mismatch, which enforced the withdrawn -09
        // rule. It refused genuine credentials: an issuer whose iss is a URL on its own service and whose
        // certificate carries only a dNSName for another host is conformant to -13 and -19.
        //
        // The certificate is what was trusted, so it is what names the issuer. Trust on this route is
        // decided by anchoring the chain, never by the identifier (StaticTrustListResolver), so accepting
        // the credential grants nothing new. What must not happen is reporting an iss the certificate does
        // not back as the issuer: that would let any anchored certificate put any name in the result. So
        // iss is the Issuer only when a subjectAltName names it, and is otherwise reported separately.
        var issuer = iss is not null && CertificateNamesIssuer(leaf, iss) ? iss : leaf.Subject;

        // Extract the typed public key: X509SecurityKey does not support ECDSA certificates in
        // Microsoft.IdentityModel's crypto providers, and ES256 is the norm for EUDI issuers.
        // A structurally valid certificate can still carry key bits the platform crypto layer
        // rejects (e.g. an EC point off the curve); those throw OS-specific CryptographicException
        // subtypes and must map to a typed verification error.
        SecurityKey leafKey;
        try
        {
            leafKey = leaf.GetECDsaPublicKey() is { } ecdsa
                ? new ECDsaSecurityKey(ecdsa)
                : leaf.GetRSAPublicKey() is { } rsa
                    ? new RsaSecurityKey(rsa)
                    : throw new SdJwtProcessingException(
                        ErrorCodes.IssuerKeyUnresolvable, "The end-entity certificate carries neither an EC nor an RSA public key.");
        }
        catch (CryptographicException e)
        {
            throw new SdJwtProcessingException(
                ErrorCodes.IssuerKeyUnresolvable, $"The end-entity certificate's key is unusable: {e.Message}");
        }

        return new IssuerKeyResolution
        {
            Keys = [leafKey],
            Method = SdJwtConstants.KeyResolutionX5c,
            Issuer = issuer,
            ClaimedIssuer = iss is not null && !string.Equals(issuer, iss, StringComparison.Ordinal) ? iss : null,
            CertificateChain = certificates.Select(c => new ReadOnlyMemory<byte>(c.RawData)).ToArray(),
        };
    }

    /// <summary>Whether a subjectAltName of the certificate names <paramref name="iss"/>.</summary>
    /// <remarks>
    /// A dNSName equal to the iss host, or a uniformResourceIdentifier equal to iss. A certificate that
    /// asserts NO names does not name iss: its subject is then the issuer. That case is real: the EUDI
    /// Wallet Reference Implementation's PID issuer signs with a leaf carrying no subjectAltName while its
    /// iss is https://issuer-backend.eudiw.dev (found 2026-09-20 from a real presentation).
    /// <para>
    /// NO subjectAltName, not "no extensions": that leaf carries six others, one of them an ISSUER
    /// Alternative Name, OID 2.5.29.18, one digit from 2.5.29.17 and carrying an unrelated URL. Matching
    /// "any name-ish extension" would pull that URL into issuer naming.
    /// </para>
    /// <para>
    /// FOUND BY OID, never by the parsed CLR type. X509SubjectAlternativeNameExtension is a parsed view, so
    /// a runtime that handed back a plain X509Extension for this OID would make a typed list empty on a
    /// certificate that does assert names. The OID is present or it is not, on every platform.
    /// </para>
    /// </remarks>
    private static bool CertificateNamesIssuer(X509Certificate2 certificate, string iss)
    {
        var sanExtensions = certificate.Extensions
            .Where(e => string.Equals(e.Oid?.Value, SubjectAltNameOid, StringComparison.Ordinal))
            .ToList();

        if (sanExtensions.Count == 0)
        {
            return false;
        }

        var issHost = Uri.TryCreate(iss, UriKind.Absolute, out var issUri) ? issUri.Host : null;

        foreach (var name in sanExtensions.SelectMany(ReadGeneralNames))
        {
            var matched = name.Tag switch
            {
                DnsGeneralNameTag => string.Equals(name.Value, issHost ?? iss, StringComparison.OrdinalIgnoreCase),
                UriGeneralNameTag => IsSameUri(name.Value, iss),
                _ => false,
            };

            if (matched)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Reads the dNSName and uniformResourceIdentifier entries out of a SAN extension's DER.</summary>
    /// <remarks>
    /// THE DER, not the platform's rendering of it. This used to read <c>EnumerateDnsNames</c> plus a
    /// substring test over <c>Format(false)</c>, and both are platform-dependent: Windows labels and
    /// punctuates the formatted text differently from Unix, so a certificate whose SAN URI matched
    /// exactly was accepted on one operating system and refused on another. Caught by Windows CI on
    /// 2026-09-20, which the release workflow does not run. RFC 5280 section 4.2.1.6 gives GeneralName
    /// as a CHOICE with implicit context tags, so the bytes say the same thing everywhere.
    /// <para>
    /// A SAN that does not parse yields no names, so nothing matches and iss is not taken as the
    /// issuer. An unreadable assertion of a name never vouches for one.
    /// </para>
    /// </remarks>
    private static List<(int Tag, string Value)> ReadGeneralNames(X509Extension extension)
    {
        var names = new List<(int, string)>();
        try
        {
            var sequence = new AsnReader(extension.RawData, AsnEncodingRules.DER).ReadSequence();
            while (sequence.HasData)
            {
                var tag = sequence.PeekTag();
                if (tag.TagClass == TagClass.ContextSpecific
                    && tag.TagValue is DnsGeneralNameTag or UriGeneralNameTag)
                {
                    names.Add((tag.TagValue, sequence.ReadCharacterString(UniversalTagNumber.IA5String, tag)));
                }
                else
                {
                    sequence.ReadEncodedValue();
                }
            }
        }
        catch (AsnContentException)
        {
            return names;
        }

        return names;
    }

    /// <summary>Whether a SAN URI entry names exactly <paramref name="iss"/>.</summary>
    /// <remarks>
    /// Compared as URIs when both parse, so a trailing slash is not a mismatch, and as exact strings
    /// otherwise. NEVER as a prefix or a substring: the earlier substring test meant a SAN of
    /// <c>https://issuer.example.attacker.test/</c> satisfied <c>iss = https://issuer.example</c>, so
    /// registering a lookalike domain was the whole attack.
    /// </remarks>
    private static bool IsSameUri(string entry, string iss) =>
        Uri.TryCreate(entry, UriKind.Absolute, out var entryUri)
        && Uri.TryCreate(iss, UriKind.Absolute, out var issAsUri)
            ? Uri.Compare(
                entryUri, issAsUri, UriComponents.AbsoluteUri, UriFormat.Unescaped, StringComparison.OrdinalIgnoreCase) == 0
            : string.Equals(entry, iss, StringComparison.OrdinalIgnoreCase);

    // ---- JWT VC Issuer Metadata ---------------------------------------------------------------

    // Identify has already required iss to be an absolute HTTPS URI.
    private async Task<IReadOnlyList<SecurityKey>> FetchMetadataKeysAsync(string iss, CancellationToken ct)
    {
        var metadataUri = BuildMetadataUri(new Uri(iss, UriKind.Absolute));
        var metadata = await FetchJsonAsync(metadataUri, ct).ConfigureAwait(false);

        // SPEC: draft-ietf-oauth-sd-jwt-vc-13 §5.3: the metadata's issuer MUST be identical to iss.
        if (!metadata.TryGetProperty("issuer", out var issuerProp)
            || issuerProp.ValueKind != JsonValueKind.String
            || !string.Equals(issuerProp.GetString(), iss, StringComparison.Ordinal))
        {
            throw new SdJwtProcessingException(
                ErrorCodes.IssuerMetadataInvalid, "JWT VC Issuer Metadata 'issuer' does not match the credential's iss.");
        }

        // SPEC: draft-ietf-oauth-sd-jwt-vc-13 §5.2: metadata "MUST include either jwks_uri or jwks ...,
        // but not both". That binds the Issuer, and the draft does not say what a verifier does when it is broken.
        // Refused rather than resolved by picking one, because the two can name different keys and either
        // choice would silently trust a key set the issuer may not have meant.
        if (metadata.TryGetProperty("jwks", out _) && metadata.TryGetProperty("jwks_uri", out _))
        {
            throw new SdJwtProcessingException(
                ErrorCodes.IssuerMetadataInvalid, "JWT VC Issuer Metadata carries both 'jwks' and 'jwks_uri'.");
        }

        // A jwks_uri must be HTTPS. -13 §5.2 sets no scheme for it, but §10.1 requires HTTPS for the
        // metadata URL, and the key set it points to is held to the same bar.
        JsonElement jwks;
        if (metadata.TryGetProperty("jwks", out var inlineJwks))
        {
            jwks = inlineJwks;
        }
        else if (metadata.TryGetProperty("jwks_uri", out var jwksUriProp)
                 && jwksUriProp.ValueKind == JsonValueKind.String
                 && Uri.TryCreate(jwksUriProp.GetString(), UriKind.Absolute, out var jwksUri)
                 && jwksUri.Scheme == Uri.UriSchemeHttps)
        {
            jwks = await FetchJsonAsync(jwksUri, ct).ConfigureAwait(false);
        }
        else
        {
            throw new SdJwtProcessingException(
                ErrorCodes.IssuerMetadataInvalid, "JWT VC Issuer Metadata carries neither 'jwks' nor a valid https 'jwks_uri'.");
        }

        var keys = new JsonWebKeySet(jwks.GetRawText()).GetSigningKeys().ToList();
        if (keys.Count == 0)
        {
            throw new SdJwtProcessingException(
                ErrorCodes.IssuerMetadataInvalid, "The issuer's JWK Set contains no usable signing keys.");
        }

        return keys;
    }

    // SPEC: draft-ietf-oauth-sd-jwt-vc-13 §5 and §5.1: insert "/.well-known/jwt-vc-issuer" between the
    // host component and the path component of iss, after removing any terminating '/'.
    internal static Uri BuildMetadataUri(Uri issUri)
    {
        var path = issUri.AbsolutePath.TrimEnd('/');
        return new Uri($"{issUri.Scheme}://{issUri.Authority}{SdJwtConstants.WellKnownSegment}{path}");
    }

    private async Task<JsonElement> FetchJsonAsync(Uri uri, CancellationToken ct)
    {
        try
        {
            var body = await OutboundFetch.GetBoundedAsync(
                _httpClient, uri, accept: null, "issuer metadata or key set", OutboundFetch.MaxMetadataBytes, ct)
                .ConfigureAwait(false);
            // Unsigned and from a host the credential names, so held to the same rules as signed JSON: a key set
            // or metadata naming jwks or issuer twice has no single meaning. A refusal is a JsonException below.
            using var document = StrictJson.ParseDocument(body);
            return document.RootElement.Clone();
        }
        catch (Exception e) when (e is HttpRequestException or JsonException or TaskCanceledException)
        {
            throw new SdJwtProcessingException(
                ErrorCodes.IssuerKeyUnresolvable, $"Fetching issuer metadata from '{uri}' failed: {e.Message}");
        }
    }
}
