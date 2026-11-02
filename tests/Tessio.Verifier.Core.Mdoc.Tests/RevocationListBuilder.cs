using System.Formats.Cbor;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// Mints MSO revocation lists as clause EAA-6.2.10.1 of Implementing Regulation (EU) 2024/2979, Annex II as replaced by 2026/1731
/// describes them: a tagged COSE_Sign1 CWT with the type and x5chain in the protected header, signed by a
/// certificate the given CA issues. Every property is a knob a negative test turns.
/// </summary>
internal sealed class RevocationListBuilder : IDisposable
{
    public RevocationListBuilder(
        X509Certificate2 issuer, ECDsa issuerKey, string subject = "CN=Test Revocation List Signer", ECCurve? curve = null)
    {
        Issuer = issuer;
        SignerKey = ECDsa.Create(curve ?? ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(subject, SignerKey, HashAlgorithmName.SHA256);
        if (issuer.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Any())
        {
            request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));
        }

        SignerCertificate = request.Create(
            issuer.SubjectName, X509SignatureGenerator.CreateForECDsa(issuerKey),
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1), Guid.NewGuid().ToByteArray());
    }

    public X509Certificate2 Issuer { get; private set; }

    public ECDsa SignerKey { get; private set; }

    public X509Certificate2 SignerCertificate { get; private set; }

    /// <summary>
    /// Signs with <paramref name="signer"/> and <paramref name="key"/>, with <paramref name="issuer"/> as the
    /// chain's second certificate, in place of the certificate this builder issued. The caller keeps ownership.
    /// </summary>
    public void UseSigner(X509Certificate2 signer, ECDsa key, X509Certificate2 issuer)
    {
        SignerCertificate.Dispose();
        SignerKey.Dispose();
        SignerCertificate = signer;
        SignerKey = key;
        Issuer = issuer;
        _ownsSigner = false;
    }

    private bool _ownsSigner = true;

    /// <summary>The <c>sub</c> claim; the list's uri when null.</summary>
    public string? Subject { get; set; }

    /// <summary>Leave the <c>sub</c> claim out.</summary>
    public bool OmitSubject { get; set; }

    /// <summary>The <c>exp</c> claim; omitted when null.</summary>
    public DateTimeOffset? ExpiresAt { get; set; } = DateTimeOffset.UtcNow.AddDays(1);

    /// <summary>The <c>iat</c> claim; omitted when null.</summary>
    public DateTimeOffset? IssuedAt { get; set; } = DateTimeOffset.UtcNow.AddMinutes(-1);

    /// <summary>The <c>ttl</c> claim; omitted when null.</summary>
    public ulong? Ttl { get; set; }

    /// <summary>The protected type; the kind's own when null.</summary>
    public string? Type { get; set; }

    /// <summary>The hash the COSE signature uses, which with the key's curve decides the algorithm.</summary>
    public HashAlgorithmName Hash { get; set; } = HashAlgorithmName.SHA256;

    /// <summary>A text label for the crit header to name, given a placeholder value.</summary>
    public string? CriticalTextLabel { get; set; }

    /// <summary>The protected type as a CoAP Content-Format number instead of text.</summary>
    public int? TypeNumber { get; set; }

    /// <summary>A protected crit header naming these labels; none when null.</summary>
    public int[]? Critical { get; set; }

    /// <summary>The <c>nbf</c> claim; omitted when null.</summary>
    public DateTimeOffset? NotBefore { get; set; }

    /// <summary>Sign with the claims detached rather than embedded.</summary>
    public bool Detached { get; set; }

    /// <summary>Put the x5chain in the unprotected header instead of the protected one.</summary>
    public bool X5ChainUnprotected { get; set; }

    /// <summary>Also put the issuing CA in the x5chain, after the signer.</summary>
    public bool IncludeIssuerInChain { get; set; }

    /// <summary>Bytes appended to the x5chain after the signer, certificate or not.</summary>
    public byte[]? ExtraChainCertificate { get; set; }

    /// <summary>Writes the list claim a second time, with every entry valid.</summary>
    public bool RepeatStatusListClaim { get; set; }

    /// <summary>The claim key the identifier list is written under.</summary>
    public long IdentifierListClaim { get; set; } = 65530;

    /// <summary>Also write a status list claim into an identifier list.</summary>
    public bool AddStatusListClaimToIdentifierList { get; set; }

    /// <summary>Signs with this key instead of the signer certificate's.</summary>
    public ECDsa? SignWith { get; set; }

    /// <summary>Signs under ESP256 (-9) instead of the algorithm the key and hash pick.</summary>
    public bool Esp256Signature { get; set; }

    public byte[] StatusList(string uri, int bits, params int[] statuses)
    {
        var packed = new byte[(statuses.Length * bits + 7) / 8];
        for (var i = 0; i < statuses.Length; i++)
        {
            packed[i * bits / 8] |= (byte)(statuses[i] << (i * bits % 8));
        }

        return Sign(uri, "application/statuslist+cwt", w =>
        {
            w.WriteInt64(65533);
            WriteStatusList(w, bits, Compress(packed));
            if (RepeatStatusListClaim)
            {
                w.WriteInt64(65533);
                WriteStatusList(w, bits, Compress(new byte[packed.Length]));
            }
        });
    }

    public byte[] IdentifierList(string uri, params byte[][] identifiers) =>
        Sign(uri, "application/identifierlist+cwt", w =>
        {
            w.WriteInt64(IdentifierListClaim);
            w.WriteStartMap(1);
            w.WriteTextString("identifiers");
            w.WriteStartMap(identifiers.Length);
            foreach (var id in identifiers)
            {
                w.WriteByteString(id);
                w.WriteStartMap(0);
                w.WriteEndMap();
            }

            w.WriteEndMap();
            w.WriteEndMap();
            if (AddStatusListClaimToIdentifierList)
            {
                w.WriteInt64(65533);
                WriteStatusList(w, 1, Compress([0]));
            }
        });

    /// <summary>An MSO <c>status</c> element referencing a status list.</summary>
    public static byte[] StatusListReference(long idx, string uri, byte[]? certificate = null) =>
        Reference("status_list", w =>
        {
            w.WriteTextString("idx");
            w.WriteInt64(idx);
        }, uri, certificate);

    /// <summary>An MSO <c>status</c> element referencing an identifier list.</summary>
    public static byte[] IdentifierListReference(byte[] id, string uri, byte[]? certificate = null) =>
        Reference("identifier_list", w =>
        {
            w.WriteTextString("id");
            w.WriteByteString(id);
        }, uri, certificate);

    private static byte[] Reference(string name, Action<CborWriter> writeKey, string uri, byte[]? certificate)
    {
        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartMap(1);
        w.WriteTextString(name);
        w.WriteStartMap(certificate is null ? 2 : 3);
        writeKey(w);
        w.WriteTextString("uri");
        w.WriteTextString(uri);
        if (certificate is not null)
        {
            w.WriteTextString("certificate");
            w.WriteByteString(certificate);
        }

        w.WriteEndMap();
        w.WriteEndMap();
        return w.Encode();
    }

    private byte[] Sign(string uri, string defaultType, Action<CborWriter> writeListClaims)
    {
        // Indefinite length, so the knobs can add and drop claims without counting them.
        var claims = new CborWriter(CborConformanceMode.Lax);
        claims.WriteStartMap(null);
        if (!OmitSubject)
        {
            claims.WriteInt64(2);
            claims.WriteTextString(Subject ?? uri);
        }

        if (IssuedAt is { } iat)
        {
            claims.WriteInt64(6);
            claims.WriteInt64(iat.ToUnixTimeSeconds());
        }

        if (NotBefore is { } nbf)
        {
            claims.WriteInt64(5);
            claims.WriteInt64(nbf.ToUnixTimeSeconds());
        }

        if (ExpiresAt is { } exp)
        {
            claims.WriteInt64(4);
            claims.WriteInt64(exp.ToUnixTimeSeconds());
        }

        if (Ttl is { } ttl)
        {
            claims.WriteInt64(65534);
            claims.WriteUInt64(ttl);
        }

        writeListClaims(claims);
        claims.WriteEndMap();

        var protectedHeaders = new CoseHeaderMap
        {
            [new CoseHeaderLabel(16)] = TypeNumber is { } number
                ? CoseHeaderValue.FromInt32(number)
                : CoseHeaderValue.FromString(Type ?? defaultType),
        };
        if (Critical is { } critical)
        {
            var crit = new CborWriter();
            crit.WriteStartArray(critical.Length);
            foreach (var label in critical)
            {
                crit.WriteInt32(label);
                // A label crit names must be present; one this builder sets nothing for gets a placeholder.
                if (!protectedHeaders.ContainsKey(new CoseHeaderLabel(label)))
                {
                    protectedHeaders.Add(new CoseHeaderLabel(label), CoseHeaderValue.FromInt32(0));
                }
            }

            crit.WriteEndArray();
            protectedHeaders[new CoseHeaderLabel(2)] = CoseHeaderValue.FromEncodedValue(crit.Encode());
        }

        var unprotectedHeaders = new CoseHeaderMap();
        (X5ChainUnprotected ? unprotectedHeaders : protectedHeaders)[new CoseHeaderLabel(33)] =
            CoseHeaderValue.FromEncodedValue(EncodeChain());

        if (CriticalTextLabel is { } text)
        {
            var crit = new CborWriter();
            crit.WriteStartArray(1);
            crit.WriteTextString(text);
            crit.WriteEndArray();
            protectedHeaders[new CoseHeaderLabel(2)] = CoseHeaderValue.FromEncodedValue(crit.Encode());
            protectedHeaders[new CoseHeaderLabel(text)] = CoseHeaderValue.FromInt32(0);
        }

        var signer = new CoseSigner(SignWith ?? SignerKey, Hash, protectedHeaders, unprotectedHeaders);
        var claimsBytes = claims.Encode();
        var signed = Detached
            ? CoseSign1Message.SignDetached(claimsBytes, signer)
            : CoseSign1Message.SignEmbedded(claimsBytes, signer);
        return Esp256Signature ? Esp256.Resign(signed, SignWith ?? SignerKey, Detached ? claimsBytes : null) : signed;
    }

    private byte[] EncodeChain()
    {
        List<byte[]> chain = [SignerCertificate.RawData];
        if (IncludeIssuerInChain)
        {
            chain.Add(Issuer.RawData);
        }

        if (ExtraChainCertificate is not null)
        {
            chain.Add(ExtraChainCertificate);
        }

        var w = new CborWriter(CborConformanceMode.Lax);
        if (chain.Count == 1)
        {
            w.WriteByteString(chain[0]);
            return w.Encode();
        }

        w.WriteStartArray(chain.Count);
        foreach (var certificate in chain)
        {
            w.WriteByteString(certificate);
        }

        w.WriteEndArray();
        return w.Encode();
    }

    private static void WriteStatusList(CborWriter w, int bits, byte[] lst)
    {
        w.WriteStartMap(2);
        w.WriteTextString("bits");
        w.WriteInt32(bits);
        w.WriteTextString("lst");
        w.WriteByteString(lst);
        w.WriteEndMap();
    }

    private static byte[] Compress(byte[] data)
    {
        using var output = new MemoryStream();
        using (var zlib = new ZLibStream(output, CompressionLevel.Optimal))
        {
            zlib.Write(data);
        }

        return output.ToArray();
    }

    public void Dispose()
    {
        if (_ownsSigner)
        {
            SignerCertificate.Dispose();
            SignerKey.Dispose();
        }
    }
}

/// <summary>Serves bytes per url and records what was asked for, including the Accept header.</summary>
internal sealed class RevocationListHttp : HttpMessageHandler
{
    private readonly Dictionary<string, byte[]> _bodies = new(StringComparer.Ordinal);

    public List<(string Url, string Accept)> Requested { get; } = [];

    public RevocationListHttp Serve(string url, byte[] body)
    {
        _bodies[url] = body;
        return this;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var url = request.RequestUri!.ToString();
        Requested.Add((url, request.Headers.Accept.ToString()));
        return Task.FromResult(_bodies.TryGetValue(url, out var body)
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) }
            : new HttpResponseMessage(HttpStatusCode.NotFound));
    }
}
