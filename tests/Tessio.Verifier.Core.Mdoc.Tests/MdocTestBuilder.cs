using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// Builds real mdoc DeviceResponses for tests: a Document Signer certificate chained to an IACA-like
/// root, IssuerSignedItems with random salts, an MSO with computed digests signed as COSE_Sign1
/// (x5chain header) and a device key. Follows the TestCredentialBuilder pattern from Core.Tests.
/// </summary>
internal sealed class MdocTestBuilder : IDisposable
{
    public const string DefaultDocType = "org.iso.18013.5.1.mDL";
    public const string DefaultNamespace = "org.iso.18013.5.1";

    private readonly ECDsa _iacaKey;
    private readonly bool _ownsIaca;
    private readonly ECDsa _dsKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    /// <param name="iacaSubject">
    /// The IACA's name. Two builders trusted side by side get distinct names, so nothing about which issuer a
    /// chain reaches depends on how a platform breaks a tie between same-named ones.
    /// </param>
    public MdocTestBuilder(string iacaSubject = "CN=Test IACA Root")
    {
        _iacaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _ownsIaca = true;
        var iacaReq = new CertificateRequest(iacaSubject, _iacaKey, HashAlgorithmName.SHA256);
        iacaReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        iacaReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(iacaReq.PublicKey, false));
        IacaCertificate = iacaReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(5));
        DsCertificate = IssueDocumentSigner();
    }

    /// <summary>
    /// A builder whose Document Signer is issued by <paramref name="issuer"/>, a CA the caller owns and
    /// disposes; it may itself sit under another root.
    /// </summary>
    public MdocTestBuilder(X509Certificate2 issuer, ECDsa issuerKey)
    {
        _iacaKey = issuerKey;
        IacaCertificate = issuer;
        DsCertificate = IssueDocumentSigner();
    }

    private X509Certificate2 IssueDocumentSigner()
    {
        var dsReq = new CertificateRequest("CN=Test Document Signer", _dsKey, HashAlgorithmName.SHA256);
        if (IacaCertificate.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Any())
        {
            dsReq.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(IacaCertificate, true, false));
        }

        // By key rather than by certificate, so an issuer handed in without its private key attached works too.
        return dsReq.Create(
            IacaCertificate.SubjectName, X509SignatureGenerator.CreateForECDsa(_iacaKey), DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1),
            Guid.NewGuid().ToByteArray());
    }

    public X509Certificate2 IacaCertificate { get; }

    public X509Certificate2 DsCertificate { get; }

    public ECDsa DeviceKey => _deviceKey;

    /// <summary>The key that issued <see cref="DsCertificate"/>, for issuing MSO revocation list signers.</summary>
    public ECDsa IacaKey => _iacaKey;

    /// <summary>A certificate appended to the MSO's x5chain, as a presenter could add to the unprotected header.</summary>
    public X509Certificate2? ExtraX5ChainCertificate { get; set; }

    /// <summary>Put only the Document Signer in the MSO's x5chain, not the certificate that issued it.</summary>
    public bool X5ChainWithoutIssuer { get; set; }

    /// <summary>An encoded MSO <c>status</c> element to sign into the MSO, or null for none.</summary>
    public byte[]? MsoStatus { get; set; }

    public string DocType { get; set; } = DefaultDocType;

    /// <summary>docType written into the MSO; defaults to <see cref="DocType"/>.</summary>
    public string? MsoDocType { get; set; }

    public string DigestAlgorithm { get; set; } = "SHA-256";

    public DateTimeOffset ValidFrom { get; set; } = DateTimeOffset.UtcNow.AddMinutes(-10);

    public DateTimeOffset ValidUntil { get; set; } = DateTimeOffset.UtcNow.AddDays(30);

    /// <summary>Claims to issue, in insertion order; digestIDs are assigned sequentially.</summary>
    public Dictionary<string, object?> Claims { get; } = new(StringComparer.Ordinal)
    {
        ["family_name"] = "Mobius",
        ["age_over_18"] = true,
    };

    /// <summary>Mutates one encoded item after digest computation, to model tampering.</summary>
    public Func<byte[], string, byte[]>? TamperItem { get; set; }

    /// <summary>Signs the MSO with this key instead of the DS certificate's key (signature mismatch).</summary>
    public ECDsa? SignerKeyOverride { get; set; }

    /// <summary>Session parameters the device signature binds to (the wallet's view of the request).</summary>
    public string ClientId { get; set; } = "x509_san_dns:verifier.test";

    public string Nonce { get; set; } = "test-nonce";

    public byte[]? EncryptionKeyThumbprint { get; set; }

    public string ResponseUri { get; set; } = "https://verifier.test/callback";

    /// <summary>Whether to emit the deviceSigned structure. Default true.</summary>
    public bool IncludeDeviceAuth { get; set; } = true;

    /// <summary>Signs deviceAuth with this key instead of the MSO's device key (holder mismatch).</summary>
    public ECDsa? DeviceSignerOverride { get; set; }

    /// <summary>Signs issuerAuth under ESP256 (-9) instead of ES256 (-7).</summary>
    public bool IssuerAuthEsp256 { get; set; }

    /// <summary>Signs the deviceSignature under ESP256 (-9) instead of ES256 (-7).</summary>
    public bool DeviceSignatureEsp256 { get; set; }

    /// <summary>Signs issuerAuth with its payload detached, which no valid mdoc does.</summary>
    public bool IssuerAuthDetached { get; set; }

    /// <summary>Signs the deviceSignature with its payload embedded, which no valid mdoc does.</summary>
    public bool DeviceSignatureEmbedded { get; set; }

    /// <summary>Writes issuerAuth's protected alg as this text instead of an integer.</summary>
    public string? IssuerAuthTextAlg { get; set; }

    /// <summary>Emits a deviceMac instead of a deviceSignature.</summary>
    public bool UseDeviceMac { get; set; }

    /// <summary>Builds a DeviceResponse and returns it base64url-encoded (the vp_token form).</summary>
    public string BuildBase64Url() => Base64UrlEncoder.Encode(Build());

    /// <summary>Builds the raw CBOR DeviceResponse.</summary>
    public byte[] Build()
    {
        List<byte[]> encodedItems = [];
        List<byte[]> digests = [];
        long digestId = 0;
        foreach (var (name, value) in Claims)
        {
            var item = EncodeIssuerSignedItem(digestId++, name, value);
            digests.Add(Hash(item));
            encodedItems.Add(TamperItem is null ? item : TamperItem(item, name));
        }

        var issuerAuth = SignMso(digests);

        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartMap(3);
        w.WriteTextString("version");
        w.WriteTextString("1.0");
        w.WriteTextString("documents");
        w.WriteStartArray(1);
        w.WriteStartMap(IncludeDeviceAuth ? 3 : 2);
        w.WriteTextString("docType");
        w.WriteTextString(DocType);
        w.WriteTextString("issuerSigned");
        w.WriteStartMap(2);
        w.WriteTextString("nameSpaces");
        w.WriteStartMap(1);
        w.WriteTextString(DefaultNamespace);
        w.WriteStartArray(encodedItems.Count);
        foreach (var item in encodedItems)
        {
            w.WriteEncodedValue(item);
        }

        w.WriteEndArray();
        w.WriteEndMap();
        w.WriteTextString("issuerAuth");
        w.WriteEncodedValue(issuerAuth);
        w.WriteEndMap();
        if (IncludeDeviceAuth)
        {
            WriteDeviceSigned(w);
        }

        w.WriteEndMap();
        w.WriteEndArray();
        w.WriteTextString("status");
        w.WriteInt32(0);
        w.WriteEndMap();
        return w.Encode();
    }

    private void WriteDeviceSigned(CborWriter w)
    {
        // DeviceNameSpacesBytes = #6.24(bstr .cbor {}) — remote presentations disclose nothing device-signed.
        var emptyMap = new CborWriter(CborConformanceMode.Lax);
        emptyMap.WriteStartMap(0);
        emptyMap.WriteEndMap();
        var nameSpacesBytes = new CborWriter(CborConformanceMode.Lax);
        nameSpacesBytes.WriteTag((CborTag)24);
        nameSpacesBytes.WriteByteString(emptyMap.Encode());
        var encodedNameSpaces = nameSpacesBytes.Encode();

        var transcript = SessionTranscriptBuilder.Build(ClientId, Nonce, EncryptionKeyThumbprint, ResponseUri);
        var deviceAuthBytes = SessionTranscriptBuilder.BuildDeviceAuthenticationBytes(transcript, DocType, encodedNameSpaces);
        var deviceSigner = new CoseSigner(DeviceSignerOverride ?? _deviceKey, HashAlgorithmName.SHA256);
        var signature = DeviceSignatureEmbedded
            ? CoseSign1Message.SignEmbedded(deviceAuthBytes, deviceSigner)
            : CoseSign1Message.SignDetached(deviceAuthBytes, deviceSigner);
        if (DeviceSignatureEsp256)
        {
            signature = Esp256.Resign(signature, DeviceSignerOverride ?? _deviceKey, deviceAuthBytes);
        }

        w.WriteTextString("deviceSigned");
        w.WriteStartMap(2);
        w.WriteTextString("nameSpaces");
        w.WriteEncodedValue(encodedNameSpaces);
        w.WriteTextString("deviceAuth");
        w.WriteStartMap(1);
        w.WriteTextString(UseDeviceMac ? "deviceMac" : "deviceSignature");
        w.WriteEncodedValue(signature); // for the MAC case only presence matters; the verifier rejects it first
        w.WriteEndMap();
        w.WriteEndMap();
    }

    private static byte[] EncodeIssuerSignedItem(long digestId, string name, object? value)
    {
        var inner = new CborWriter(CborConformanceMode.Lax);
        inner.WriteStartMap(4);
        inner.WriteTextString("digestID");
        inner.WriteInt64(digestId);
        inner.WriteTextString("random");
        inner.WriteByteString(RandomNumberGenerator.GetBytes(16));
        inner.WriteTextString("elementIdentifier");
        inner.WriteTextString(name);
        inner.WriteTextString("elementValue");
        WriteValue(inner, value);
        inner.WriteEndMap();

        // IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)
        var outer = new CborWriter(CborConformanceMode.Lax);
        outer.WriteTag((CborTag)24);
        outer.WriteByteString(inner.Encode());
        return outer.Encode();
    }

    private static void WriteValue(CborWriter w, object? value)
    {
        switch (value)
        {
            case null: w.WriteNull(); break;
            case string s: w.WriteTextString(s); break;
            case bool b: w.WriteBoolean(b); break;
            case int i: w.WriteInt64(i); break;
            case long l: w.WriteInt64(l); break;
            case byte[] bytes: w.WriteByteString(bytes); break;
            // A value the claim writes for itself, for shapes the cases above cannot express.
            case Action<CborWriter> write: write(w); break;
            default: throw new NotSupportedException($"Unsupported test claim type {value.GetType()}.");
        }
    }

    private byte[] SignMso(List<byte[]> digests)
    {
        var mso = new CborWriter(CborConformanceMode.Lax);
        mso.WriteStartMap(MsoStatus is null ? 6 : 7);
        mso.WriteTextString("version");
        mso.WriteTextString("1.0");
        mso.WriteTextString("digestAlgorithm");
        mso.WriteTextString(DigestAlgorithm);
        mso.WriteTextString("valueDigests");
        mso.WriteStartMap(1);
        mso.WriteTextString(DefaultNamespace);
        mso.WriteStartMap(digests.Count);
        for (var i = 0; i < digests.Count; i++)
        {
            mso.WriteInt32(i);
            mso.WriteByteString(digests[i]);
        }

        mso.WriteEndMap();
        mso.WriteEndMap();
        mso.WriteTextString("deviceKeyInfo");
        mso.WriteStartMap(1);
        mso.WriteTextString("deviceKey");
        WriteCoseKey(mso, _deviceKey);
        mso.WriteEndMap();
        mso.WriteTextString("docType");
        mso.WriteTextString(MsoDocType ?? DocType);
        mso.WriteTextString("validityInfo");
        mso.WriteStartMap(3);
        mso.WriteTextString("signed");
        WriteTDate(mso, DateTimeOffset.UtcNow);
        mso.WriteTextString("validFrom");
        WriteTDate(mso, ValidFrom);
        mso.WriteTextString("validUntil");
        WriteTDate(mso, ValidUntil);
        mso.WriteEndMap();
        if (MsoStatus is not null)
        {
            mso.WriteTextString("status");
            mso.WriteEncodedValue(MsoStatus);
        }

        mso.WriteEndMap();

        // MobileSecurityObjectBytes = #6.24(bstr .cbor MSO), signed as the COSE_Sign1 payload.
        var payload = new CborWriter(CborConformanceMode.Lax);
        payload.WriteTag((CborTag)24);
        payload.WriteByteString(mso.Encode());

        var signer = new CoseSigner(SignerKeyOverride ?? _dsKey, HashAlgorithmName.SHA256);
        // SPEC: RFC 9360 — x5chain at header label 33; DS certificate first, then the chain.
        signer.UnprotectedHeaders.Add(new CoseHeaderLabel(33), CoseHeaderValue.FromEncodedValue(EncodeChain()));
        var issuerAuth = IssuerAuthDetached
            ? CoseSign1Message.SignDetached(payload.Encode(), signer)
            : CoseSign1Message.SignEmbedded(payload.Encode(), signer);
        if (IssuerAuthTextAlg is { } textAlg)
        {
            return Esp256.ResignWithTextAlg(issuerAuth, SignerKeyOverride ?? _dsKey, textAlg);
        }

        return IssuerAuthEsp256 ? Esp256.Resign(issuerAuth, SignerKeyOverride ?? _dsKey) : issuerAuth;
    }

    private byte[] EncodeChain()
    {
        List<byte[]> chain = [DsCertificate.RawData];
        if (!X5ChainWithoutIssuer)
        {
            chain.Add(IacaCertificate.RawData);
        }

        if (ExtraX5ChainCertificate is { } extra)
        {
            chain.Add(extra.RawData);
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

    private static void WriteCoseKey(CborWriter w, ECDsa key) =>
        w.WriteEncodedValue(CoseKey.EncodeP256(key.ExportParameters(false)));

    private static void WriteTDate(CborWriter w, DateTimeOffset value)
    {
        w.WriteTag((CborTag)0);
        w.WriteTextString(value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture));
    }

    private byte[] Hash(byte[] data) => DigestAlgorithm switch
    {
        "SHA-384" => SHA384.HashData(data),
        "SHA-512" => SHA512.HashData(data),
        _ => SHA256.HashData(data),
    };

    public void Dispose()
    {
        DsCertificate.Dispose();
        if (_ownsIaca)
        {
            IacaCertificate.Dispose();
            _iacaKey.Dispose();
        }

        _dsKey.Dispose();
        _deviceKey.Dispose();
    }
}
