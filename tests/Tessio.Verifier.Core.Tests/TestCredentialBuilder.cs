using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.Core.Tests;

/// <summary>
/// Builds real, signed SD-JWT VC presentations for tests: ES256 issuer/holder keys, selective
/// disclosures with salts, optional decoys, cnf.jwk, KB-JWT, and an optional self-signed x5c chain.
/// Structure follows RFC 9901 §4 / draft-ietf-oauth-sd-jwt-vc-13.
/// </summary>
internal sealed class TestCredentialBuilder : IDisposable
{
    public const string DefaultIssuer = "https://issuer.example";
    public const string DefaultVct = "https://credentials.example/identity";
    public const string DefaultAudience = "https://verifier.example";
    public const string DefaultNonce = "test-nonce-1234";

    private readonly ECDsa _issuerEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _holderEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public string Issuer { get; set; } = DefaultIssuer;

    public string? Vct { get; set; } = DefaultVct;

    public string Typ { get; set; } = "dc+sd-jwt";

    public long? Exp { get; set; } = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();

    public long? Nbf { get; set; }

    /// <summary>Claims embedded plainly (not selectively disclosable).</summary>
    public Dictionary<string, object> PlainClaims { get; } = [];

    /// <summary>Claims hidden behind top-level _sd digests. All are disclosed unless listed in <see cref="Withhold"/>.</summary>
    public Dictionary<string, object> SdClaims { get; } = new() { ["family_name"] = "Möbius", ["age_over_18"] = true };

    /// <summary>SD claim names to keep undisclosed (digest present, disclosure absent).</summary>
    public HashSet<string> Withhold { get; } = [];

    /// <summary>Extra digests with no matching disclosure (decoys, RFC 9901 §4.2.5).</summary>
    public int DecoyDigests { get; set; }

    /// <summary>Raw disclosure strings appended on top of the generated ones (e.g. unreferenced ones).</summary>
    public List<string> ExtraDisclosures { get; } = [];

    /// <summary>Rewrites the serialized issuer payload before signing, for shapes a dictionary cannot hold (a repeated key).</summary>
    public Func<string, string>? RewritePayloadJson { get; set; }

    /// <summary>Rewrites the serialized KB-JWT payload before signing, for an iat no DateTimeOffset holds.</summary>
    public Func<string, string>? RewriteKbPayloadJson { get; set; }

    /// <summary>Extra raw digest strings injected into the top-level _sd array.</summary>
    public List<string> ExtraSdDigests { get; } = [];

    public bool IncludeCnf { get; set; } = true;

    public bool IncludeKbJwt { get; set; } = true;

    public string KbAudience { get; set; } = DefaultAudience;

    public string KbNonce { get; set; } = DefaultNonce;

    public string? SdAlg { get; set; } = "sha-256";

    /// <summary>When set, the issuer JWT carries this x5c chain instead of using metadata resolution.</summary>
    public X509Certificate2? Certificate { get; private set; }

    /// <summary>When set, the credential carries a status claim referencing a Token Status List.</summary>
    public (long Idx, string Uri)? Status { get; set; }

    /// <summary>Overrides the KB-JWT iat; null uses now.</summary>
    public DateTimeOffset? KbIatOverride { get; set; }

    /// <summary>Overrides the sd_hash input; null computes the correct value.</summary>
    public string? SdHashOverride { get; set; }

    /// <summary>When set, the KB-JWT acknowledges these transaction_data strings (sha-256 hashes).</summary>
    public List<string>? TransactionData { get; set; }

    /// <summary>Raw transaction_data_hashes to emit instead of computing them (for negatives).</summary>
    public List<string>? TransactionDataHashesOverride { get; set; }

    /// <summary>When set, the KB-JWT declares this transaction_data_hashes_alg.</summary>
    public string? TransactionDataHashesAlg { get; set; }

    public ECDsaSecurityKey IssuerPublicKey => new(ECDsa.Create(_issuerEcdsa.ExportParameters(false)));

    /// <summary>Creates a self-signed ES256 certificate whose SAN DNS matches the issuer host, and switches to x5c mode.</summary>
    /// <param name="sanDnsName">The DNS name to assert, or null for the issuer's own host.</param>
    /// <param name="withSan">
    /// False builds a leaf carrying NO subject alternative name, which is what the EUDI Wallet
    /// Reference Implementation's PID issuer ships. Every other caller here asserts a name, so the
    /// no-name case was unreachable from the tests and went unnoticed until a real credential met it.
    /// </param>
    /// <param name="sanUri">
    /// When set, the SAN carries ONLY this uniformResourceIdentifier and no dNSName. That certificate
    /// asserts a name the platform's DNS enumeration cannot see, which is a different case from
    /// asserting none, and only the URI fallback can answer it.
    /// </param>
    public X509Certificate2 UseCertificate(string? sanDnsName = null, bool withSan = true, string? sanUri = null)
    {
        var request = new CertificateRequest("CN=Test Issuer", _issuerEcdsa, HashAlgorithmName.SHA256);
        if (withSan)
        {
            var san = new SubjectAlternativeNameBuilder();
            if (sanUri is not null)
            {
                san.AddUri(new Uri(sanUri));
            }
            else
            {
                san.AddDnsName(sanDnsName ?? new Uri(Issuer).Host);
            }

            request.CertificateExtensions.Add(san.Build());
        }

        Certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
        return Certificate;
    }

    /// <summary>The issuer's public JWK Set JSON, for serving as JWT VC Issuer Metadata.</summary>
    public string BuildJwksJson()
    {
        var p = _issuerEcdsa.ExportParameters(false);
        return JsonSerializer.Serialize(new
        {
            keys = new[]
            {
                new
                {
                    kty = "EC",
                    crv = "P-256",
                    x = Base64UrlEncoder.Encode(p.Q.X!),
                    y = Base64UrlEncoder.Encode(p.Q.Y!),
                },
            },
        });
    }

    public string Build()
    {
        var payload = new Dictionary<string, object?>();
        if (Issuer.Length > 0)
        {
            payload["iss"] = Issuer;
        }

        if (Vct is not null)
        {
            payload["vct"] = Vct;
        }

        if (Exp is not null)
        {
            payload["exp"] = Exp;
        }

        if (Nbf is not null)
        {
            payload["nbf"] = Nbf;
        }

        if (SdAlg is not null)
        {
            payload["_sd_alg"] = SdAlg;
        }

        if (Status is { } status)
        {
            // SPEC: draft-ietf-oauth-status-list-20 §6.2: the referenced-token status claim.
            payload["status"] = new Dictionary<string, object>
            {
                ["status_list"] = new Dictionary<string, object> { ["idx"] = status.Idx, ["uri"] = status.Uri },
            };
        }

        if (IncludeCnf)
        {
            var hp = _holderEcdsa.ExportParameters(false);
            payload["cnf"] = new Dictionary<string, object>
            {
                ["jwk"] = new Dictionary<string, object>
                {
                    ["kty"] = "EC",
                    ["crv"] = "P-256",
                    ["x"] = Base64UrlEncoder.Encode(hp.Q.X!),
                    ["y"] = Base64UrlEncoder.Encode(hp.Q.Y!),
                },
            };
        }

        foreach (var (name, value) in PlainClaims)
        {
            payload[name] = value;
        }

        // Top-level _sd array + matching disclosures (RFC 9901 §4.2.1/§4.2.4.1).
        var digests = new List<string>();
        var disclosures = new List<string>();
        foreach (var (name, value) in SdClaims)
        {
            var disclosure = MakeDisclosure(name, value);
            digests.Add(DisclosureProcessor.ComputeDigest(disclosure));
            if (!Withhold.Contains(name))
            {
                disclosures.Add(disclosure);
            }
        }

        for (var i = 0; i < DecoyDigests; i++)
        {
            digests.Add(DisclosureProcessor.ComputeDigest(MakeDisclosure($"decoy{i}", i)));
        }

        digests.AddRange(ExtraSdDigests);
        if (digests.Count > 0)
        {
            payload["_sd"] = digests;
        }

        disclosures.AddRange(ExtraDisclosures);

        var issuerJwt = SignJwt(
            RewritePayloadJson?.Invoke(JsonSerializer.Serialize(payload)) ?? JsonSerializer.Serialize(payload),
            new ECDsaSecurityKey(_issuerEcdsa),
            Typ,
            Certificate is { } cert ? new List<string> { Convert.ToBase64String(cert.RawData) } : null);

        var withoutKb = issuerJwt + "~" + string.Concat(disclosures.Select(d => d + "~"));
        if (!IncludeKbJwt)
        {
            return withoutKb;
        }

        // SPEC: RFC 9901 §4.3 — KB-JWT over aud, nonce, iat, and sd_hash of the presented part.
        var sdHash = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(SdHashOverride ?? withoutKb)));
        var kbClaims = new Dictionary<string, object>
        {
            ["iat"] = (KbIatOverride ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds(),
            ["aud"] = KbAudience,
            ["nonce"] = KbNonce,
            ["sd_hash"] = sdHash,
        };
        var hashes = TransactionDataHashesOverride
            ?? TransactionData?.Select(td => Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(td)))).ToList();
        if (hashes is not null)
        {
            kbClaims["transaction_data_hashes"] = hashes;
        }

        if (TransactionDataHashesAlg is not null)
        {
            kbClaims["transaction_data_hashes_alg"] = TransactionDataHashesAlg;
        }

        var kbPayload = RewriteKbPayloadJson?.Invoke(JsonSerializer.Serialize(kbClaims)) ?? JsonSerializer.Serialize(kbClaims);

        return withoutKb + SignJwt(kbPayload, new ECDsaSecurityKey(_holderEcdsa), "kb+jwt", x5c: null);
    }

    /// <summary>
    /// Builds a signed Token Status List JWT for the given per-index status values, packed LSB-first
    /// and zlib-deflate compressed per draft-ietf-oauth-status-list-20 §4.1/§4.2.
    /// </summary>
    /// <remarks>
    /// Set <c>signWith</c> to sign with that certificate's key and carry it in an <c>x5c</c> header.
    /// Without it every status list token here resolves by METADATA with an empty chain, which a trust
    /// seam judges by identifier rather than by anchoring. The real tokens this code meets carry x5c,
    /// so a suite with no x5c status token says nothing about the anchoring path. Added 2026-09-20
    /// after review found that gap.
    /// <c>statusList</c> replaces the <c>status_list</c> claim, given the encoded <c>lst</c>, for a claim of
    /// the wrong JSON shape. <c>rewritePayloadJson</c> edits the serialized payload before signing, for JSON a
    /// dictionary cannot hold, such as a repeated member.
    /// </remarks>
    public string BuildStatusListToken(
        string uri, int bits, byte[] statuses, object? exp = null, string typ = "statuslist+jwt", string? sub = null,
        object? ttl = null, X509Certificate2? signWith = null, bool includeIat = true, object? nbf = null, object? iat = null,
        Func<string, object>? statusList = null, Func<string, string>? rewritePayloadJson = null)
    {
        var packed = new byte[(statuses.Length * bits + 7) / 8];
        for (var i = 0; i < statuses.Length; i++)
        {
            packed[i * bits / 8] |= (byte)(statuses[i] << (i * bits % 8));
        }

        byte[] compressed;
        using (var output = new MemoryStream())
        {
            using (var zlib = new System.IO.Compression.ZLibStream(output, System.IO.Compression.CompressionMode.Compress, leaveOpen: true))
            {
                zlib.Write(packed);
            }

            compressed = output.ToArray();
        }

        var claims = new Dictionary<string, object>
        {
            ["iss"] = Issuer,
            ["sub"] = sub ?? uri,
            ["status_list"] = statusList?.Invoke(Base64UrlEncoder.Encode(compressed)) ?? new Dictionary<string, object>
            {
                ["bits"] = bits,
                ["lst"] = Base64UrlEncoder.Encode(compressed),
            },
        };
        if (includeIat)
        {
            claims["iat"] = iat ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        }

        if (exp is { } expValue)
        {
            claims["exp"] = expValue;
        }

        if (nbf is { } nbfValue)
        {
            claims["nbf"] = nbfValue;
        }

        if (ttl is { } ttlValue)
        {
            claims["ttl"] = ttlValue;
        }

        var payload = JsonSerializer.Serialize(claims);
        payload = rewritePayloadJson?.Invoke(payload) ?? payload;

        if (signWith is null)
        {
            return SignJwt(payload, new ECDsaSecurityKey(_issuerEcdsa), typ, x5c: null);
        }

        return SignJwt(
            payload,
            new ECDsaSecurityKey(signWith.GetECDsaPrivateKey() ?? throw new InvalidOperationException("signWith has no EC private key.")),
            typ,
            [Convert.ToBase64String(signWith.RawData)]);
    }

    public static string MakeDisclosure(string name, object? value) =>
        Base64UrlEncoder.Encode(JsonSerializer.Serialize(new[] { "salt-" + name, name, value }));

    public static string MakeArrayDisclosure(object? value) =>
        Base64UrlEncoder.Encode(JsonSerializer.Serialize(new[] { "salt-array", value }));

    private static string SignJwt(string payload, SecurityKey key, string typ, List<string>? x5c)
    {
        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        var headers = new Dictionary<string, object> { ["typ"] = typ };
        if (x5c is not null)
        {
            headers["x5c"] = x5c;
        }

        return handler.CreateToken(
            payload,
            new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256),
            headers);
    }

    public void Dispose()
    {
        _issuerEcdsa.Dispose();
        _holderEcdsa.Dispose();
        Certificate?.Dispose();
    }
}
