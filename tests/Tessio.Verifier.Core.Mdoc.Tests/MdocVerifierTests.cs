using System.Security.Cryptography;
using Tessio.Verifier.Core;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// End-to-end mdoc verification: issuerAuth signature, IACA trust anchoring, validity window,
/// digest checks and the claim mapping. Mirrors the negative families of the SD-JWT suite.
/// </summary>
public sealed class MdocVerifierTests : IDisposable
{
    private readonly MdocTestBuilder _builder = new();

    private static MdocVerifier VerifierFor(MdocTestBuilder builder) => new(
        new StaticTrustListResolver(
            [builder.DsCertificate.Subject], source: "mdoc-test", trustAnchors: [builder.IacaCertificate]));

    private static PresentedCredential Credential(MdocTestBuilder builder, string format = MdocVerifier.Format) =>
        new() { Format = format, RawValue = builder.BuildBase64Url() };

    private MdocVerificationContext Context(string? docType = MdocTestBuilder.DefaultDocType) => ContextFor(_builder, docType);

    private static MdocVerificationContext ContextFor(MdocTestBuilder builder, string? docType = MdocTestBuilder.DefaultDocType) =>
        new()
        {
            ExpectedDocType = docType,
            ClientId = builder.ClientId,
            Nonce = builder.Nonce,
            EncryptionKeyThumbprint = builder.EncryptionKeyThumbprint,
            ResponseUri = builder.ResponseUri,
        };

    [Fact]
    public async Task ValidMdoc_Verifies_WithNamespacedClaims()
    {
        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
        Assert.True(result.Issuer.Trusted);
        Assert.Equal("x5c", result.Issuer.KeyResolutionMethod);
        Assert.Contains("Test Document Signer", result.Issuer.Identifier, StringComparison.Ordinal);

        var elements = Assert.IsType<Dictionary<string, object?>>(result.DisclosedClaims[MdocTestBuilder.DefaultNamespace]);
        Assert.Equal("Mobius", elements["family_name"]);
        Assert.Equal(true, elements["age_over_18"]);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task AnMdocSignedUnderEsp256_Verifies(bool issuerAuth, bool deviceSignature)
    {
        // SPEC: HAIP 1.0 section 7, verifiers support COSE -7 "or -9, as applicable". RFC 9864 registers -9 as
        // ESP256, ECDSA on P-256 with SHA-256, which the platform's COSE implementation does not know.
        _builder.IssuerAuthEsp256 = issuerAuth;
        _builder.DeviceSignatureEsp256 = deviceSignature;

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
    }

    public static TheoryData<int> AdvertisedAlgorithms() => [.. CoseAlgorithms.Advertised];

    [Theory]
    [MemberData(nameof(AdvertisedAlgorithms))]
    public async Task EveryAlgorithmARequestAdvertises_Verifies(int alg)
    {
        // A request tells the wallet these are accepted (issuerauth_alg_values, deviceauth_alg_values), so each
        // must verify under both. A value added to the list without a signer here fails, rather than passing
        // untested.
        var esp256 = alg switch
        {
            CoseAlgorithms.Es256 => false,
            CoseAlgorithms.Esp256 => true,
            _ => throw new InvalidOperationException($"No test signer for COSE algorithm {alg}; add one before advertising it."),
        };
        _builder.IssuerAuthEsp256 = esp256;
        _builder.DeviceSignatureEsp256 = esp256;

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
    }

    [Fact]
    public async Task AnIssuerAuthUnderEsp256_ByAnotherKey_IsRefused()
    {
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _builder.IssuerAuthEsp256 = true;
        _builder.SignerKeyOverride = other;

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.SignatureInvalid);
    }

    [Fact]
    public async Task ADeviceSignatureUnderEsp256_ByAnotherKey_IsRefused()
    {
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _builder.DeviceSignatureEsp256 = true;
        _builder.DeviceSignerOverride = other;

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.DeviceAuthInvalid);
    }

    [Fact]
    public async Task ADetachedIssuerAuth_IsRefused_NotThrown()
    {
        // The signature is checked before the MSO is read, and the platform throws InvalidOperationException for
        // an embedded check of a detached message. That used to escape VerifyAsync.
        _builder.IssuerAuthDetached = true;

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.MsoInvalid);
    }

    [Fact]
    public async Task AnIssuerAuthMarkingAHeaderCriticalItDoesNotProcess_IsRefused()
    {
        // SPEC: RFC 9052 section 3.1, crit names the headers "an application that is processing a message is required
        // to understand". The platform verifies such a signature regardless.
        _builder.IssuerAuthCritical = [99];

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.MsoInvalid
            && e.Message.Contains("critical", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ADeviceSignatureMarkingAHeaderCriticalItDoesNotProcess_IsRefused()
    {
        _builder.DeviceSignatureCritical = [99];

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.DeviceAuthInvalid
            && e.Message.Contains("critical", StringComparison.Ordinal));
    }

    // A tagged COSE_Sign1 whose protected header has a label past Int32, which makes the platform's decoder throw
    // OverflowException. Nothing here is signed: the decoder refuses it first.
    private static byte[] CoseSign1WithAHugeHeaderLabel(bool detached)
    {
        var protectedMap = new System.Formats.Cbor.CborWriter();
        protectedMap.WriteStartMap(2);
        protectedMap.WriteInt32(1);
        protectedMap.WriteInt32(-7);
        protectedMap.WriteUInt64(1UL << 32);
        protectedMap.WriteInt32(0);
        protectedMap.WriteEndMap();
        var w = new System.Formats.Cbor.CborWriter();
        w.WriteTag((System.Formats.Cbor.CborTag)18);
        w.WriteStartArray(4);
        w.WriteByteString(protectedMap.Encode());
        w.WriteStartMap(0);
        w.WriteEndMap();
        if (detached)
        {
            w.WriteNull();
        }
        else
        {
            w.WriteByteString([1]);
        }

        w.WriteByteString(new byte[64]);
        w.WriteEndArray();
        return w.Encode();
    }

    [Fact]
    public async Task AnIssuerAuthTheDecoderCannotRead_IsRefused_NotThrown()
    {
        // Verification returns a result for bad input; an OverflowException used to escape VerifyAsync here.
        _builder.IssuerAuthBytes = CoseSign1WithAHugeHeaderLabel(detached: false);

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.MsoInvalid);
    }

    [Fact]
    public async Task ADeviceSignatureTheDecoderCannotRead_IsRefused_NotThrown()
    {
        _builder.DeviceSignatureBytes = CoseSign1WithAHugeHeaderLabel(detached: true);

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.DeviceAuthInvalid);
    }

    [Fact]
    public async Task AnIssuerAuthWithATextAlg_IsRefused_NotThrown()
    {
        // Reading a text alg as an integer throws InvalidOperationException, which used to escape VerifyAsync.
        _builder.IssuerAuthTextAlg = "ES256";

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.AlgorithmNotAllowed);
    }

    [Fact]
    public async Task ADeviceSignatureCarryingItsPayload_IsRefused_NotThrown()
    {
        // The platform throws InvalidOperationException for a detached check of a message with content, and the
        // device check caught only CryptographicException and ArgumentException.
        _builder.DeviceSignatureEmbedded = true;

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.False(result.IsValid);
        // Named for what is wrong, rather than "does not verify", which would send a wallet developer to the key.
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.DeviceAuthInvalid
            && e.Message.Contains("must be detached", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ExternalSessionTranscript_IsUsedVerbatimForDeviceAuth()
    {
        // The builder signs over the redirect transcript of its own values. Handing the verifier
        // those same bytes externally, with every redirect field left null, must verify: the
        // override is used as given and nothing else is consulted to build one.
        var transcript = SessionTranscriptBuilder.Build(
            _builder.ClientId, _builder.Nonce, _builder.EncryptionKeyThumbprint, _builder.ResponseUri);
        var context = new MdocVerificationContext
        {
            ExpectedDocType = MdocTestBuilder.DefaultDocType,
            SessionTranscript = transcript,
        };

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), context);

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
    }

    [Fact]
    public async Task ExternalSessionTranscript_TheDeviceDidNotSign_FailsDeviceAuth()
    {
        var context = new MdocVerificationContext
        {
            ExpectedDocType = MdocTestBuilder.DefaultDocType,
            SessionTranscript = SessionTranscriptBuilder.BuildForIso18013AnnexC([0x01], "https://verifier.example.com"),
        };

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), context);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.DeviceAuthInvalid);
    }

    [Fact]
    public async Task SpoofedDocumentSigner_IsUntrusted()
    {
        // A second issuer with its own IACA: same doctype and claims, but its chain does not anchor
        // on the trust list configured for the first issuer.
        using var spoof = new MdocTestBuilder();
        var verifier = new MdocVerifier(new StaticTrustListResolver(
            [spoof.DsCertificate.Subject], source: "mdoc-test", trustAnchors: [_builder.IacaCertificate]));

        var result = await verifier.VerifyAsync(Credential(spoof), ContextFor(spoof));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.IssuerUntrusted);
    }

    [Fact]
    public async Task WrongSignerKey_FailsSignatureCheck()
    {
        using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _builder.SignerKeyOverride = wrongKey;

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.SignatureInvalid);
    }

    [Fact]
    public async Task ExpiredMso_IsRejected()
    {
        _builder.ValidUntil = DateTimeOffset.UtcNow.AddHours(-1);

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.CredentialExpired);
    }

    [Fact]
    public async Task NotYetValidMso_IsRejected()
    {
        _builder.ValidFrom = DateTimeOffset.UtcNow.AddHours(1);

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.CredentialNotYetValid);
    }

    [Fact]
    public async Task DocTypeMismatch_AgainstDcqlExpectation_IsRejected()
    {
        var result = await VerifierFor(_builder).VerifyAsync(
            Credential(_builder), Context(docType: "eu.europa.ec.eudi.pid.1"));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.DocTypeMismatch);
    }

    [Fact]
    public async Task TamperedClaim_FailsDigests_EvenWithValidSignature()
    {
        _builder.TamperItem = (encoded, name) => encoded; // baseline sanity: no tampering passes
        var baseline = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());
        Assert.True(baseline.IsValid);

        // Now actually swap a value after the MSO digests are fixed. The issuerAuth signature stays
        // valid (it covers the MSO, not the items), so only the digest check catches this.
        _builder.TamperItem = (encoded, name) => name == "age_over_18" ? ReplaceBool(encoded) : encoded;
        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.DigestMismatch);
        Assert.Empty(result.DisclosedClaims); // tampered presentations disclose nothing
    }

    [Fact]
    public async Task WrongFormat_IsRejected()
    {
        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder, format: "dc+sd-jwt"), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.FormatUnsupported);
    }

    [Fact]
    public async Task TrustResolver_ReceivesTheDsFirstChain()
    {
        ReadOnlyMemory<byte>[]? seen = null;
        var capturing = new CapturingResolver(chain => seen = chain);

        await new MdocVerifier(capturing).VerifyAsync(Credential(_builder), Context());

        Assert.NotNull(seen);
        Assert.Equal(2, seen!.Length);
        Assert.Equal(_builder.DsCertificate.RawData, seen[0].ToArray());
        Assert.Equal(_builder.IacaCertificate.RawData, seen[1].ToArray());
    }

    /// <summary>
    /// A trust source that is down becomes a result with its own code, never an exception, so the
    /// verifier keeps its promise to return a result for any input.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TrustSourceDown_FailsClosed_WithoutThrowing(bool notReady)
    {
        var result = await new MdocVerifier(new ThrowingResolver(notReady)).VerifyAsync(Credential(_builder), Context());

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors, e => e.Code == MdocErrorCodes.IssuerTrustUnresolvable);
        Assert.Contains("trust source unreachable", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(result.Errors, e => e.Code == MdocErrorCodes.IssuerUntrusted);
    }

    /// <summary>
    /// A refusal whose cause is the list (ETSI TS 119 612 V2.4.1 section 5.3.15) is reported as the list's,
    /// not as an untrusted Document Signer.
    /// </summary>
    [Fact]
    public async Task ALapsedTrustList_IsReportedAsTheList_NotAsTheIssuer()
    {
        var result = await new MdocVerifier(new LapsedListResolver()).VerifyAsync(Credential(_builder), Context());

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors, e => e.Code == MdocErrorCodes.TrustListExpired);
        Assert.Equal("the list lapsed", error.Message);
        Assert.DoesNotContain(result.Errors, e => e.Code == MdocErrorCodes.IssuerUntrusted);
    }

    private sealed class LapsedListResolver : ITrustListResolver
    {
        public Task<IssuerTrustStatus> ResolveAsync(string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default) =>
            Task.FromResult(new IssuerTrustStatus { Trusted = false, Reason = "the list lapsed", TrustListExpired = true });
    }

    /// <summary>A cancellation the caller asked for is not a trust source failure, so it propagates.</summary>
    [Fact]
    public async Task ACallerCancellation_AtTheTrustSeam_StillPropagates()
    {
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new MdocVerifier(new CancellationObservingResolver()).VerifyAsync(Credential(_builder), Context(), cancelled.Token));
    }

    private sealed class CancellationObservingResolver : ITrustListResolver
    {
        public Task<IssuerTrustStatus> ResolveAsync(string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            return Task.FromResult(new IssuerTrustStatus { Trusted = true });
        }
    }

    private sealed class ThrowingResolver(bool notReady) : ITrustListResolver
    {
        public Task<IssuerTrustStatus> ResolveAsync(string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default) =>
            throw (notReady
                ? new InvalidOperationException("trust source unreachable")
                : new HttpRequestException("trust source unreachable"));
    }

    private sealed class CapturingResolver(Action<ReadOnlyMemory<byte>[]> onResolve) : ITrustListResolver
    {
        public Task<IssuerTrustStatus> ResolveAsync(string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default)
        {
            onResolve(x5c);
            return Task.FromResult(new IssuerTrustStatus { Trusted = true, TrustListSource = "capturing" });
        }
    }

    public void Dispose() => _builder.Dispose();

    /// <summary>Rewrites a bool elementValue to its negation inside IssuerSignedItemBytes.</summary>
    private static byte[] ReplaceBool(byte[] encoded)
    {
        var outerReader = new System.Formats.Cbor.CborReader(encoded, System.Formats.Cbor.CborConformanceMode.Lax);
        outerReader.ReadTag();
        var innerReader = new System.Formats.Cbor.CborReader(outerReader.ReadByteString(), System.Formats.Cbor.CborConformanceMode.Lax);

        var inner = new System.Formats.Cbor.CborWriter(System.Formats.Cbor.CborConformanceMode.Lax);
        innerReader.ReadStartMap();
        inner.WriteStartMap(4);
        while (innerReader.PeekState() != System.Formats.Cbor.CborReaderState.EndMap)
        {
            var key = innerReader.ReadTextString();
            inner.WriteTextString(key);
            if (key == "elementValue")
            {
                inner.WriteBoolean(!innerReader.ReadBoolean());
            }
            else
            {
                inner.WriteEncodedValue(innerReader.ReadEncodedValue().Span);
            }
        }

        inner.WriteEndMap();

        var outer = new System.Formats.Cbor.CborWriter(System.Formats.Cbor.CborConformanceMode.Lax);
        outer.WriteTag((System.Formats.Cbor.CborTag)24);
        outer.WriteByteString(inner.Encode());
        return outer.Encode();
    }

    /// <summary>
    /// The trust provenance the resolver returns has to REACH the caller, on both verdicts.
    /// </summary>
    /// <remarks>
    /// The resolver's own tests prove it computes these. They say nothing about whether this verifier
    /// copies them into <c>IssuerInfo</c>, which is a different claim: a mechanism can be correct and
    /// reach no caller. Deleting the three assignments in <c>MdocVerifier</c> leaves every other test in
    /// this file green, so this is the one that holds the wiring.
    /// </remarks>
    [Fact]
    public async Task IssuerInfo_CarriesTheTrustProvenance_OnSuccessAndOnFailure()
    {
        var expected = _builder.IacaCertificate.GetCertHashString(HashAlgorithmName.SHA256);

        var ok = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.True(ok.IsValid, string.Join("; ", ok.Errors.Select(e => e.Code)));
        Assert.Equal("mdoc-test", ok.Issuer.TrustListSource);
        Assert.Equal(_builder.IacaCertificate.Subject, ok.Issuer.TrustAnchorSubject);
        Assert.Equal(expected, ok.Issuer.TrustAnchorThumbprint);

        // A refusal names the list that refused and no anchor. This is the verdict a relying party comes
        // back to question, so it is the half worth pinning: an implementation that carried provenance
        // only on the passing branch would satisfy the assertions above and fail these.
        using var spoof = new MdocTestBuilder();
        var refused = await VerifierFor(spoof).VerifyAsync(Credential(_builder), ContextFor(spoof));

        Assert.False(refused.IsValid);
        Assert.Equal("mdoc-test", refused.Issuer.TrustListSource);
        Assert.Null(refused.Issuer.TrustAnchorSubject);
        Assert.Null(refused.Issuer.TrustAnchorThumbprint);
    }

    [Fact]
    public async Task CredentialType_ReportsTheDocType_OnSuccessAndOnFailure()
    {
        // For mdoc the type is the docType, which parsing establishes before any check runs, so unlike
        // the SD-JWT VC path there is no case where an issuer is known and the type is not.
        var ok = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.True(ok.IsValid, string.Join("; ", ok.Errors.Select(e => e.Code)));
        Assert.Equal(MdocTestBuilder.DefaultDocType, ok.CredentialType);

        var mismatched = await VerifierFor(_builder).VerifyAsync(
            Credential(_builder), Context("org.example.other"));

        Assert.False(mismatched.IsValid);
        Assert.Contains(mismatched.Errors, e => e.Code == MdocErrorCodes.DocTypeMismatch);
        Assert.Equal(MdocTestBuilder.DefaultDocType, mismatched.CredentialType);
    }
}
