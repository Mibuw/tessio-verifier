using System.Formats.Cbor;
using System.Security.Cryptography.Cose;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Decodes the base64url CBOR <c>DeviceResponse</c> from an OpenID4VP <c>vp_token</c> entry and the
/// Mobile Security Object from an <c>issuerAuth</c> COSE_Sign1. Reads leniently
/// (<see cref="CborConformanceMode.Lax"/>): wallets are not required to emit canonical CBOR, and
/// digests are computed over transported bytes, so re-encoding never happens.
/// </summary>
internal static class DeviceResponseParser
{
    public static ParsedDeviceResponse Parse(string base64UrlDeviceResponse)
    {
        byte[] cbor;
        try
        {
            cbor = Base64UrlEncoder.DecodeBytes(base64UrlDeviceResponse);
        }
        catch (FormatException)
        {
            throw new MdocProcessingException(MdocErrorCodes.StructureInvalid, "The mdoc presentation is not valid base64url.");
        }

        try
        {
            var reader = new CborReader(cbor, CborConformanceMode.Lax);
            return ReadDeviceResponse(reader);
        }
        catch (Exception e) when (CborFailure.IsMalformed(e))
        {
            throw new MdocProcessingException(MdocErrorCodes.StructureInvalid, $"The DeviceResponse CBOR is malformed: {e.Message}");
        }
    }

    /// <summary>Extracts and parses the MSO from the issuerAuth payload (tag-24 wrapped).</summary>
    public static MobileSecurityObject ParseMso(byte[] issuerAuth)
    {
        var message = CoseSign1Verification.Decode(issuerAuth, out var problem)
            ?? throw new MdocProcessingException(MdocErrorCodes.MsoInvalid, $"issuerAuth is not a valid COSE_Sign1: {problem}");
        var payload = message.Content?.ToArray();

        if (payload is null)
        {
            throw new MdocProcessingException(MdocErrorCodes.MsoInvalid, "issuerAuth carries no embedded payload.");
        }

        try
        {
            // SPEC: ISO 18013-5 §9.1.2.4 — payload is MobileSecurityObjectBytes = #6.24(bstr .cbor MSO).
            var outer = new CborReader(payload, CborConformanceMode.Lax);
            if (outer.PeekState() == CborReaderState.Tag)
            {
                outer.ReadTag();
            }

            var msoBytes = outer.ReadByteString();
            return ReadMso(new CborReader(msoBytes, CborConformanceMode.Lax));
        }
        catch (Exception e) when (CborFailure.IsMalformed(e))
        {
            throw new MdocProcessingException(MdocErrorCodes.MsoInvalid, $"The MSO CBOR is malformed: {e.Message}");
        }
    }

    private static ParsedDeviceResponse ReadDeviceResponse(CborReader reader)
    {
        string? version = null;
        long status = -1;
        List<ParsedDocument> documents = [];
        List<ReadOnlyMemory<byte>> zkDocuments = [];

        reader.ReadStartMap();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            switch (reader.ReadTextString())
            {
                case "version":
                    version = reader.ReadTextString();
                    break;
                case "status":
                    status = reader.ReadInt64();
                    break;
                case "documents":
                    reader.ReadStartArray();
                    while (reader.PeekState() != CborReaderState.EndArray)
                    {
                        documents.Add(ReadDocument(reader));
                    }

                    reader.ReadEndArray();
                    break;
                case "zkDocuments":
                    // SPEC: the member name follows the example of a zero knowledge response in the age
                    // verification technical specification 1.1.0, Annex A, A.11.
                    // Kept encoded, not read: ZkDocumentParser reads an entry only when one is verified.
                    // Only an array's items are kept; any other value is skipped, as before.
                    ReadEncodedArrayItems(reader, zkDocuments);
                    break;
                default:
                    reader.SkipValue();
                    break;
            }
        }

        reader.ReadEndMap();

        if (version is null || status < 0)
        {
            throw new MdocProcessingException(MdocErrorCodes.StructureInvalid, "The DeviceResponse lacks version or status.");
        }

        return new ParsedDeviceResponse
        {
            Version = version,
            Documents = documents,
            Status = status,
            ZkDocuments = zkDocuments,
        };
    }

    /// <summary>Adds each item of an array value to <paramref name="items"/> as encoded CBOR; skips any other value.</summary>
    private static void ReadEncodedArrayItems(CborReader reader, List<ReadOnlyMemory<byte>> items)
    {
        if (reader.PeekState() != CborReaderState.StartArray)
        {
            reader.SkipValue();
            return;
        }

        reader.ReadStartArray();
        while (reader.PeekState() != CborReaderState.EndArray)
        {
            items.Add(reader.ReadEncodedValue());
        }

        reader.ReadEndArray();
    }

    private static ParsedDocument ReadDocument(CborReader reader)
    {
        string? docType = null;
        IReadOnlyDictionary<string, IReadOnlyList<ParsedIssuerSignedItem>>? nameSpaces = null;
        byte[]? issuerAuth = null;
        ParsedDeviceSigned? deviceSigned = null;

        reader.ReadStartMap();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            switch (reader.ReadTextString())
            {
                case "docType":
                    docType = reader.ReadTextString();
                    break;
                case "issuerSigned":
                    (nameSpaces, issuerAuth) = ReadIssuerSigned(reader);
                    break;
                case "deviceSigned":
                    deviceSigned = ReadDeviceSigned(reader);
                    break;
                default:
                    reader.SkipValue();
                    break;
            }
        }

        reader.ReadEndMap();

        if (docType is null || issuerAuth is null)
        {
            throw new MdocProcessingException(MdocErrorCodes.StructureInvalid, "A document lacks docType or issuerAuth.");
        }

        return new ParsedDocument
        {
            DocType = docType,
            NameSpaces = nameSpaces ?? new Dictionary<string, IReadOnlyList<ParsedIssuerSignedItem>>(StringComparer.Ordinal),
            IssuerAuth = issuerAuth,
            DeviceSigned = deviceSigned,
        };
    }

    private static (IReadOnlyDictionary<string, IReadOnlyList<ParsedIssuerSignedItem>> NameSpaces, byte[] IssuerAuth)
        ReadIssuerSigned(CborReader reader)
    {
        Dictionary<string, IReadOnlyList<ParsedIssuerSignedItem>> nameSpaces = new(StringComparer.Ordinal);
        byte[]? issuerAuth = null;

        reader.ReadStartMap();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            switch (reader.ReadTextString())
            {
                case "nameSpaces":
                    reader.ReadStartMap();
                    while (reader.PeekState() != CborReaderState.EndMap)
                    {
                        var ns = reader.ReadTextString();
                        List<ParsedIssuerSignedItem> items = [];
                        reader.ReadStartArray();
                        while (reader.PeekState() != CborReaderState.EndArray)
                        {
                            items.Add(ReadIssuerSignedItem(reader));
                        }

                        reader.ReadEndArray();
                        nameSpaces[ns] = items;
                    }

                    reader.ReadEndMap();
                    break;
                case "issuerAuth":
                    issuerAuth = reader.ReadEncodedValue().ToArray();
                    break;
                default:
                    reader.SkipValue();
                    break;
            }
        }

        reader.ReadEndMap();

        if (issuerAuth is null)
        {
            throw new MdocProcessingException(MdocErrorCodes.StructureInvalid, "issuerSigned lacks issuerAuth.");
        }

        return (nameSpaces, issuerAuth);
    }

    private static ParsedIssuerSignedItem ReadIssuerSignedItem(CborReader reader)
    {
        // The exact transported encoding of IssuerSignedItemBytes (including the #6.24 tag) is the
        // digest input, so capture it before decoding the content.
        var encoded = reader.ReadEncodedValue().ToArray();

        var tagged = new CborReader(encoded, CborConformanceMode.Lax);
        if (tagged.PeekState() == CborReaderState.Tag)
        {
            tagged.ReadTag();
        }

        var inner = new CborReader(tagged.ReadByteString(), CborConformanceMode.Lax);

        long? digestId = null;
        string? elementIdentifier = null;
        object? elementValue = null;

        inner.ReadStartMap();
        while (inner.PeekState() != CborReaderState.EndMap)
        {
            switch (inner.ReadTextString())
            {
                case "digestID":
                    digestId = inner.ReadInt64();
                    break;
                case "elementIdentifier":
                    elementIdentifier = inner.ReadTextString();
                    break;
                case "elementValue":
                    elementValue = CborValueConverter.Read(inner);
                    break;
                default:
                    inner.SkipValue();
                    break;
            }
        }

        inner.ReadEndMap();

        if (digestId is null || elementIdentifier is null)
        {
            throw new MdocProcessingException(MdocErrorCodes.StructureInvalid, "An IssuerSignedItem lacks digestID or elementIdentifier.");
        }

        return new ParsedIssuerSignedItem
        {
            DigestId = digestId.Value,
            ElementIdentifier = elementIdentifier,
            ElementValue = elementValue,
            EncodedItemBytes = encoded,
        };
    }

    private static ParsedDeviceSigned ReadDeviceSigned(CborReader reader)
    {
        byte[]? nameSpacesBytes = null;
        byte[]? deviceSignature = null;
        byte[]? deviceMac = null;

        reader.ReadStartMap();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            switch (reader.ReadTextString())
            {
                case "nameSpaces":
                    nameSpacesBytes = reader.ReadEncodedValue().ToArray();
                    break;
                case "deviceAuth":
                    reader.ReadStartMap();
                    while (reader.PeekState() != CborReaderState.EndMap)
                    {
                        switch (reader.ReadTextString())
                        {
                            case "deviceSignature":
                                deviceSignature = reader.ReadEncodedValue().ToArray();
                                break;
                            case "deviceMac":
                                deviceMac = reader.ReadEncodedValue().ToArray();
                                break;
                            default:
                                reader.SkipValue();
                                break;
                        }
                    }

                    reader.ReadEndMap();
                    break;
                default:
                    reader.SkipValue();
                    break;
            }
        }

        reader.ReadEndMap();

        if (nameSpacesBytes is null)
        {
            throw new MdocProcessingException(MdocErrorCodes.StructureInvalid, "deviceSigned lacks nameSpaces.");
        }

        return new ParsedDeviceSigned
        {
            EncodedNameSpacesBytes = nameSpacesBytes,
            DeviceSignature = deviceSignature,
            DeviceMac = deviceMac,
        };
    }

    private static MobileSecurityObject ReadMso(CborReader reader)
    {
        string? version = null, digestAlgorithm = null, docType = null;
        Dictionary<string, IReadOnlyDictionary<long, byte[]>> valueDigests = new(StringComparer.Ordinal);
        byte[]? deviceKey = null, status = null;
        DateTimeOffset? signed = null, validFrom = null, validUntil = null;

        reader.ReadStartMap();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            switch (reader.ReadTextString())
            {
                case "version":
                    version = reader.ReadTextString();
                    break;
                case "digestAlgorithm":
                    digestAlgorithm = reader.ReadTextString();
                    break;
                case "docType":
                    docType = reader.ReadTextString();
                    break;
                case "valueDigests":
                    reader.ReadStartMap();
                    while (reader.PeekState() != CborReaderState.EndMap)
                    {
                        var ns = reader.ReadTextString();
                        Dictionary<long, byte[]> digests = [];
                        reader.ReadStartMap();
                        while (reader.PeekState() != CborReaderState.EndMap)
                        {
                            digests[reader.ReadInt64()] = reader.ReadByteString();
                        }

                        reader.ReadEndMap();
                        valueDigests[ns] = digests;
                    }

                    reader.ReadEndMap();
                    break;
                case "deviceKeyInfo":
                    reader.ReadStartMap();
                    while (reader.PeekState() != CborReaderState.EndMap)
                    {
                        if (reader.ReadTextString() == "deviceKey")
                        {
                            deviceKey = reader.ReadEncodedValue().ToArray();
                        }
                        else
                        {
                            reader.SkipValue();
                        }
                    }

                    reader.ReadEndMap();
                    break;
                case "status":
                    // Kept encoded and read only if status is checked (MsoStatus).
                    status = reader.ReadEncodedValue().ToArray();
                    break;
                case "validityInfo":
                    reader.ReadStartMap();
                    while (reader.PeekState() != CborReaderState.EndMap)
                    {
                        switch (reader.ReadTextString())
                        {
                            case "signed":
                                signed = ReadTDate(reader);
                                break;
                            case "validFrom":
                                validFrom = ReadTDate(reader);
                                break;
                            case "validUntil":
                                validUntil = ReadTDate(reader);
                                break;
                            default:
                                reader.SkipValue();
                                break;
                        }
                    }

                    reader.ReadEndMap();
                    break;
                default:
                    reader.SkipValue();
                    break;
            }
        }

        reader.ReadEndMap();

        if (version is null || digestAlgorithm is null || docType is null || deviceKey is null
            || signed is null || validFrom is null || validUntil is null || valueDigests.Count == 0)
        {
            throw new MdocProcessingException(MdocErrorCodes.MsoInvalid, "The MSO lacks a required element.");
        }

        return new MobileSecurityObject
        {
            Version = version,
            DigestAlgorithm = digestAlgorithm,
            ValueDigests = valueDigests,
            DeviceKeyEncoded = deviceKey,
            DocType = docType,
            Signed = signed.Value,
            ValidFrom = validFrom.Value,
            ValidUntil = validUntil.Value,
            StatusEncoded = status,
        };
    }

    // SPEC: ISO 18013-5 — tdate is #6.0(tstr) with an RFC 3339 timestamp.
    private static DateTimeOffset ReadTDate(CborReader reader)
    {
        if (reader.PeekState() == CborReaderState.Tag)
        {
            reader.ReadTag();
        }

        return DateTimeOffset.Parse(reader.ReadTextString(), System.Globalization.CultureInfo.InvariantCulture);
    }
}
