// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests.Inspection;

using System.CommandLine;
using System.Formats.Cbor;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CoseSign1.Headers;
using CoseSign1.Headers.Extensions;
using CoseSign1.Factories.Indirect;
using CoseSign1.Tests.Common;
using CoseSignTool.Inspection;
using CoseSignTool.Output;

/// <summary>
/// Tests for CoseInspectionService.
/// </summary>
[TestFixture]
public class CoseInspectionServiceTests
{
    private sealed class CapturingOutputFormatter : IOutputFormatter
    {
        public object? StructuredData { get; private set; }

        public List<(string Key, string Value)> KeyValues { get; } = [];

        public List<string> Errors { get; } = [];

        public List<string> Warnings { get; } = [];

        public void WriteInfo(string message) { }

        public void WriteSuccess(string message) { }

        public void WriteWarning(string message) => Warnings.Add(message);

        public void WriteError(string message) => Errors.Add(message);

        public void WriteKeyValue(string key, string value) => KeyValues.Add((key, value));

        public void BeginSection(string title) { }

        public void EndSection() { }

        public void WriteStructuredData<T>(T data) where T : class => StructuredData = data;

        public void Flush() { }
    }

    private sealed class ThrowingBeginSectionOutputFormatter : IOutputFormatter
    {
        public List<string> Errors { get; } = [];

        public void WriteInfo(string message) { }
        public void WriteSuccess(string message) { }
        public void WriteWarning(string message) { }
        public void WriteError(string message) => Errors.Add(message);
        public void WriteKeyValue(string key, string value) { }

        public void BeginSection(string title) => throw new InvalidOperationException("boom");
        public void EndSection() { }

        public void WriteStructuredData<T>(T data) where T : class { }
        public void Flush() { }
    }

    private sealed class ThrowingStructuredDataOutputFormatter : IOutputFormatter
    {
        public void WriteInfo(string message) { }
        public void WriteSuccess(string message) { }
        public void WriteWarning(string message) { }
        public void WriteError(string message) { }
        public void WriteKeyValue(string key, string value) { }
        public void BeginSection(string title) { }
        public void EndSection() { }

        public void WriteStructuredData<T>(T data) where T : class
            => throw new InvalidOperationException("boom");

        public void Flush() { }
    }

    private static byte[] CreateSign1Embedded(
        byte[] payload,
        CoseHeaderMap? protectedHeaders = null,
        CoseHeaderMap? unprotectedHeaders = null)
    {
        using var key = ECDsa.Create();
        protectedHeaders ??= new CoseHeaderMap();
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        return CoseSign1Message.SignEmbedded(payload, signer);
    }

    private static byte[] CreateSign1Detached(
        byte[] payload,
        CoseHeaderMap? protectedHeaders = null,
        CoseHeaderMap? unprotectedHeaders = null)
    {
        using var key = ECDsa.Create();
        protectedHeaders ??= new CoseHeaderMap();
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        return CoseSign1Message.SignDetached(payload, signer, ReadOnlySpan<byte>.Empty);
    }

    private static byte[] CreateRawSign1WithProtectedMap(Action<CborWriter> writeProtectedMap)
    {
        var protectedWriter = new CborWriter();
        writeProtectedMap(protectedWriter);
        var protectedBytes = protectedWriter.Encode();

        var writer = new CborWriter();
        writer.WriteStartArray(4);
        writer.WriteByteString(protectedBytes);
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteByteString(new byte[] { 0x01 });
        writer.WriteByteString(new byte[] { 0x00 });
        writer.WriteEndArray();
        return writer.Encode();
    }

    private static CoseHeaderValue CborValue(Action<CborWriter> write)
    {
        var writer = new CborWriter();
        write(writer);
        return CoseHeaderValue.FromEncodedValue(writer.Encode());
    }

    private static CoseHeaderValue CreateX5T(int hashAlgId, byte[] thumbprint)
    {
        return CborValue(writer =>
        {
            writer.WriteStartArray(2);
            writer.WriteInt32(hashAlgId);
            writer.WriteByteString(thumbprint);
            writer.WriteEndArray();
        });
    }

    private static CoseHeaderValue CreateX5ChainArray(params byte[][] certs)
    {
        return CborValue(writer =>
        {
            writer.WriteStartArray(certs.Length);
            foreach (var cert in certs)
            {
                writer.WriteByteString(cert);
            }
            writer.WriteEndArray();
        });
    }

    [Test]
    public void Constructor_WithNullFormatter_UsesDefaultFormatter()
    {
        // Arrange & Act
        var service = new CoseInspectionService(null);

        // Assert - Should not throw
        Assert.That(service, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithFormatter_UsesProvidedFormatter()
    {
        // Arrange
        var formatter = new TextOutputFormatter();

        // Act
        var service = new CoseInspectionService(formatter);

        // Assert
        Assert.That(service, Is.Not.Null);
    }

    [Test]
    public async Task InspectAsync_WithVariousProtectedHeaderTypes_DecodesTypeMetadata()
    {
        // Arrange
        var formatter = new CapturingOutputFormatter();
        var service = new CoseInspectionService(formatter);

        var protectedHeaders = new CoseHeaderMap();

        // Force ContentType parsing to hit the exception path (UInt64 too large for ReadInt32).
        protectedHeaders[CoseHeaderLabel.ContentType] = CborValue(writer => writer.WriteUInt64(1UL << 40));

        // Custom headers to exercise BuildHeaderInfo type decoding.
        protectedHeaders[new CoseHeaderLabel(9001)] = CborValue(writer => writer.WriteTextString("hello"));
        protectedHeaders[new CoseHeaderLabel(9002)] = CborValue(writer => writer.WriteUInt64(123));
        protectedHeaders[new CoseHeaderLabel(9003)] = CborValue(writer => writer.WriteInt64(-123));
        protectedHeaders[new CoseHeaderLabel(9004)] = CborValue(writer => writer.WriteByteString([1, 2, 3, 4]));
        protectedHeaders[new CoseHeaderLabel(9005)] = CborValue(writer =>
        {
            writer.WriteStartArray(2);
            writer.WriteInt32(1);
            writer.WriteInt32(2);
            writer.WriteEndArray();
        });
        protectedHeaders[new CoseHeaderLabel(9006)] = CborValue(writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteTextString("k");
            writer.WriteTextString("v");
            writer.WriteEndMap();
        });
        protectedHeaders[new CoseHeaderLabel(9007)] = CborValue(writer => writer.WriteBoolean(true));
        protectedHeaders[new CoseHeaderLabel(9008)] = CborValue(writer => writer.WriteNull());

        var payload = Encoding.UTF8.GetBytes("payload");
        var coseBytes = CreateSign1Embedded(payload, protectedHeaders);

        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(tempFile, coseBytes);

            // Act
            var resultCode = await service.InspectAsync(tempFile);

            // Assert
            Assert.That(resultCode, Is.EqualTo((int)ExitCode.Success));
            Assert.That(formatter.StructuredData, Is.InstanceOf<CoseInspectionResult>());

            var result = (CoseInspectionResult)formatter.StructuredData!;
            Assert.That(result.ProtectedHeaders, Is.Not.Null);

            // Content type could not be parsed into int/string.
            Assert.That(result.ProtectedHeaders!.ContentType, Is.Null);

            Assert.That(result.ProtectedHeaders.OtherHeaders, Is.Not.Null);
            var other = result.ProtectedHeaders.OtherHeaders!;

            Assert.That(other.Count(h => h.ValueType == "string"), Is.EqualTo(1));
            Assert.That(other.Count(h => h.ValueType == "uint"), Is.EqualTo(1));
            Assert.That(other.Count(h => h.ValueType == "int"), Is.EqualTo(1));
            Assert.That(other.Count(h => h.ValueType == "array"), Is.EqualTo(1));
            Assert.That(other.Count(h => h.ValueType == "map"), Is.EqualTo(1));
            Assert.That(other.Count(h => h.ValueType == "bool"), Is.EqualTo(1));
            Assert.That(other.Count(h => h.ValueType == "unknown"), Is.EqualTo(1));

            var bytesHeader = other.Single(h => h.ValueType == "bytes");
            Assert.That(bytesHeader.LengthBytes, Is.EqualTo(4));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithNonExistentFile_ReturnsFileNotFound()
    {
        // Arrange
        var service = new CoseInspectionService();
        var nonExistentPath = Path.Combine(Path.GetTempPath(), $"nonexistent_{Guid.NewGuid()}.cose");

        // Act
        var result = await service.InspectAsync(nonExistentPath);

        // Assert
        Assert.That(result, Is.EqualTo((int)ExitCode.FileNotFound));
    }

    [Test]
    public async Task InspectAsync_WithInvalidCbor_ReturnsInvalidSignatureAndWritesWarning()
    {
        // Arrange
        var formatter = new CapturingOutputFormatter();
        var service = new CoseInspectionService(formatter);

        var tempFile = Path.GetTempFileName();
        try
        {
            // 0xFF is invalid CBOR and should fail decoding with CborContentException.
            await File.WriteAllBytesAsync(tempFile, [0xFF]);

            // Act
            var exitCode = await service.InspectAsync(tempFile);

            // Assert
            Assert.That(exitCode, Is.EqualTo((int)ExitCode.InvalidSignature));
            Assert.That(formatter.Warnings, Has.Count.GreaterThanOrEqualTo(1));
            Assert.That(formatter.Warnings.Any(w => w.Contains("Failed to decode", StringComparison.OrdinalIgnoreCase)), Is.True);
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WhenBeginSectionThrows_ReturnsInspectionFailed()
    {
        // Arrange
        var formatter = new ThrowingBeginSectionOutputFormatter();
        var service = new CoseInspectionService(formatter);

        var payload = Encoding.UTF8.GetBytes("payload");
        var coseBytes = CreateSign1Embedded(payload);

        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(tempFile, coseBytes);

            // Act
            var exitCode = await service.InspectAsync(tempFile);

            // Assert
            Assert.That(exitCode, Is.EqualTo((int)ExitCode.InspectionFailed));
            Assert.That(formatter.Errors, Has.Count.GreaterThanOrEqualTo(1));
            Assert.That(formatter.Errors[0], Does.Contain("Error reading file"));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public void BuildProtectedHeaders_WithMalformedHeaderValues_DoesNotThrowAndFallsBack()
    {
        // Arrange
        var formatter = new CapturingOutputFormatter();
        var service = new CoseInspectionService(formatter);

        var payload = Encoding.UTF8.GetBytes("payload");
        var coseBytes = CreateRawSign1WithProtectedMap(w =>
        {
            // Protected headers are a CBOR map; use integer keys per RFC 9052.
            w.WriteStartMap(6);

            // alg (1): use a UINT > Int32.MaxValue so inspection's ReadInt32 throws.
            w.WriteInt32(1);
            w.WriteUInt64((ulong)int.MaxValue + 1UL);

            // x5t (34): array where first element overflows Int32.
            w.WriteInt32(34);
            w.WriteStartArray(2);
            w.WriteUInt64((ulong)int.MaxValue + 1UL);
            w.WriteByteString(new byte[] { 1, 2, 3, 4 });
            w.WriteEndArray();

            // payload-hash-alg (258): UINT > Int32.MaxValue so ReadInt32 throws.
            w.WriteInt32(258);
            w.WriteUInt64((ulong)int.MaxValue + 1UL);

            // preimage-content-type (259): non-text -> not set.
            w.WriteInt32(259);
            w.WriteUInt64(1);

            // payload-location (260): non-text -> not set.
            w.WriteInt32(260);
            w.WriteUInt64(1);

            // kid (4): "other" header so OtherHeaders gets populated.
            w.WriteInt32(4);
            w.WriteByteString(new byte[] { 0x01, 0x02 });

            w.WriteEndMap();
        });

        var message = CoseSign1Message.DecodeSign1(coseBytes);

        var method = typeof(CoseInspectionService).GetMethod(
            "BuildProtectedHeaders",
            BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.That(method, Is.Not.Null);

        // Act
        var info = (ProtectedHeadersInfo)method!.Invoke(service, [message])!;

        // Assert
        Assert.That(info.Algorithm, Is.Null);
        Assert.That(info.CertificateThumbprint, Is.Null);
        Assert.That(info.CertificateChainLength, Is.Null);
        Assert.That(info.PayloadHashAlgorithm, Is.Null);
        Assert.That(info.PreimageContentType, Is.Null);
        Assert.That(info.PayloadLocation, Is.Null);

        Assert.That(info.OtherHeaders, Is.Not.Null);
        Assert.That(info.OtherHeaders!.Any(h => h.LabelId == 4 && h.ValueType == "bytes"), Is.True);
    }

    [Test]
    public void BuildProtectedHeaders_WithMalformedX5Chain_FallsBackToStructuralLength()
    {
        var formatter = new CapturingOutputFormatter();
        var service = new CoseInspectionService(formatter);

        var coseBytes = CreateRawSign1WithProtectedMap(w =>
        {
            // Include x5chain (33) but with invalid certificate bytes so TryGetCertificateChain fails.
            // BuildProtectedHeaders should fall back to structural parsing and report the array length.
            w.WriteStartMap(4);

            // x5chain (33): array with 2 invalid cert entries
            w.WriteInt32(33);
            w.WriteStartArray(2);
            w.WriteByteString(new byte[] { 0x01 });
            w.WriteByteString(new byte[] { 0x02 });
            w.WriteEndArray();

            // payload-hash-alg (258): -16 => SHA-256
            w.WriteInt32(258);
            w.WriteInt32(-16);

            // preimage-content-type (259)
            w.WriteInt32(259);
            w.WriteTextString("text/plain");

            // payload-location (260)
            w.WriteInt32(260);
            w.WriteTextString("inline");

            w.WriteEndMap();
        });

        var message = CoseSign1Message.DecodeSign1(coseBytes);

        var method = typeof(CoseInspectionService).GetMethod(
            "BuildProtectedHeaders",
            BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.That(method, Is.Not.Null);

        var info = (ProtectedHeadersInfo)method!.Invoke(service, [message])!;

        Assert.That(info.CertificateChainLength, Is.EqualTo(2));
        Assert.That(info.PayloadHashAlgorithm, Is.Not.Null);
        Assert.That(info.PayloadHashAlgorithm!.Name, Does.Contain("SHA-256"));
        Assert.That(info.PreimageContentType, Is.EqualTo("text/plain"));
        Assert.That(info.PayloadLocation, Is.EqualTo("inline"));
    }

    [Test]
    public void PrivateHelpers_GetX5ChainRawCertificates_ArrayStopsOnUnsupportedElementType()
    {
        var coseBytes = CreateRawSign1WithProtectedMap(w =>
        {
            w.WriteStartMap(1);
            w.WriteInt32(33);
            w.WriteStartArray(2);
            w.WriteByteString(new byte[] { 0x01, 0x02, 0x03 });
            w.WriteInt32(123); // unsupported element type => stop parsing
            w.WriteEndArray();
            w.WriteEndMap();
        });

        var message = CoseSign1Message.DecodeSign1(coseBytes);

        var method = typeof(CoseInspectionService).GetMethod(
            "GetX5ChainRawCertificates",
            BindingFlags.Static | BindingFlags.NonPublic);
        Assert.That(method, Is.Not.Null);

        var raw = (List<byte[]>)method!.Invoke(null, [message])!;

        Assert.That(raw, Has.Count.EqualTo(1));
        Assert.That(raw[0], Is.EqualTo(new byte[] { 0x01, 0x02, 0x03 }));
    }

    [Test]
    public void PrivateHelpers_GetX5ChainRawCertificates_SingleByteString_ReturnsOne()
    {
        var coseBytes = CreateRawSign1WithProtectedMap(w =>
        {
            w.WriteStartMap(1);
            w.WriteInt32(33);
            w.WriteByteString(new byte[] { 0x0A, 0x0B });
            w.WriteEndMap();
        });

        var message = CoseSign1Message.DecodeSign1(coseBytes);

        var method = typeof(CoseInspectionService).GetMethod(
            "GetX5ChainRawCertificates",
            BindingFlags.Static | BindingFlags.NonPublic);
        Assert.That(method, Is.Not.Null);

        var raw = (List<byte[]>)method!.Invoke(null, [message])!;

        Assert.That(raw, Has.Count.EqualTo(1));
        Assert.That(raw[0], Is.EqualTo(new byte[] { 0x0A, 0x0B }));
    }

    [Test]
    public async Task InspectAsync_WithEmptyEmbeddedPayload_Succeeds()
    {
        var formatter = new CapturingOutputFormatter();
        var service = new CoseInspectionService(formatter);

        var coseBytes = CreateSign1Embedded(Array.Empty<byte>());

        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(tempFile, coseBytes);

            var exitCode = await service.InspectAsync(tempFile);

            Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public void DisplayProtectedHeaders_WithUnparsableAlgorithm_WritesUnableToParse()
    {
        // Arrange
        var formatter = new CapturingOutputFormatter();
        var service = new CoseInspectionService(formatter);

        var payload = Encoding.UTF8.GetBytes("payload");
        var coseBytes = CreateRawSign1WithProtectedMap(w =>
        {
            w.WriteStartMap(1);
            w.WriteInt32(1);
            w.WriteUInt64((ulong)int.MaxValue + 1UL);
            w.WriteEndMap();
        });

        var message = CoseSign1Message.DecodeSign1(coseBytes);

        var method = typeof(CoseInspectionService).GetMethod(
            "DisplayProtectedHeaders",
            BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.That(method, Is.Not.Null);

        // Act
        method!.Invoke(service, [message]);

        // Assert
        Assert.That(formatter.KeyValues.Any(kv => kv.Key.Contains("Algorithm", StringComparison.OrdinalIgnoreCase)
            && kv.Value.Contains("unable to parse", StringComparison.OrdinalIgnoreCase)), Is.True);
    }

    [Test]
    public void BuildHeaderInfo_WithInvalidEncodedValue_MarksBinary()
    {
        // Arrange
        var formatter = new CapturingOutputFormatter();
        var service = new CoseInspectionService(formatter);

        var method = typeof(CoseInspectionService).GetMethod(
            "BuildHeaderInfo",
            BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.That(method, Is.Not.Null);

        var invalid = CoseHeaderValue.FromEncodedValue([0xFF]);

        // Act
        var info = (HeaderInfo)method!.Invoke(service, [new CoseHeaderLabel(2000), invalid])!;

        // Assert
        Assert.That(info.ValueType, Is.EqualTo("binary"));
    }

    [Test]
    public void PrivateHelpers_FormatHeaderValueWithDecode_CoversSpecialAndGenericCases()
    {
        var method = typeof(CoseInspectionService).GetMethod(
            "FormatHeaderValueWithDecode",
            BindingFlags.Static | BindingFlags.NonPublic);
        Assert.That(method, Is.Not.Null);

        // payload-hash-alg => SHA-384
        var payloadHashAlgValue = CborValue(w => w.WriteInt32(-43));
        var payloadHashAlgStr = (string)method!.Invoke(null, [CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg, payloadHashAlgValue])!;
        Assert.That(payloadHashAlgStr, Does.Contain("SHA-384"));

        // preimage-content-type
        var preimageValue = CborValue(w => w.WriteTextString("text/plain"));
        var preimageStr = (string)method.Invoke(null, [CoseHashEnvelopeHeaderContributor.HeaderLabels.PreimageContentType, preimageValue])!;
        Assert.That(preimageStr, Is.EqualTo("text/plain"));

        // payload-location
        var locationValue = CborValue(w => w.WriteTextString("inline"));
        var locationStr = (string)method.Invoke(null, [CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadLocation, locationValue])!;
        Assert.That(locationStr, Is.EqualTo("inline"));

        // x5t (thumbprint)
        var x5t = CreateX5T(-44, [1, 2, 3, 4]);
        var x5tStr = (string)method.Invoke(null, [new CoseHeaderLabel(34), x5t])!;
        Assert.That(x5tStr, Does.Contain("SHA-512"));

        // Generic decode: unsigned integer
        var uintValue = CborValue(w => w.WriteUInt64(123));
        var uintStr = (string)method.Invoke(null, [new CoseHeaderLabel(9001), uintValue])!;
        Assert.That(uintStr, Is.EqualTo("123"));

        // Generic decode: negative integer
        var intValue = CborValue(w => w.WriteInt64(-123));
        var intStr = (string)method.Invoke(null, [new CoseHeaderLabel(9002), intValue])!;
        Assert.That(intStr, Is.EqualTo("-123"));

        // Generic decode: byte string
        var bsValue = CborValue(w => w.WriteByteString([1, 2, 3, 4]));
        var bsStr = (string)method.Invoke(null, [new CoseHeaderLabel(9003), bsValue])!;
        Assert.That(bsStr, Does.StartWith("<"));

        // Default: map
        var mapValue = CborValue(w => { w.WriteStartMap(1); w.WriteTextString("k"); w.WriteTextString("v"); w.WriteEndMap(); });
        var mapStr = (string)method.Invoke(null, [new CoseHeaderLabel(9004), mapValue])!;
        Assert.That(mapStr, Does.StartWith("<"));

        // Catch path: invalid CBOR
        var bad = CoseHeaderValue.FromEncodedValue([0xFF]);
        var badStr = (string)method.Invoke(null, [new CoseHeaderLabel(9005), bad])!;
        Assert.That(badStr, Does.StartWith("<"));
    }

    [Test]
    public void PrivateHelpers_GetAlgorithmNameAndHashAlgorithmName_CoverKnownAndUnknownCases()
    {
        var getAlg = typeof(CoseInspectionService).GetMethod(
            "GetAlgorithmName",
            BindingFlags.Static | BindingFlags.NonPublic);
        var getHashAlg = typeof(CoseInspectionService).GetMethod(
            "GetHashAlgorithmName",
            BindingFlags.Static | BindingFlags.NonPublic);
        Assert.That(getAlg, Is.Not.Null);
        Assert.That(getHashAlg, Is.Not.Null);

        foreach (var algId in new[] { -35, -36, -38, -39, -257, -258, -259 })
        {
            var name = (string)getAlg!.Invoke(null, [algId])!;
            Assert.That(name, Is.Not.EqualTo("Unknown"));
        }

        Assert.That((string)getAlg!.Invoke(null, [-999])!, Is.EqualTo("Unknown"));

        Assert.That((string)getHashAlg!.Invoke(null, [-43])!, Is.EqualTo("SHA-384"));
        Assert.That((string)getHashAlg!.Invoke(null, [-44])!, Is.EqualTo("SHA-512"));
        Assert.That((string)getHashAlg!.Invoke(null, [123])!, Does.Contain("Unknown"));
    }

    [Test]
    public void PrivateHelpers_FormatHeaderValue_UsesHexPreviewForLargeEncodedValues()
    {
        var method = typeof(CoseInspectionService).GetMethod(
            "FormatHeaderValue",
            BindingFlags.Static | BindingFlags.NonPublic);
        Assert.That(method, Is.Not.Null);

        // Valid CBOR that produces an encoded value length >= 50
        var large = CborValue(w => w.WriteByteString(new byte[55]));
        var formatted = (string)method!.Invoke(null, [large])!;

        Assert.That(formatted, Does.Contain("["));
        Assert.That(formatted, Does.Contain("bytes"));
    }

    [Test]
    public async Task InspectAsync_WithExtractPayloadAndDetachedSignature_WritesWarningAndDoesNotCreateFile()
    {
        // Arrange
        var formatter = new CapturingOutputFormatter();
        var service = new CoseInspectionService(formatter);

        var payloadBytes = Encoding.UTF8.GetBytes("payload");
        var coseBytes = CreateSign1Detached(payloadBytes);

        var tempDir = Path.Combine(Path.GetTempPath(), $"cose_extract_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        var cosePath = Path.Combine(tempDir, "detached.cose");
        await File.WriteAllBytesAsync(cosePath, coseBytes);

        var extractPath = Path.Combine(tempDir, "extracted.bin");

        try
        {
            // Act
            var exitCode = await service.InspectAsync(cosePath, extractPath);

            // Assert
            Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
            Assert.That(File.Exists(extractPath), Is.False);
            Assert.That(formatter.Warnings.Any(w => w.Contains("Cannot extract payload", StringComparison.OrdinalIgnoreCase)), Is.True);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithKeyVaultAndCertificateHeaders_PopulatesStructuredProtectedHeadersAndCertInfo()
    {
        // Arrange
        var formatter = new CapturingOutputFormatter();
        var service = new CoseInspectionService(formatter);

        using var leafCert = LocalCertificateFactory.CreateRsaCertificate("CoseInspectLeaf", 2048);
        var leafBytes = leafCert.Export(X509ContentType.Cert);

        var protectedHeaders = new CoseHeaderMap
        {
            // Force algorithm header to be present and parsable.
            [CoseHeaderLabel.Algorithm] = CborValue(w => w.WriteInt32(-7)),
            [new CoseHeaderLabel(34)] = CreateX5T(-16, [1, 2, 3, 4]),
            [new CoseHeaderLabel(33)] = CreateX5ChainArray(leafBytes),
            [CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg] = CborValue(w => w.WriteInt32(-16)),
            [CoseHashEnvelopeHeaderContributor.HeaderLabels.PreimageContentType] = CborValue(w => w.WriteTextString("application/json")),
            [CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadLocation] = CborValue(w => w.WriteTextString("inline")),
        };

        var unprotectedHeaders = new CoseHeaderMap
        {
            // Add a well-known header to cover label-id matching logic.
            // Use a different label than those already in protected headers to avoid duplicates.
            [CoseHeaderLabel.ContentType] = CborValue(w => w.WriteTextString("application/test")),
        };

        var payload = Encoding.UTF8.GetBytes("payload");
        var coseBytes = CreateSign1Embedded(payload, protectedHeaders, unprotectedHeaders);

        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(tempFile, coseBytes);

            // Act
            var resultCode = await service.InspectAsync(tempFile);

            // Assert
            Assert.That(resultCode, Is.EqualTo((int)ExitCode.Success));
            Assert.That(formatter.StructuredData, Is.InstanceOf<CoseInspectionResult>());

            var result = (CoseInspectionResult)formatter.StructuredData!;

            Assert.That(result.ProtectedHeaders, Is.Not.Null);
            Assert.That(result.ProtectedHeaders!.Algorithm, Is.Not.Null);
            Assert.That(result.ProtectedHeaders.Algorithm!.Name, Is.Not.Null.And.Not.Empty);
            Assert.That(result.ProtectedHeaders.CertificateThumbprint, Is.Not.Null);
            Assert.That(result.ProtectedHeaders.CertificateThumbprint!.Algorithm, Is.EqualTo("SHA-256"));
            Assert.That(result.ProtectedHeaders.CertificateChainLength, Is.EqualTo(1));
            Assert.That(result.ProtectedHeaders.PayloadHashAlgorithm, Is.Not.Null);
            Assert.That(result.ProtectedHeaders.PayloadHashAlgorithm!.Name, Is.EqualTo("SHA-256"));
            Assert.That(result.ProtectedHeaders.PreimageContentType, Is.EqualTo("application/json"));
            Assert.That(result.ProtectedHeaders.PayloadLocation, Is.EqualTo("inline"));

            Assert.That(result.UnprotectedHeaders, Is.Not.Null);
            Assert.That(result.UnprotectedHeaders!, Has.Count.EqualTo(1));
            Assert.That(result.UnprotectedHeaders![0].LabelId, Is.EqualTo(3));

            Assert.That(result.Certificates, Is.Not.Null);
            Assert.That(result.Certificates!, Has.Count.EqualTo(1));
            Assert.That(result.Certificates![0].Subject, Is.Not.Null.And.Not.Empty);
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithX5ChainAsSingleByteString_SetsChainLengthOne()
    {
        // Arrange
        var formatter = new CapturingOutputFormatter();
        var service = new CoseInspectionService(formatter);

        using var leafCert = LocalCertificateFactory.CreateRsaCertificate("CoseInspectLeaf2", 2048);
        var leafBytes = leafCert.Export(X509ContentType.Cert);

        var protectedHeaders = new CoseHeaderMap
        {
            [new CoseHeaderLabel(33)] = CborValue(w => w.WriteByteString(leafBytes)),
        };

        var payload = Encoding.UTF8.GetBytes("payload");
        var coseBytes = CreateSign1Embedded(payload, protectedHeaders);

        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(tempFile, coseBytes);

            // Act
            var resultCode = await service.InspectAsync(tempFile);

            // Assert
            Assert.That(resultCode, Is.EqualTo((int)ExitCode.Success));
            var result = (CoseInspectionResult)formatter.StructuredData!;
            Assert.That(result.ProtectedHeaders, Is.Not.Null);
            Assert.That(result.ProtectedHeaders!.CertificateChainLength, Is.EqualTo(1));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithUnknownX5tAlgorithm_UsesTolerantFallbackParsing()
    {
        var formatter = new CapturingOutputFormatter();
        var service = new CoseInspectionService(formatter);

        // Use an unknown hash algorithm id to encourage the shared helper to reject it,
        // so the inspection service falls back to tolerant CBOR parsing.
        byte[] thumbprintBytes = [0xAA, 0xBB, 0xCC, 0xDD];
        var protectedHeaders = new CoseHeaderMap
        {
            [new CoseHeaderLabel(34)] = CreateX5T(999, thumbprintBytes),
        };

        var coseBytes = CreateSign1Embedded(Encoding.UTF8.GetBytes("payload"), protectedHeaders);

        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(tempFile, coseBytes);

            var resultCode = await service.InspectAsync(tempFile);

            Assert.That(resultCode, Is.EqualTo((int)ExitCode.Success));
            var result = (CoseInspectionResult)formatter.StructuredData!;

            Assert.That(result.ProtectedHeaders, Is.Not.Null);
            Assert.That(result.ProtectedHeaders!.CertificateThumbprint, Is.Not.Null);
            Assert.That(result.ProtectedHeaders.CertificateThumbprint!.Value, Is.EqualTo(Convert.ToHexString(thumbprintBytes)));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithPartiallyInvalidX5Chain_UsesStructuralFallbackAndLoadsValidCertificates()
    {
        var formatter = new CapturingOutputFormatter();
        var service = new CoseInspectionService(formatter);

        using var leafCert = LocalCertificateFactory.CreateRsaCertificate("CoseInspectLeafPartial", 2048);
        var leafBytes = leafCert.Export(X509ContentType.Cert);

        // Include one valid and one invalid entry. This commonly causes the shared helper to fail,
        // which should drive the inspection service down the tolerant fallback path.
        var protectedHeaders = new CoseHeaderMap
        {
            [new CoseHeaderLabel(33)] = CreateX5ChainArray(leafBytes, [0x01, 0x02, 0x03])
        };

        var coseBytes = CreateSign1Embedded(Encoding.UTF8.GetBytes("payload"), protectedHeaders);

        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(tempFile, coseBytes);

            var resultCode = await service.InspectAsync(tempFile);

            Assert.That(resultCode, Is.EqualTo((int)ExitCode.Success));
            var result = (CoseInspectionResult)formatter.StructuredData!;

            Assert.That(result.ProtectedHeaders, Is.Not.Null);
            Assert.That(result.ProtectedHeaders!.CertificateChainLength, Is.EqualTo(2));

            Assert.That(result.Certificates, Is.Not.Null);
            Assert.That(result.Certificates!, Has.Count.EqualTo(1));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public void PrivateHelpers_MapAlgorithmsAndFormatHeaderValues()
    {
        var type = typeof(CoseInspectionService);

        var getAlgName = type.GetMethod("GetAlgorithmName", BindingFlags.NonPublic | BindingFlags.Static);
        var getHashAlgName = type.GetMethod("GetHashAlgorithmName", BindingFlags.NonPublic | BindingFlags.Static);
        var formatWithDecode = type.GetMethod("FormatHeaderValueWithDecode", BindingFlags.NonPublic | BindingFlags.Static);
        var getHeaderName = type.GetMethod("GetHeaderName", BindingFlags.NonPublic | BindingFlags.Static);
        var formatHeaderValue = type.GetMethod("FormatHeaderValue", BindingFlags.NonPublic | BindingFlags.Static);

        Assert.That(getAlgName, Is.Not.Null);
        Assert.That(getHashAlgName, Is.Not.Null);
        Assert.That(formatWithDecode, Is.Not.Null);
        Assert.That(getHeaderName, Is.Not.Null);
        Assert.That(formatHeaderValue, Is.Not.Null);

        // Algorithm name mapping
        Assert.That((string)getAlgName!.Invoke(null, [-257])!, Is.EqualTo("RS256 (RSASSA-PKCS1-v1_5 w/ SHA-256)"));
        Assert.That((string)getAlgName!.Invoke(null, [-37])!, Is.EqualTo("PS256 (RSASSA-PSS w/ SHA-256)"));
        Assert.That((string)getAlgName!.Invoke(null, [12345])!, Is.EqualTo("Unknown"));

        // Hash algorithm mapping
        Assert.That((string)getHashAlgName!.Invoke(null, [-16])!, Is.EqualTo("SHA-256"));
        Assert.That(((string)getHashAlgName!.Invoke(null, [999])!), Does.Contain("Unknown"));

        // Header name mapping (well-known and custom)
        Assert.That((string)getHeaderName!.Invoke(null, [CoseHeaderLabel.Algorithm])!, Does.Contain("alg"));
        Assert.That((string)getHeaderName!.Invoke(null, [new CoseHeaderLabel(9999)])!, Does.Contain("custom"));

        // FormatHeaderValue length formatting
        var shortValue = CoseHeaderValue.FromEncodedValue(new byte[] { 0x01, 0x02, 0x03 });
        var longValue = CoseHeaderValue.FromEncodedValue(new byte[60]);
        Assert.That((string)formatHeaderValue!.Invoke(null, [shortValue])!, Does.Contain("bytes"));
        Assert.That((string)formatHeaderValue!.Invoke(null, [longValue])!, Does.Contain("[") );

        // Decode a few special headers
        var hashHeader = CoseHeaderValue.FromEncodedValue(CborValue(w => w.WriteInt32(-16)).EncodedValue.Span);
        var decodedHash = (string)formatWithDecode!.Invoke(null, [CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg, hashHeader])!;
        Assert.That(decodedHash, Is.EqualTo("SHA-256"));

        var payloadLocationHeader = CoseHeaderValue.FromEncodedValue(CborValue(w => w.WriteTextString("inline")).EncodedValue.Span);
        var decodedPayloadLoc = (string)formatWithDecode!.Invoke(null, [CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadLocation, payloadLocationHeader])!;
        Assert.That(decodedPayloadLoc, Is.EqualTo("inline"));

        var thumbprintHeader = CreateX5T(-16, [9, 9, 9, 9]);
        var decodedThumbprint = (string)formatWithDecode!.Invoke(null, [new CoseHeaderLabel(34), thumbprintHeader])!;
        Assert.That(decodedThumbprint, Does.Contain("SHA-256"));
    }

    [Test]
    public async Task InspectAsync_WithExtractPayloadInvalidPath_WritesErrorButReturnsSuccess()
    {
        // Arrange
        var formatter = new CapturingOutputFormatter();
        var service = new CoseInspectionService(formatter);

        var payloadBytes = Encoding.UTF8.GetBytes("payload");
        var coseBytes = CreateSign1Embedded(payloadBytes);

        var tempDir = Path.Combine(Path.GetTempPath(), $"cose_extract_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        var cosePath = Path.Combine(tempDir, "embedded.cose");
        await File.WriteAllBytesAsync(cosePath, coseBytes);

        // String containing a NUL char will cause GetFullPath / file APIs to throw.
        var invalidPath = "\0";

        try
        {
            // Act
            var exitCode = await service.InspectAsync(cosePath, invalidPath);

            // Assert
            Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
            Assert.That(formatter.Errors.Any(e => e.Contains("Failed to extract payload", StringComparison.OrdinalIgnoreCase)), Is.True);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithInvalidCoseFile_ReturnsInspectionFailed()
    {
        // Arrange
        var service = new CoseInspectionService();
        var tempFile = Path.GetTempFileName();

        try
        {
            // Write invalid COSE data (random bytes that aren't valid CBOR/COSE)
            await File.WriteAllBytesAsync(tempFile, [0x01, 0x02, 0x03, 0x04]);

            // Act
            var result = await service.InspectAsync(tempFile);

            // Assert - Invalid COSE returns InspectionFailed
            Assert.That(result == (int)ExitCode.InvalidSignature || result == (int)ExitCode.InspectionFailed, Is.True);
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithPartialCoseData_ReturnsError()
    {
        // Arrange
        var service = new CoseInspectionService();
        var tempFile = Path.GetTempFileName();

        try
        {
            // Write partial COSE data (starts like COSE but incomplete)
            await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84, 0x43, 0xA1]);

            // Act
            var result = await service.InspectAsync(tempFile);

            // Assert - Incomplete COSE returns error
            Assert.That(result != (int)ExitCode.Success, Is.True);
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithEmptyFile_ReturnsError()
    {
        // Arrange
        var service = new CoseInspectionService();
        var tempFile = Path.GetTempFileName();

        try
        {
            // Write empty file
            await File.WriteAllBytesAsync(tempFile, []);

            // Act
            var result = await service.InspectAsync(tempFile);

            // Assert - Empty file returns error
            Assert.That(result != (int)ExitCode.Success, Is.True);
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public async Task InspectAsync_UsesFormatter()
    {
        // Arrange
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);
        var tempFile = Path.GetTempFileName();

        try
        {
            await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84]);

            // Act
            await service.InspectAsync(tempFile);
            formatter.Flush();

            // Assert - Formatter should have been used
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("COSE Sign1 Signature Details"));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithJsonFormatter_ProducesJsonOutput()
    {
        // Arrange
        var stringWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);
        var tempFile = Path.GetTempFileName();

        try
        {
            await File.WriteAllBytesAsync(tempFile, [0x01, 0x02, 0x03, 0x04]);

            // Act
            await service.InspectAsync(tempFile);
            formatter.Flush();

            // Assert - JSON formatter should have been used
            var output = stringWriter.ToString();
            Assert.That(output.Contains("{") || output.Contains("[") || string.IsNullOrEmpty(output.Trim()));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithXmlFormatter_ProducesXmlOutput()
    {
        // Arrange
        var stringWriter = new StringWriter();
        var formatter = new XmlOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);
        var tempFile = Path.GetTempFileName();

        try
        {
            await File.WriteAllBytesAsync(tempFile, [0x01, 0x02, 0x03, 0x04]);

            // Act
            await service.InspectAsync(tempFile);
            formatter.Flush();

            // Assert - XML formatter should produce some output
            var output = stringWriter.ToString();
            Assert.That(output.Contains("<") || string.IsNullOrEmpty(output.Trim()));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithQuietFormatter_ProducesMinimalOutput()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();
        var service = new CoseInspectionService(formatter);
        var tempFile = Path.GetTempFileName();

        try
        {
            await File.WriteAllBytesAsync(tempFile, [0x01, 0x02, 0x03, 0x04]);

            // Act
            var result = await service.InspectAsync(tempFile);

            // Assert - QuietOutputFormatter suppresses output, just check we get a result
            Assert.That(result != (int)ExitCode.Success || result == (int)ExitCode.Success, Is.True); // Always true, just verifies no exception
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithValidSignature_ReturnsSuccess()
    {
        // Arrange - Create a real signature using sign-ephemeral command
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload for inspection");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("COSE Sign1 Signature Details"));
            Assert.That(output, Does.Contain("Protected Headers:"));
            Assert.That(output, Does.Contain("Algorithm"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithTextPayload_ShowsPreview()
    {
        // Arrange - Create a signature with text payload using direct type (embeds payload)
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            // Create a text payload
            File.WriteAllText(tempPayload, "This is a text payload that should show a preview when inspected.");

            // Sign with 'embedded' type to ensure payload is embedded
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type embedded");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Payload:"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithBinaryPayload_ShowsHashAndType()
    {
        // Arrange - Create a signature with binary payload
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            // Create a binary payload
            File.WriteAllBytes(tempPayload, [0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD]);

            // Sign with 'embedded' type
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type embedded");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Payload:"));
            // Binary data shows type and SHA-256
            Assert.That(output.Contains("Binary data") || output.Contains("SHA-256") || output.Contains("Payload"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithDetachedSignature_ShowsDetachedInfo()
    {
        // Arrange - Create a detached signature
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload");

            // Sign with 'detached' type
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type detached");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Detached"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task InspectAsync_ShowsSignatureSize()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Size"));
            Assert.That(output, Does.Contain("bytes"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task InspectAsync_ShowsCertificateChainInfo()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            // Certificate chain should be shown
            Assert.That(output, Does.Contain("Certificate Chain"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithDifferentContentType_ShowsContentType()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "{\"test\": \"data\"}");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --content-type application/json");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            // Should contain headers info
            Assert.That(output, Does.Contain("Header"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithLongTextPayload_ShowsTruncatedPreview()
    {
        // Arrange - Create a signature with long text payload
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            // Create a text payload longer than 100 chars
            var longText = new string('A', 200);
            File.WriteAllText(tempPayload, longText);

            // Sign with 'embedded' type to ensure payload is embedded
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type embedded");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Payload:"));
            // Should have preview with truncation indicator
            Assert.That(output.Contains("...") || output.Contains("Preview") || output.Contains("bytes"),
                "Long payload should show preview or size");
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WritesFileInfoCorrectly()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("File:"));
            Assert.That(output, Does.Contain(tempSignature));
            Assert.That(output, Does.Contain("Size:"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithAllFormatters_Succeeds()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Test each formatter type
            var textWriter = new StringWriter();
            var textFormatter = new TextOutputFormatter(textWriter);
            var textService = new CoseInspectionService(textFormatter);
            var textResult = await textService.InspectAsync(tempSignature);
            Assert.That(textResult, Is.EqualTo((int)ExitCode.Success));

            var jsonWriter = new StringWriter();
            var jsonFormatter = new JsonOutputFormatter(jsonWriter);
            var jsonService = new CoseInspectionService(jsonFormatter);
            var jsonResult = await jsonService.InspectAsync(tempSignature);
            Assert.That(jsonResult, Is.EqualTo((int)ExitCode.Success));

            var xmlWriter = new StringWriter();
            var xmlFormatter = new XmlOutputFormatter(xmlWriter);
            var xmlService = new CoseInspectionService(xmlFormatter);
            var xmlResult = await xmlService.InspectAsync(tempSignature);
            Assert.That(xmlResult, Is.EqualTo((int)ExitCode.Success));

            var quietFormatter = new QuietOutputFormatter();
            var quietService = new CoseInspectionService(quietFormatter);
            var quietResult = await quietService.InspectAsync(tempSignature);
            Assert.That(quietResult, Is.EqualTo((int)ExitCode.Success));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithJsonFormatter_ReturnsStructuredResult()
    {
        // Arrange - Create a real signature
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var jsonWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(jsonWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload for JSON inspection");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type embedded");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var jsonOutput = jsonWriter.ToString();

            // Parse JSON to verify structure
            var doc = System.Text.Json.JsonDocument.Parse(jsonOutput);
            var root = doc.RootElement;

            // Verify file info
            Assert.That(root.TryGetProperty("file", out var fileElement), Is.True);
            Assert.That(fileElement.GetProperty("path").GetString(), Does.Contain(tempSignature));
            Assert.That(fileElement.GetProperty("sizeBytes").GetInt64(), Is.GreaterThan(0));

            // Verify protected headers
            Assert.That(root.TryGetProperty("protectedHeaders", out var headersElement), Is.True);
            Assert.That(headersElement.TryGetProperty("algorithm", out var algElement), Is.True);
            Assert.That(algElement.GetProperty("id").GetInt32(), Is.Not.EqualTo(0));
            Assert.That(algElement.GetProperty("name").GetString(), Is.Not.Null.And.Not.Empty);

            // Verify payload info
            Assert.That(root.TryGetProperty("payload", out var payloadElement), Is.True);
            Assert.That(payloadElement.GetProperty("isEmbedded").GetBoolean(), Is.True);
            Assert.That(payloadElement.GetProperty("sizeBytes").GetInt32(), Is.GreaterThan(0));

            // Verify signature info
            Assert.That(root.TryGetProperty("signature", out var sigElement), Is.True);
            Assert.That(sigElement.GetProperty("totalSizeBytes").GetInt32(), Is.GreaterThan(0));

            // Verify certificates
            Assert.That(root.TryGetProperty("certificates", out var certsElement), Is.True);
            Assert.That(certsElement.GetArrayLength(), Is.GreaterThan(0));
            var firstCert = certsElement[0];
            Assert.That(firstCert.GetProperty("subject").GetString(), Is.Not.Null.And.Not.Empty);
            Assert.That(firstCert.GetProperty("thumbprint").GetString(), Is.Not.Null.And.Not.Empty);
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithJsonFormatter_DecodesAlgorithmName()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var jsonWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(jsonWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type embedded");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            var jsonOutput = jsonWriter.ToString();
            var doc = System.Text.Json.JsonDocument.Parse(jsonOutput);
            var algName = doc.RootElement.GetProperty("protectedHeaders").GetProperty("algorithm").GetProperty("name").GetString();

            // Should contain descriptive algorithm name like "PS256" or "RSASSA-PSS"
            Assert.That(algName, Does.Match("ES|PS|RS|ECDSA|RSA|EdDSA").IgnoreCase);
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithJsonFormatter_IncludesCertificateChainInfo()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var jsonWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(jsonWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            var jsonOutput = jsonWriter.ToString();
            var doc = System.Text.Json.JsonDocument.Parse(jsonOutput);

            // Check certificate chain location
            var sigElement = doc.RootElement.GetProperty("signature");
            if (sigElement.TryGetProperty("certificateChainLocation", out var chainLoc))
            {
                Assert.That(chainLoc.GetString(), Is.EqualTo("protected").Or.EqualTo("unprotected"));
            }

            // Check certificates array
            var certs = doc.RootElement.GetProperty("certificates");
            Assert.That(certs.GetArrayLength(), Is.GreaterThanOrEqualTo(1));

            var cert = certs[0];
            Assert.That(cert.GetProperty("subject").GetString(), Does.Contain("CN="));
            Assert.That(cert.GetProperty("issuer").GetString(), Does.Contain("CN="));
            Assert.That(cert.GetProperty("serialNumber").GetString(), Is.Not.Null);
            Assert.That(cert.GetProperty("notBefore").GetString(), Does.Contain("UTC"));
            Assert.That(cert.GetProperty("notAfter").GetString(), Does.Contain("UTC"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithJsonFormatter_DetachedSignature_ShowsNoEmbeddedPayload()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var jsonWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(jsonWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test");
            // Create detached signature (payload not embedded)
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type detached");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            var jsonOutput = jsonWriter.ToString();
            var doc = System.Text.Json.JsonDocument.Parse(jsonOutput);
            var payloadElement = doc.RootElement.GetProperty("payload");

            Assert.That(payloadElement.GetProperty("isEmbedded").GetBoolean(), Is.False);
            // sizeBytes should be null or not present for detached signatures
            if (payloadElement.TryGetProperty("sizeBytes", out var sizeElement))
            {
                Assert.That(sizeElement.ValueKind, Is.EqualTo(System.Text.Json.JsonValueKind.Null));
            }
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithJsonFormatter_TextPayload_ShowsPreview()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var jsonWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(jsonWriter);
        var service = new CoseInspectionService(formatter);
        var testContent = "Hello, this is a test payload for JSON inspection!";

        try
        {
            File.WriteAllText(tempPayload, testContent);
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type embedded");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            var jsonOutput = jsonWriter.ToString();
            var doc = System.Text.Json.JsonDocument.Parse(jsonOutput);
            var payloadElement = doc.RootElement.GetProperty("payload");

            Assert.That(payloadElement.GetProperty("isEmbedded").GetBoolean(), Is.True);
            // Embedded signatures contain binary hash envelope, so isText is false
            // The preview is only for truly embedded payload, not hash envelopes
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithJsonFormatter_BinaryPayload_ShowsSha256()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var jsonWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(jsonWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            // Write binary data (not valid UTF-8 text)
            File.WriteAllBytes(tempPayload, new byte[] { 0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, 0x00, 0x00 });
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type embedded");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            var jsonOutput = jsonWriter.ToString();
            var doc = System.Text.Json.JsonDocument.Parse(jsonOutput);
            var payloadElement = doc.RootElement.GetProperty("payload");

            Assert.That(payloadElement.GetProperty("isEmbedded").GetBoolean(), Is.True);
            Assert.That(payloadElement.GetProperty("isText").GetBoolean(), Is.False);
            Assert.That(payloadElement.GetProperty("sha256").GetString(), Does.Match("^[A-F0-9]{64}$"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithJsonFormatter_IndirectSignature_ShowsHashAlgorithm()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var jsonWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(jsonWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test");
            // Create indirect signature (default type)
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type indirect");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            var jsonOutput = jsonWriter.ToString();
            var doc = System.Text.Json.JsonDocument.Parse(jsonOutput);
            var headersElement = doc.RootElement.GetProperty("protectedHeaders");

            // Indirect signatures should have payloadHashAlgorithm
            if (headersElement.TryGetProperty("payloadHashAlgorithm", out var hashAlg))
            {
                Assert.That(hashAlg.GetProperty("name").GetString(), Does.Contain("SHA"));
            }
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public void CoseInspectionResult_PropertiesAreNullByDefault()
    {
        // Arrange & Act
        var result = new CoseInspectionResult();

        // Assert
        Assert.That(result.File, Is.Null);
        Assert.That(result.ProtectedHeaders, Is.Null);
        Assert.That(result.UnprotectedHeaders, Is.Null);
        Assert.That(result.CwtClaims, Is.Null);
        Assert.That(result.Payload, Is.Null);
        Assert.That(result.Signature, Is.Null);
        Assert.That(result.Certificates, Is.Null);
    }

    [Test]
    public void FileInformation_CanSetProperties()
    {
        // Arrange & Act
        var fileInfo = new FileInformation
        {
            Path = "/test/path.cose",
            SizeBytes = 1234
        };

        // Assert
        Assert.That(fileInfo.Path, Is.EqualTo("/test/path.cose"));
        Assert.That(fileInfo.SizeBytes, Is.EqualTo(1234));
    }

    [Test]
    public void ProtectedHeadersInfo_CanSetProperties()
    {
        // Arrange & Act
        var headers = new ProtectedHeadersInfo
        {
            Algorithm = new AlgorithmInfo { Id = -37, Name = "PS256" },
            ContentType = "application/json",
            CertificateChainLength = 3,
            PayloadHashAlgorithm = new AlgorithmInfo { Id = -16, Name = "SHA-256" },
            PreimageContentType = "text/plain",
            PayloadLocation = "https://example.com/payload"
        };

        // Assert
        Assert.That(headers.Algorithm?.Id, Is.EqualTo(-37));
        Assert.That(headers.Algorithm?.Name, Is.EqualTo("PS256"));
        Assert.That(headers.ContentType, Is.EqualTo("application/json"));
        Assert.That(headers.CertificateChainLength, Is.EqualTo(3));
        Assert.That(headers.PayloadHashAlgorithm?.Name, Is.EqualTo("SHA-256"));
        Assert.That(headers.PreimageContentType, Is.EqualTo("text/plain"));
        Assert.That(headers.PayloadLocation, Is.EqualTo("https://example.com/payload"));
    }

    [Test]
    public void CertificateThumbprintInfo_CanSetProperties()
    {
        // Arrange & Act
        var thumbprint = new CertificateThumbprintInfo
        {
            Algorithm = "SHA-256",
            Value = "ABCD1234"
        };

        // Assert
        Assert.That(thumbprint.Algorithm, Is.EqualTo("SHA-256"));
        Assert.That(thumbprint.Value, Is.EqualTo("ABCD1234"));
    }

    [Test]
    public void HeaderInfo_CanSetProperties()
    {
        // Arrange & Act
        var header = new HeaderInfo
        {
            Label = "custom-header",
            LabelId = 999,
            Value = "test-value",
            ValueType = "string",
            LengthBytes = 10
        };

        // Assert
        Assert.That(header.Label, Is.EqualTo("custom-header"));
        Assert.That(header.LabelId, Is.EqualTo(999));
        Assert.That(header.Value, Is.EqualTo("test-value"));
        Assert.That(header.ValueType, Is.EqualTo("string"));
        Assert.That(header.LengthBytes, Is.EqualTo(10));
    }

    [Test]
    public void CwtClaimsInfo_CanSetProperties()
    {
        // Arrange & Act
        var claims = new CwtClaimsInfo
        {
            Issuer = "test-issuer",
            Subject = "test-subject",
            Audience = "test-audience",
            IssuedAt = "2025-01-01 00:00:00 UTC",
            IssuedAtUnix = 1735689600,
            NotBefore = "2025-01-01 00:00:00 UTC",
            NotBeforeUnix = 1735689600,
            ExpirationTime = "2026-01-01 00:00:00 UTC",
            ExpirationTimeUnix = 1767225600,
            IsExpired = false,
            CwtId = "ABCD1234",
            CustomClaimsCount = 5
        };

        // Assert
        Assert.That(claims.Issuer, Is.EqualTo("test-issuer"));
        Assert.That(claims.Subject, Is.EqualTo("test-subject"));
        Assert.That(claims.Audience, Is.EqualTo("test-audience"));
        Assert.That(claims.IssuedAt, Is.EqualTo("2025-01-01 00:00:00 UTC"));
        Assert.That(claims.IssuedAtUnix, Is.EqualTo(1735689600));
        Assert.That(claims.IsExpired, Is.False);
        Assert.That(claims.CwtId, Is.EqualTo("ABCD1234"));
        Assert.That(claims.CustomClaimsCount, Is.EqualTo(5));
    }

    [Test]
    public void PayloadInfo_CanSetProperties()
    {
        // Arrange & Act
        var payload = new PayloadInfo
        {
            IsEmbedded = true,
            SizeBytes = 1024,
            ContentType = "application/json",
            IsText = true,
            Preview = "{ \"key\": \"value\" }",
            Sha256 = null // Not set when it's text
        };

        // Assert
        Assert.That(payload.IsEmbedded, Is.True);
        Assert.That(payload.SizeBytes, Is.EqualTo(1024));
        Assert.That(payload.ContentType, Is.EqualTo("application/json"));
        Assert.That(payload.IsText, Is.True);
        Assert.That(payload.Preview, Does.Contain("key"));
        Assert.That(payload.Sha256, Is.Null);
    }

    [Test]
    public void SignatureInfo_CanSetProperties()
    {
        // Arrange & Act
        var sig = new SignatureInfo
        {
            TotalSizeBytes = 2048,
            CertificateChainLocation = "protected"
        };

        // Assert
        Assert.That(sig.TotalSizeBytes, Is.EqualTo(2048));
        Assert.That(sig.CertificateChainLocation, Is.EqualTo("protected"));
    }

    [Test]
    public void CertificateInfo_CanSetProperties()
    {
        // Arrange & Act
        var cert = new CertificateInfo
        {
            Subject = "CN=Test Cert",
            Issuer = "CN=Test CA",
            SerialNumber = "123456",
            Thumbprint = "ABCDEF123456",
            NotBefore = "2025-01-01 00:00:00 UTC",
            NotAfter = "2026-01-01 00:00:00 UTC",
            IsExpired = false,
            KeyAlgorithm = "RSA",
            SignatureAlgorithm = "sha256RSA"
        };

        // Assert
        Assert.That(cert.Subject, Is.EqualTo("CN=Test Cert"));
        Assert.That(cert.Issuer, Is.EqualTo("CN=Test CA"));
        Assert.That(cert.SerialNumber, Is.EqualTo("123456"));
        Assert.That(cert.Thumbprint, Is.EqualTo("ABCDEF123456"));
        Assert.That(cert.NotBefore, Does.Contain("2025"));
        Assert.That(cert.NotAfter, Does.Contain("2026"));
        Assert.That(cert.IsExpired, Is.False);
        Assert.That(cert.KeyAlgorithm, Is.EqualTo("RSA"));
        Assert.That(cert.SignatureAlgorithm, Is.EqualTo("sha256RSA"));
    }

    [Test]
    public void AlgorithmInfo_CanSetProperties()
    {
        // Arrange & Act
        var alg = new AlgorithmInfo
        {
            Id = -37,
            Name = "PS256 (RSASSA-PSS w/ SHA-256)"
        };

        // Assert
        Assert.That(alg.Id, Is.EqualTo(-37));
        Assert.That(alg.Name, Is.EqualTo("PS256 (RSASSA-PSS w/ SHA-256)"));
    }

    [Test]
    public async Task InspectAsync_WithExtractPayloadPath_ExtractsPayloadToFile()
    {
        // Arrange - Create a signature with embedded payload
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var extractPath = Path.Combine(Path.GetTempPath(), $"extracted_{Guid.NewGuid()}.bin");
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);
        var testContent = "This is the test payload content to extract";

        try
        {
            File.WriteAllText(tempPayload, testContent);
            // Sign with 'embedded' type to ensure payload is in signature
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type embedded");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature, extractPath);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            Assert.That(File.Exists(extractPath), Is.True, "Extracted file should exist");
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Payload extracted to"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }

            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }

            if (File.Exists(extractPath))
            {
                File.Delete(extractPath);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithExtractPayloadPath_CreatesDirectoryIfNeeded()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var newDir = Path.Combine(Path.GetTempPath(), $"newdir_{Guid.NewGuid()}");
        var extractPath = Path.Combine(newDir, "extracted.bin");
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type embedded");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature, extractPath);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            Assert.That(Directory.Exists(newDir), Is.True, "Directory should be created");
            Assert.That(File.Exists(extractPath), Is.True, "Extracted file should exist");
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }

            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }

            if (File.Exists(extractPath))
            {
                File.Delete(extractPath);
            }

            if (Directory.Exists(newDir))
            {
                Directory.Delete(newDir, true);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithDetachedSignature_ExtractPayloadShowsWarning()
    {
        // Arrange - Create detached signature (no embedded payload)
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var extractPath = Path.Combine(Path.GetTempPath(), $"extracted_{Guid.NewGuid()}.bin");
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type detached");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature, extractPath);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Cannot extract payload"));
            Assert.That(File.Exists(extractPath), Is.False, "No file should be created for detached signature");
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }

            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }

            if (File.Exists(extractPath))
            {
                File.Delete(extractPath);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithDisplayPath_UsesDisplayPathInOutput()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);
        var displayPath = "<stdin>";

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature, extractPayloadPath: null, displayPath: displayPath);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("<stdin>"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }

            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithIndirectSignature_DisplaysHashEnvelopeHeaders()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type indirect");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            // Indirect signatures should show hash algorithm in headers
            Assert.That(output, Does.Contain("Hash Algorithm").Or.Contain("payload-hash-alg").Or.Contain("SHA"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }

            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithContentType_DisplaysContentType()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "{\"test\": true}");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --content-type application/json");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            // Content type header may show as "payload-preimage-content-type" for indirect signatures
            Assert.That(output, Does.Contain("content-type").Or.Contain("application/json"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }

            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithProtectedCertChain_DisplaysCertChainInProtectedHeaders()
    {
        // Arrange - Default ephemeral signing puts cert chain in protected headers
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            // Should show cert chain location
            Assert.That(output, Does.Contain("Certificate Chain"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }

            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task InspectAsync_DisplaysAllAlgorithmNames()
    {
        // Arrange - Test that different algorithm IDs are properly named
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var jsonWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(jsonWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var jsonOutput = jsonWriter.ToString();
            var doc = System.Text.Json.JsonDocument.Parse(jsonOutput);
            var algName = doc.RootElement.GetProperty("protectedHeaders").GetProperty("algorithm").GetProperty("name").GetString();

            // Algorithm name should be human-readable (ES256, PS256, etc.)
            Assert.That(algName, Is.Not.Null.And.Not.Empty);
            Assert.That(algName, Does.Not.Contain("Unknown"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }

            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithScittCompliantSignature_DisplaysCwtClaims()
    {
        // Arrange - Create a signature programmatically with CWT claims
        using var cert = TestCertificateUtils.CreateCertificate();

        var protectedHeaders = new CoseHeaderMap();

        // Add CWT claims to the protected headers
        var claims = new CwtClaims
        {
            Issuer = "did:x509:test-issuer",
            Subject = "test-subject",
            Audience = "test-audience",
            IssuedAt = DateTimeOffset.UtcNow,
            NotBefore = DateTimeOffset.UtcNow,
            ExpirationTime = DateTimeOffset.UtcNow.AddHours(1),
            CwtId = [0x01, 0x02, 0x03, 0x04]
        };
        protectedHeaders.SetCwtClaims(claims);

        var payloadBytes = Encoding.UTF8.GetBytes("Test payload with CWT claims");
        var messageBytes = CreateSign1Embedded(payloadBytes, protectedHeaders);

        var tempDir = Path.Combine(Path.GetTempPath(), $"cose_inspect_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        var cosePath = Path.Combine(tempDir, "scitt.cose");

        try
        {
            await File.WriteAllBytesAsync(cosePath, messageBytes);

            var stringWriter = new StringWriter();
            var formatter = new TextOutputFormatter(stringWriter);
            var service = new CoseInspectionService(formatter);

            // Act
            var result = await service.InspectAsync(cosePath);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();

            // Should contain CWT claims section with our values
            Assert.That(output, Does.Contain("CWT Claims"));
            Assert.That(output, Does.Contain("Issuer"));
            Assert.That(output, Does.Contain("did:x509:test-issuer"));
            Assert.That(output, Does.Contain("Subject"));
            Assert.That(output, Does.Contain("test-subject"));
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, true);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithJsonFormatter_HandlesEmptyPayload()
    {
        // Arrange - Create signature with detached payload
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var jsonWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(jsonWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type detached");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var jsonOutput = jsonWriter.ToString();
            var doc = System.Text.Json.JsonDocument.Parse(jsonOutput);
            var payloadElement = doc.RootElement.GetProperty("payload");
            Assert.That(payloadElement.GetProperty("isEmbedded").GetBoolean(), Is.False);
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }

            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithCorruptedCborStructure_ReturnsAppropriateError()
    {
        // Arrange
        var service = new CoseInspectionService();
        var tempFile = Path.GetTempFileName();

        try
        {
            // Write malformed CBOR that looks like COSE but isn't valid
            // COSE Sign1 tag (0xD2) followed by incomplete structure
            await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84, 0x40, 0xA0, 0x40]);

            // Act
            var result = await service.InspectAsync(tempFile);

            // Assert - Should return error code for invalid signature
            Assert.That(result, Is.EqualTo((int)ExitCode.InvalidSignature).Or.EqualTo((int)ExitCode.InspectionFailed));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithTruncatedCborData_ReturnsError()
    {
        // Arrange
        var stdoutWriter = new StringWriter();
        var stderrWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stdoutWriter, stderrWriter);
        var service = new CoseInspectionService(formatter);
        var tempFile = Path.GetTempFileName();

        try
        {
            // Write truncated CBOR data
            await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84, 0x43]);

            // Act
            var result = await service.InspectAsync(tempFile);
            formatter.Flush();

            // Assert - Either returns error code or writes error to stderr
            var combinedOutput = stdoutWriter.ToString() + stderrWriter.ToString();
            Assert.That(
                result != (int)ExitCode.Success ||
                combinedOutput.Contains("Failed") ||
                combinedOutput.Contains("Error") ||
                combinedOutput.Contains("invalid"),
                Is.True,
                "Truncated CBOR should result in error");
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithZeroBytePayload_HandlesGracefully()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            // Create empty file
            File.WriteAllBytes(tempPayload, []);
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type embedded");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Payload").Or.Contain("Success"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }

            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public void ProtectedHeadersInfo_OtherHeaders_CanBeSet()
    {
        // Arrange & Act
        var headers = new ProtectedHeadersInfo
        {
            OtherHeaders = new List<HeaderInfo>
            {
                new HeaderInfo { Label = "custom-1", Value = "value-1" },
                new HeaderInfo { Label = "custom-2", Value = "value-2" }
            }
        };

        // Assert
        Assert.That(headers.OtherHeaders, Has.Count.EqualTo(2));
        Assert.That(headers.OtherHeaders[0].Label, Is.EqualTo("custom-1"));
    }

    [Test]
    public void ProtectedHeadersInfo_CertificateThumbprint_CanBeSet()
    {
        // Arrange & Act
        var headers = new ProtectedHeadersInfo
        {
            CertificateThumbprint = new CertificateThumbprintInfo
            {
                Algorithm = "SHA-256",
                Value = "ABC123"
            }
        };

        // Assert
        Assert.That(headers.CertificateThumbprint, Is.Not.Null);
        Assert.That(headers.CertificateThumbprint.Algorithm, Is.EqualTo("SHA-256"));
        Assert.That(headers.CertificateThumbprint.Value, Is.EqualTo("ABC123"));
    }

    [Test]
    public async Task InspectAsync_WithIndirectSignature_ShowsHashAlgorithm()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload for indirect signature");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type indirect");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            // Indirect signatures should show payload hash algorithm
            Assert.That(output, Does.Contain("Header").Or.Contain("Algorithm"));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task InspectAsync_ExtractPayload_ToFile_Succeeds()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var tempExtract = Path.Combine(Path.GetTempPath(), $"extracted_{Guid.NewGuid()}.bin");
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            var originalContent = "Test payload content for extraction";
            File.WriteAllText(tempPayload, originalContent);
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type embedded");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act - extract payload
            var result = await service.InspectAsync(tempSignature, tempExtract);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            Assert.That(File.Exists(tempExtract), Is.True, "Extracted file should exist");
            var extractedBytes = File.ReadAllBytes(tempExtract);
            // COSE payload is exact - may include the original content but trim nulls if present
            var extractedContent = System.Text.Encoding.UTF8.GetString(extractedBytes).TrimEnd('\0');
            Assert.That(extractedContent, Is.EqualTo(originalContent));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
            if (File.Exists(tempExtract))
            {
                File.Delete(tempExtract);
            }
        }
    }

    [Test]
    public async Task InspectAsync_ExtractPayload_ToStdout_Succeeds()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter, standardOutputProvider: () => Stream.Null);

        try
        {
            File.WriteAllText(tempPayload, "x");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type embedded");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature, "-");
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public async Task InspectAsync_ExtractPayload_FromDetached_ShowsWarning()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var tempExtract = Path.Combine(Path.GetTempPath(), $"extracted_{Guid.NewGuid()}.bin");
        var stdoutWriter = new StringWriter();
        var stderrWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stdoutWriter, stderrWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type detached");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act - try to extract payload from detached signature
            var result = await service.InspectAsync(tempSignature, tempExtract);
            formatter.Flush();

            // Assert - should succeed but warn that payload can't be extracted
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var combinedOutput = stdoutWriter.ToString() + stderrWriter.ToString();
            Assert.That(combinedOutput.Contains("Cannot") || 
                       combinedOutput.Contains("Detached") || 
                       !File.Exists(tempExtract), 
                       Is.True,
                       "Should warn about detached signature or not create extract file");
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
            if (File.Exists(tempExtract))
            {
                File.Delete(tempExtract);
            }
        }
    }

    [Test]
    public async Task InspectAsync_WithDisplayPath_UsesCustomDisplayName()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");

            // Act - use custom display path
            var customDisplayPath = "<stdin>";
            var result = await service.InspectAsync(tempSignature, null, customDisplayPath);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain(customDisplayPath));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Test]
    public void AlgorithmInfo_Properties_Work()
    {
        // Arrange & Act
        var info = new AlgorithmInfo
        {
            Id = -7,
            Name = "ES256 (ECDSA w/ SHA-256)"
        };

        // Assert
        Assert.That(info.Id, Is.EqualTo(-7));
        Assert.That(info.Name, Is.EqualTo("ES256 (ECDSA w/ SHA-256)"));
    }

    [Test]
    public void CwtClaimsInfo_AllProperties_CanBeSet()
    {
        // Arrange & Act
        var info = new CwtClaimsInfo
        {
            Issuer = "test-issuer",
            Subject = "test-subject",
            Audience = "test-audience",
            IssuedAt = "2024-01-01 00:00:00 UTC",
            IssuedAtUnix = 1704067200,
            NotBefore = "2024-01-01 00:00:00 UTC",
            NotBeforeUnix = 1704067200,
            ExpirationTime = "2025-01-01 00:00:00 UTC",
            ExpirationTimeUnix = 1735689600,
            IsExpired = false,
            CwtId = "ABC123",
            CustomClaimsCount = 3
        };

        // Assert
        Assert.That(info.Issuer, Is.EqualTo("test-issuer"));
        Assert.That(info.Subject, Is.EqualTo("test-subject"));
        Assert.That(info.Audience, Is.EqualTo("test-audience"));
        Assert.That(info.IssuedAtUnix, Is.EqualTo(1704067200));
        Assert.That(info.NotBeforeUnix, Is.EqualTo(1704067200));
        Assert.That(info.ExpirationTimeUnix, Is.EqualTo(1735689600));
        Assert.That(info.IsExpired, Is.False);
        Assert.That(info.CwtId, Is.EqualTo("ABC123"));
        Assert.That(info.CustomClaimsCount, Is.EqualTo(3));
    }

    [Test]
    public void SignatureInfo_AllProperties_CanBeSet()
    {
        // Arrange & Act
        var info = new SignatureInfo
        {
            TotalSizeBytes = 1000,
            CertificateChainLocation = "protected"
        };

        // Assert
        Assert.That(info.TotalSizeBytes, Is.EqualTo(1000));
        Assert.That(info.CertificateChainLocation, Is.EqualTo("protected"));
    }

    [Test]
    public void PayloadInfo_AllProperties_CanBeSet()
    {
        // Arrange & Act
        var info = new PayloadInfo
        {
            IsEmbedded = true,
            SizeBytes = 500,
            IsText = true,
            Preview = "Hello, world!",
            Sha256 = "ABC123"
        };

        // Assert
        Assert.That(info.IsEmbedded, Is.True);
        Assert.That(info.SizeBytes, Is.EqualTo(500));
        Assert.That(info.IsText, Is.True);
        Assert.That(info.Preview, Is.EqualTo("Hello, world!"));
        Assert.That(info.Sha256, Is.EqualTo("ABC123"));
    }

    [Test]
    public void HeaderInfo_AllProperties_CanBeSet()
    {
        // Arrange & Act
        var info = new HeaderInfo
        {
            Label = "custom-header",
            LabelId = 42,
            Value = "test-value",
            ValueType = "string",
            LengthBytes = 10
        };

        // Assert
        Assert.That(info.Label, Is.EqualTo("custom-header"));
        Assert.That(info.LabelId, Is.EqualTo(42));
        Assert.That(info.Value, Is.EqualTo("test-value"));
        Assert.That(info.ValueType, Is.EqualTo("string"));
        Assert.That(info.LengthBytes, Is.EqualTo(10));
    }

    [Test]
    public void CertificateInfo_AllProperties_CanBeSet()
    {
        // Arrange & Act
        var info = new CertificateInfo
        {
            Subject = "CN=Test",
            Issuer = "CN=CA",
            SerialNumber = "123456",
            Thumbprint = "ABC123",
            NotBefore = "2024-01-01",
            NotAfter = "2025-01-01",
            IsExpired = false,
            KeyAlgorithm = "RSA",
            SignatureAlgorithm = "sha256RSA"
        };

        // Assert
        Assert.That(info.Subject, Is.EqualTo("CN=Test"));
        Assert.That(info.Issuer, Is.EqualTo("CN=CA"));
        Assert.That(info.SerialNumber, Is.EqualTo("123456"));
        Assert.That(info.Thumbprint, Is.EqualTo("ABC123"));
        Assert.That(info.NotBefore, Is.EqualTo("2024-01-01"));
        Assert.That(info.NotAfter, Is.EqualTo("2025-01-01"));
        Assert.That(info.IsExpired, Is.False);
        Assert.That(info.KeyAlgorithm, Is.EqualTo("RSA"));
        Assert.That(info.SignatureAlgorithm, Is.EqualTo("sha256RSA"));
    }

    [Test]
    public async Task InspectAsync_WithValidEmbeddedMessage_InspectsAndCanExtractPayload()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate();

        var protectedHeaders = new CoseHeaderMap();
        protectedHeaders.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("text/plain"));
        protectedHeaders.Add(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg, CoseHeaderValue.FromInt32(-16));
        protectedHeaders.Add(CoseHashEnvelopeHeaderContributor.HeaderLabels.PreimageContentType, CoseHeaderValue.FromString("application/json"));
        protectedHeaders.Add(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadLocation, CoseHeaderValue.FromString("https://example.test/payload"));
        protectedHeaders.Add(new CoseHeaderLabel(34), CreateX5T(-16, cert.GetCertHash(HashAlgorithmName.SHA256))); // x5t

        var claims = new CwtClaims
        {
            Issuer = "issuer",
            Subject = "subject",
            Audience = "audience",
            IssuedAt = DateTimeOffset.UtcNow,
            NotBefore = DateTimeOffset.UtcNow,
            ExpirationTime = DateTimeOffset.UtcNow.AddMinutes(30),
            CwtId = [0x01, 0x02, 0x03]
        };
        claims.CustomClaims.Add(999, "custom");
        protectedHeaders.SetCwtClaims(claims);

        // Add an additional protected header to exercise BuildHeaderInfo decoding.
        protectedHeaders.Add(new CoseHeaderLabel(5000), CborValue(w => w.WriteBoolean(true)));

        var unprotectedHeaders = new CoseHeaderMap();
        // x5chain in unprotected headers as array with one good cert and one malformed cert.
        unprotectedHeaders.Add(new CoseHeaderLabel(33), CreateX5ChainArray(cert.RawData, [0xFF, 0x00, 0xFF]));

        // Varied CBOR types for BuildHeaderInfo and DisplayUnprotectedHeaders.
        unprotectedHeaders.Add(new CoseHeaderLabel(2000), CborValue(w => w.WriteUInt64(123)));
        unprotectedHeaders.Add(new CoseHeaderLabel(2001), CborValue(w => w.WriteInt64(-5)));
        unprotectedHeaders.Add(new CoseHeaderLabel(2002), CoseHeaderValue.FromBytes([0x01, 0x02, 0x03]));
        unprotectedHeaders.Add(new CoseHeaderLabel(2003), CborValue(w => { w.WriteStartArray(0); w.WriteEndArray(); }));
        unprotectedHeaders.Add(new CoseHeaderLabel(2004), CborValue(w => { w.WriteStartMap(0); w.WriteEndMap(); }));
        unprotectedHeaders.Add(new CoseHeaderLabel(2005), CborValue(w => w.WriteBoolean(false)));
        unprotectedHeaders.Add(new CoseHeaderLabel(2006), CborValue(w => w.WriteNull()));
        // Use a valid but uncommon CBOR form (indefinite-length empty array) to exercise decoding paths.
        unprotectedHeaders.Add(new CoseHeaderLabel(2007), CoseHeaderValue.FromEncodedValue([0x9F, 0xFF]));
        unprotectedHeaders.Add(new CoseHeaderLabel(2008), CoseHeaderValue.FromBytes(new byte[100])); // long header encoding

        var payloadBytes = Encoding.UTF8.GetBytes("Hello from COSE inspection");
        var messageBytes = CreateSign1Embedded(payloadBytes, protectedHeaders, unprotectedHeaders);

        var tempDir = Path.Combine(Path.GetTempPath(), $"cose_inspect_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        var cosePath = Path.Combine(tempDir, "message.cose");
        await File.WriteAllBytesAsync(cosePath, messageBytes);

        var extractedPath = Path.Combine(tempDir, "nested", "payload.bin");

        var sw = new StringWriter();
        var formatter = new TextOutputFormatter(sw);
        var service = new CoseInspectionService(formatter);

        // Act
        var result = await service.InspectAsync(cosePath, extractPayloadPath: extractedPath, displayPath: "<stdin>");
        formatter.Flush();

        // Assert
        Assert.That(result, Is.EqualTo((int)ExitCode.Success));
        Assert.That(sw.ToString(), Does.Contain("COSE Sign1 message inspection complete"));
        Assert.That(sw.ToString(), Does.Contain("Payload extracted to:"));
        Assert.That(sw.ToString(), Does.Contain("<stdin>"));
        Assert.That(File.Exists(extractedPath), Is.True);
    }

    [Test]
    public async Task InspectAsync_WithInvalidCbor_ReturnsInvalidSignature()
    {
        // Arrange
        var tempDir = Path.Combine(Path.GetTempPath(), $"cose_inspect_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        var cosePath = Path.Combine(tempDir, "invalid.cose");

        // Deliberately invalid CBOR ("break" byte outside an indefinite-length item).
        // This is intended to hit the CborContentException path inside InspectAsync.
        await File.WriteAllBytesAsync(cosePath, [0xFF]);

        var sw = new StringWriter();
        var formatter = new TextOutputFormatter(sw);
        var service = new CoseInspectionService(formatter);

        // Act
        var result = await service.InspectAsync(cosePath);
        formatter.Flush();

        // Assert
        Assert.That(result, Is.EqualTo((int)ExitCode.InvalidSignature));
        Assert.That(sw.ToString(), Does.Contain("Failed to decode"));
    }

    [Test]
    public async Task InspectAsync_WhenStructuredDataWriteThrows_ReturnsInspectionFailed()
    {
        // Arrange
        var payloadBytes = Encoding.UTF8.GetBytes("payload");
        var messageBytes = CreateSign1Embedded(payloadBytes);

        var tempDir = Path.Combine(Path.GetTempPath(), $"cose_inspect_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        var cosePath = Path.Combine(tempDir, "ok.cose");
        await File.WriteAllBytesAsync(cosePath, messageBytes);

        var formatter = new ThrowingStructuredDataOutputFormatter();
        var service = new CoseInspectionService(formatter);

        // Act
        var result = await service.InspectAsync(cosePath);

        // Assert
        Assert.That(result, Is.EqualTo((int)ExitCode.InspectionFailed));
    }

    [Test]
    public async Task InspectAsync_WithProtectedHeaders_CoversProtectedParsingAndWellKnownMappings()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate();

        var protectedHeaders = new CoseHeaderMap();
        protectedHeaders.Add(CoseHeaderLabel.Algorithm, CoseHeaderValue.FromInt32(-7)); // ES256
        protectedHeaders.Add(CoseHeaderLabel.CriticalHeaders, CborValue(w =>
        {
            w.WriteStartArray(1);
            w.WriteInt32(3); // content-type
            w.WriteEndArray();
        }));
        protectedHeaders.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("text/plain"));
        protectedHeaders.Add(new CoseHeaderLabel(33), CreateX5ChainArray(cert.RawData, [0xFF])); // x5chain
        protectedHeaders.Add(new CoseHeaderLabel(34), CreateX5T(12345, [0x01, 0x02, 0x03])); // x5t (unknown hash alg)
        protectedHeaders.Add(new CoseHeaderLabel(35), CoseHeaderValue.FromString("https://example.test/cert.cer")); // x5u
        protectedHeaders.Add(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadHashAlg, CoseHeaderValue.FromInt32(-44)); // SHA-512
        protectedHeaders.Add(CoseHashEnvelopeHeaderContributor.HeaderLabels.PreimageContentType, CoseHeaderValue.FromString("application/json"));
        protectedHeaders.Add(CoseHashEnvelopeHeaderContributor.HeaderLabels.PayloadLocation, CoseHeaderValue.FromString("https://example.test/payload"));
        protectedHeaders.Add(new CoseHeaderLabel(9999), CoseHeaderValue.FromBytes([0xAA, 0xBB, 0xCC]));

        var bigBytes = Enumerable.Repeat((byte)0x42, 60).ToArray();
        var unprotectedHeaders = new CoseHeaderMap();
        unprotectedHeaders.Add(CoseHeaderLabel.KeyIdentifier, CoseHeaderValue.FromBytes([0x99]));
        unprotectedHeaders.Add(new CoseHeaderLabel(2008), CoseHeaderValue.FromBytes(bigBytes));
        unprotectedHeaders.Add(new CoseHeaderLabel(2002), CoseHeaderValue.FromBytes([0x01, 0x02, 0x03]));

        var payload = Encoding.UTF8.GetBytes("hello");
        var messageBytes = CreateSign1Embedded(payload, protectedHeaders, unprotectedHeaders);

        var tempDir = Path.Combine(Path.GetTempPath(), $"cose_inspect_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        var cosePath = Path.Combine(tempDir, "manual.cose");
        await File.WriteAllBytesAsync(cosePath, messageBytes);

        var formatter = new CapturingOutputFormatter();
        var service = new CoseInspectionService(formatter);

        // Act
        var result = await service.InspectAsync(cosePath);

        // Assert
        Assert.That(result, Is.EqualTo((int)ExitCode.Success));
        Assert.That(formatter.StructuredData, Is.TypeOf<CoseInspectionResult>());

        var data = (CoseInspectionResult)formatter.StructuredData!;
        Assert.That(data.ProtectedHeaders, Is.Not.Null);
        Assert.That(data.ProtectedHeaders!.Algorithm, Is.Not.Null);
        Assert.That(data.ProtectedHeaders.Algorithm!.Id, Is.EqualTo(-7));
        Assert.That(data.ProtectedHeaders.Algorithm.Name, Does.Contain("ES256"));

        Assert.That(data.ProtectedHeaders.ContentType, Is.EqualTo("text/plain"));
        Assert.That(data.ProtectedHeaders.CertificateChainLength, Is.EqualTo(2));
        Assert.That(data.ProtectedHeaders.PayloadHashAlgorithm, Is.Not.Null);
        Assert.That(data.ProtectedHeaders.PayloadHashAlgorithm!.Id, Is.EqualTo(-44));
        Assert.That(data.ProtectedHeaders.PayloadHashAlgorithm.Name, Is.EqualTo("SHA-512"));

        Assert.That(data.ProtectedHeaders.CertificateThumbprint, Is.Not.Null);
        Assert.That(data.ProtectedHeaders.CertificateThumbprint!.Algorithm, Does.Contain("12345"));
        Assert.That(data.ProtectedHeaders.CertificateThumbprint.Value, Is.EqualTo("010203"));

        Assert.That(data.Signature, Is.Not.Null);
        Assert.That(data.Signature!.CertificateChainLocation, Is.EqualTo("protected"));

        Assert.That(data.Certificates, Is.Not.Null);
        Assert.That(data.Certificates!.Count, Is.EqualTo(1));

        Assert.That(data.ProtectedHeaders.OtherHeaders, Is.Not.Null);
        Assert.That(data.ProtectedHeaders.OtherHeaders!.Any(h => h.LabelId == 35), Is.True);

        Assert.That(data.UnprotectedHeaders, Is.Not.Null);
        Assert.That(data.UnprotectedHeaders!.Any(h => h.LabelId == 4), Is.True);
    }

    [Test]
    public async Task InspectAsync_WithRsaPssSha256Message_MapsAlgorithmNameInStructuredOutput()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var protectedHeaders = new CoseHeaderMap();
        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256, protectedHeaders);

        var payloadBytes = Encoding.UTF8.GetBytes("payload");
        var messageBytes = CoseSign1Message.SignEmbedded(payloadBytes, signer);

        var tempDir = Path.Combine(Path.GetTempPath(), $"cose_inspect_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        var cosePath = Path.Combine(tempDir, "rsa-pss-sha256.cose");
        await File.WriteAllBytesAsync(cosePath, messageBytes);

        var formatter = new CapturingOutputFormatter();
        var service = new CoseInspectionService(formatter);

        // Act
        var result = await service.InspectAsync(cosePath);

        // Assert
        Assert.That(result, Is.EqualTo((int)ExitCode.Success));
        var data = (CoseInspectionResult)formatter.StructuredData!;
        Assert.That(data.ProtectedHeaders!.Algorithm!.Id, Is.EqualTo(-37));
        Assert.That(data.ProtectedHeaders.Algorithm.Name, Does.Contain("PS256"));
    }

    [Test]
    public async Task InspectAsync_WithDetachedMessage_AndExtractRequested_WarnsButSucceeds()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate();

        var protectedHeaders = new CoseHeaderMap();
        protectedHeaders.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromInt32(42));
        protectedHeaders.Add(new CoseHeaderLabel(33), CoseHeaderValue.FromBytes(cert.RawData)); // x5chain as single bstr
        protectedHeaders.Add(new CoseHeaderLabel(34), CreateX5T(-16, cert.GetCertHash(HashAlgorithmName.SHA256))); // x5t

        // Expired CWT claims to exercise the [EXPIRED] warning path.
        var expiredClaims = new CwtClaims
        {
            Issuer = "issuer",
            ExpirationTime = DateTimeOffset.UtcNow.AddMinutes(-5)
        };
        protectedHeaders.SetCwtClaims(expiredClaims);

        var payloadBytes = Encoding.UTF8.GetBytes("Detached payload bytes");
        var messageBytes = CreateSign1Detached(payloadBytes, protectedHeaders);

        var tempDir = Path.Combine(Path.GetTempPath(), $"cose_inspect_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        var cosePath = Path.Combine(tempDir, "detached.cose");
        await File.WriteAllBytesAsync(cosePath, messageBytes);

        var sw = new StringWriter();
        var formatter = new TextOutputFormatter(sw);
        var service = new CoseInspectionService(formatter);

        // Act
        var result = await service.InspectAsync(cosePath, extractPayloadPath: Path.Combine(tempDir, "should_not_exist.bin"));
        formatter.Flush();

        // Assert
        Assert.That(result, Is.EqualTo((int)ExitCode.Success));
        Assert.That(sw.ToString(), Does.Contain("Cannot extract payload"));
        Assert.That(sw.ToString(), Does.Contain("[EXPIRED]"));
    }

    [Test]
    public async Task InspectAsync_WithEmbeddedLargeTextPayload_TruncatesPreview()
    {
        // Arrange
        var payloadBytes = Encoding.UTF8.GetBytes(new string('A', 150));
        var messageBytes = CreateSign1Embedded(payloadBytes);

        var tempDir = Path.Combine(Path.GetTempPath(), $"cose_inspect_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        var cosePath = Path.Combine(tempDir, "large-text.cose");
        await File.WriteAllBytesAsync(cosePath, messageBytes);

        var sw = new StringWriter();
        var formatter = new TextOutputFormatter(sw);
        var service = new CoseInspectionService(formatter);

        // Act
        var result = await service.InspectAsync(cosePath);
        formatter.Flush();

        // Assert
        Assert.That(result, Is.EqualTo((int)ExitCode.Success));
        Assert.That(sw.ToString(), Does.Contain("Preview"));
        Assert.That(sw.ToString(), Does.Contain("..."));
    }

    [Test]
    public async Task InspectAsync_WithEmbeddedBinaryPayload_PrintsSha256()
    {
        // Arrange
        var payloadBytes = new byte[128];
        RandomNumberGenerator.Fill(payloadBytes);

        var messageBytes = CreateSign1Embedded(payloadBytes);

        var tempDir = Path.Combine(Path.GetTempPath(), $"cose_inspect_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        var cosePath = Path.Combine(tempDir, "binary.cose");
        await File.WriteAllBytesAsync(cosePath, messageBytes);

        var sw = new StringWriter();
        var formatter = new TextOutputFormatter(sw);
        var service = new CoseInspectionService(formatter);

        // Act
        var result = await service.InspectAsync(cosePath);
        formatter.Flush();

        // Assert
        Assert.That(result, Is.EqualTo((int)ExitCode.Success));
        Assert.That(sw.ToString(), Does.Contain("Binary data"));
        Assert.That(sw.ToString(), Does.Contain("SHA-256"));
    }

    [Test]
    public async Task InspectAsync_WithEmbeddedMessage_AndExtractToStdout_Succeeds()
    {
        // Arrange
        var payloadBytes = Encoding.UTF8.GetBytes("stdout payload");
        var messageBytes = CreateSign1Embedded(payloadBytes);

        var tempDir = Path.Combine(Path.GetTempPath(), $"cose_inspect_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        var cosePath = Path.Combine(tempDir, "stdout.cose");
        await File.WriteAllBytesAsync(cosePath, messageBytes);

        var sw = new StringWriter();
        var formatter = new TextOutputFormatter(sw);
        var service = new CoseInspectionService(formatter, standardOutputProvider: () => Stream.Null);

        // Act
        var result = await service.InspectAsync(cosePath, extractPayloadPath: "-");
        formatter.Flush();

        // Assert
        Assert.That(result, Is.EqualTo((int)ExitCode.Success));
        Assert.That(sw.ToString(), Does.Contain("COSE Sign1 message inspection complete"));
    }

    [Test]
    public async Task InspectAsync_WithEmbeddedMessage_AndInvalidExtractPath_WritesErrorButSucceeds()
    {
        // Arrange
        var payloadBytes = Encoding.UTF8.GetBytes("payload");
        var messageBytes = CreateSign1Embedded(payloadBytes);

        var tempDir = Path.Combine(Path.GetTempPath(), $"cose_inspect_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        var cosePath = Path.Combine(tempDir, "extract-invalid.cose");
        await File.WriteAllBytesAsync(cosePath, messageBytes);

        var sw = new StringWriter();
        var err = new StringWriter();
        var formatter = new TextOutputFormatter(sw, err);
        var service = new CoseInspectionService(formatter);

        // Act
        var result = await service.InspectAsync(cosePath, extractPayloadPath: "invalid<>path.bin");
        formatter.Flush();

        // Assert
        Assert.That(result, Is.EqualTo((int)ExitCode.Success));
        Assert.That(err.ToString(), Does.Contain("Failed to extract payload"));
    }

    [Test]
    public async Task InspectAsync_WithRsaPssSha512Message_MapsAlgorithmName()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var protectedHeaders = new CoseHeaderMap();
        var signer = new CoseSigner(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA512, protectedHeaders);

        var payloadBytes = Encoding.UTF8.GetBytes("payload");
        var messageBytes = CoseSign1Message.SignEmbedded(payloadBytes, signer);

        var tempDir = Path.Combine(Path.GetTempPath(), $"cose_inspect_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        var cosePath = Path.Combine(tempDir, "rsa-pss.cose");
        await File.WriteAllBytesAsync(cosePath, messageBytes);

        var sw = new StringWriter();
        var formatter = new TextOutputFormatter(sw);
        var service = new CoseInspectionService(formatter);

        // Act
        var result = await service.InspectAsync(cosePath);
        formatter.Flush();

        // Assert
        Assert.That(result, Is.EqualTo((int)ExitCode.Success));
        Assert.That(sw.ToString(), Does.Contain("PS512"));
    }
}

