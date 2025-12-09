// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Extensions;
using CoseSign1.Indirect.Extensions;

namespace CoseSign1.Tests.Extensions;

/// <summary>
/// Tests for CoseSign1MessageExtensions core header extraction methods.
/// </summary>
[TestFixture]
public class CoseSign1MessageExtensionsTests
{
    private static CoseSign1Message CreateTestMessage(CoseHeaderMap headers)
    {
        using var key = ECDsa.Create();
        byte[] signedBytes = CoseSign1Message.SignDetached("test"u8.ToArray(), key, HashAlgorithmName.SHA256, headers);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    [Test]
    public void TryGetContentType_WithDirectSignature_ReturnsHeaderThree()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json"));
        var message = CreateTestMessage(headers);

        // Act
        bool result = message.TryGetContentType(out string? contentType);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(contentType, Is.EqualTo("application/json"));
    }

    [Test]
    public void TryGetContentType_WithIndirectHashLegacy_StripsPlusHashExtension()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json+hash-sha256"));
        
        var message = CoseSign1Message.SignDetached(
            "hash"u8.ToArray(),
            ECDsa.Create(),
            HashAlgorithmName.SHA256,
            headers);

        // Act
        bool result = message.TryGetContentType(out string? contentType);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(contentType, Is.EqualTo("application/json"));
    }

    [Test]
    public void TryGetContentType_WithCoseHashV_StripsPlusCoseHashV()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json+cose-hash-v"));
        
        var message = CoseSign1Message.SignDetached(
            "hash"u8.ToArray(),
            ECDsa.Create(),
            HashAlgorithmName.SHA256,
            headers);

        // Act
        bool result = message.TryGetContentType(out string? contentType);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(contentType, Is.EqualTo("application/json"));
    }

    [Test]
    public void TryGetContentType_WithCoseHashEnvelope_ReturnsPreimageContentType()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(new CoseHeaderLabel(258), CoseHeaderValue.FromInt32(-16)); // PayloadHashAlg
        headers.Add(new CoseHeaderLabel(259), CoseHeaderValue.FromString("application/octet-stream")); // PreimageContentType
        
        var message = CoseSign1Message.SignDetached(
            "hash"u8.ToArray(),
            ECDsa.Create(),
            HashAlgorithmName.SHA256,
            headers);

        // Act
        bool result = message.TryGetContentType(out string? contentType);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(contentType, Is.EqualTo("application/octet-stream"));
    }

    [Test]
    public void TryGetContentType_WithNullMessage_ReturnsFalse()
    {
        // Act
        bool result = ((CoseSign1Message)null!).TryGetContentType(out string? contentType);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(contentType, Is.Null);
    }

    [Test]
    public void GetSignatureFormat_WithDirectSignature_ReturnsDirect()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json"));
        
        var message = CoseSign1Message.SignDetached(
            "test"u8.ToArray(),
            ECDsa.Create(),
            HashAlgorithmName.SHA256,
            headers);

        // Act
        var format = message.GetSignatureFormat();

        // Assert
        Assert.That(format, Is.EqualTo(SignatureFormat.Direct));
    }

    [Test]
    public void GetSignatureFormat_WithHashLegacy_ReturnsIndirectHashLegacy()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json+hash-sha384"));
        
        var message = CoseSign1Message.SignDetached(
            "hash"u8.ToArray(),
            ECDsa.Create(),
            HashAlgorithmName.SHA256,
            headers);

        // Act
        var format = message.GetSignatureFormat();

        // Assert
        Assert.That(format, Is.EqualTo(SignatureFormat.IndirectHashLegacy));
    }

    [Test]
    public void GetSignatureFormat_WithCoseHashV_ReturnsIndirectCoseHashV()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/vnd.example+cose-hash-v"));
        
        var message = CoseSign1Message.SignDetached(
            "hash"u8.ToArray(),
            ECDsa.Create(),
            HashAlgorithmName.SHA256,
            headers);

        // Act
        var format = message.GetSignatureFormat();

        // Assert
        Assert.That(format, Is.EqualTo(SignatureFormat.IndirectCoseHashV));
    }

    [Test]
    public void GetSignatureFormat_WithCoseHashEnvelope_ReturnsIndirectCoseHashEnvelope()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(new CoseHeaderLabel(258), CoseHeaderValue.FromInt32(-16)); // PayloadHashAlg
        
        var message = CoseSign1Message.SignDetached(
            "hash"u8.ToArray(),
            ECDsa.Create(),
            HashAlgorithmName.SHA256,
            headers);

        // Act
        var format = message.GetSignatureFormat();

        // Assert
        Assert.That(format, Is.EqualTo(SignatureFormat.IndirectCoseHashEnvelope));
    }

    [Test]
    public void TryGetHeader_String_WithProtectedHeader_ReturnsValue()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("text/plain"));
        
        var message = CoseSign1Message.SignDetached(
            "test"u8.ToArray(),
            ECDsa.Create(),
            HashAlgorithmName.SHA256,
            headers);

        // Act
        bool result = message.TryGetHeader(CoseHeaderLabel.ContentType, out string? value);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(value, Is.EqualTo("text/plain"));
    }

    [Test]
    public void TryGetHeader_Int_WithProtectedHeader_ReturnsValue()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.Algorithm, CoseHeaderValue.FromInt32(-7)); // ES256
        
        var message = CoseSign1Message.SignDetached(
            "test"u8.ToArray(),
            ECDsa.Create(),
            HashAlgorithmName.SHA256,
            headers);

        // Act
        bool result = message.TryGetHeader(CoseHeaderLabel.Algorithm, out int value);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(value, Is.EqualTo(-7));
    }

    [Test]
    public void TryGetHeader_Bytes_WithProtectedHeader_ReturnsValue()
    {
        // Arrange
        var testBytes = new byte[] { 1, 2, 3, 4 };
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.KeyIdentifier, CoseHeaderValue.FromBytes(testBytes));
        
        var message = CoseSign1Message.SignDetached(
            "test"u8.ToArray(),
            ECDsa.Create(),
            HashAlgorithmName.SHA256,
            headers);

        // Act
        bool result = message.TryGetHeader(CoseHeaderLabel.KeyIdentifier, out ReadOnlyMemory<byte> value);

        // Assert
        Assert.That(result, Is.True);
        Assert.That(value.ToArray(), Is.EqualTo(testBytes));
    }

    [Test]
    public void TryGetHeader_WithMissingHeader_ReturnsFalse()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        var message = CoseSign1Message.SignDetached(
            "test"u8.ToArray(),
            ECDsa.Create(),
            HashAlgorithmName.SHA256,
            headers);

        // Act
        bool result = message.TryGetHeader(CoseHeaderLabel.ContentType, out string? value);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(value, Is.Null);
    }

    [Test]
    public void TryGetHeader_WithNullMessage_ReturnsFalse()
    {
        // Act
        bool result = ((CoseSign1Message)null!).TryGetHeader(CoseHeaderLabel.ContentType, out string? value);

        // Assert
        Assert.That(result, Is.False);
        Assert.That(value, Is.Null);
    }

    [Test]
    public void HasHeader_WithExistingProtectedHeader_ReturnsTrue()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        headers.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString("application/json"));
        
        var message = CoseSign1Message.SignDetached(
            "test"u8.ToArray(),
            ECDsa.Create(),
            HashAlgorithmName.SHA256,
            headers);

        // Act
        bool result = message.HasHeader(CoseHeaderLabel.ContentType);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void HasHeader_WithMissingHeader_ReturnsFalse()
    {
        // Arrange
        var headers = new CoseHeaderMap();
        var message = CoseSign1Message.SignDetached(
            "test"u8.ToArray(),
            ECDsa.Create(),
            HashAlgorithmName.SHA256,
            headers);

        // Act
        bool result = message.HasHeader(CoseHeaderLabel.ContentType);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void HasHeader_WithNullMessage_ReturnsFalse()
    {
        // Act
        bool result = ((CoseSign1Message)null!).HasHeader(CoseHeaderLabel.ContentType);

        // Assert
        Assert.That(result, Is.False);
    }
}
