// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests;

using System.Formats.Cbor;

/// <summary>
/// Tests for CoseX509Thumbprint class.
/// </summary>
[TestFixture]
public class CoseX509ThumbprintTests
{
    private static X509Certificate2 CreateTestCertificate()
    {
        using var certKey = ECDsa.Create();
        var certReq = new CertificateRequest(
            new X500DistinguishedName("CN=Test Certificate"),
            certKey,
            HashAlgorithmName.SHA256);
        return certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    [Test]
    public void Constructor_WithCertificate_UsesSHA256ByDefault()
    {
        // Arrange
        using var testCert = CreateTestCertificate();

        // Act
        var thumbprint = new CoseX509Thumbprint(testCert);

        // Assert
        Assert.That(thumbprint.HashId, Is.EqualTo(-16)); // SHA256 = -16
        Assert.That(thumbprint.Thumbprint.Length, Is.EqualTo(32)); // SHA256 is 32 bytes
    }

    [Test]
    public void Constructor_WithCertificateAndSHA384_UsesCorrectHashId()
    {
        // Arrange
        using var testCert = CreateTestCertificate();

        // Act
        var thumbprint = new CoseX509Thumbprint(testCert, HashAlgorithmName.SHA384);

        // Assert
        Assert.That(thumbprint.HashId, Is.EqualTo(-43)); // SHA384 = -43
        Assert.That(thumbprint.Thumbprint.Length, Is.EqualTo(48)); // SHA384 is 48 bytes
    }

    [Test]
    public void Constructor_WithCertificateAndSHA512_UsesCorrectHashId()
    {
        // Arrange
        using var testCert = CreateTestCertificate();

        // Act
        var thumbprint = new CoseX509Thumbprint(testCert, HashAlgorithmName.SHA512);

        // Assert
        Assert.That(thumbprint.HashId, Is.EqualTo(-44)); // SHA512 = -44
        Assert.That(thumbprint.Thumbprint.Length, Is.EqualTo(64)); // SHA512 is 64 bytes
    }

    [Test]
    public void Constructor_WithNullCertificate_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new CoseX509Thumbprint(null!));
    }

    [Test]
    public void Constructor_WithUnsupportedHashAlgorithm_ThrowsArgumentException()
    {
        // Arrange
        using var testCert = CreateTestCertificate();

        // Act & Assert
        Assert.Throws<ArgumentException>(() => new CoseX509Thumbprint(testCert, HashAlgorithmName.MD5));
    }

    [Test]
    public void Match_WithMatchingCertificate_ReturnsTrue()
    {
        // Arrange
        using var testCert = CreateTestCertificate();
        var thumbprint = new CoseX509Thumbprint(testCert);

        // Act
        bool result = thumbprint.Match(testCert);

        // Assert
        Assert.That(result, Is.True);
    }

    [Test]
    public void Match_WithDifferentCertificate_ReturnsFalse()
    {
        // Arrange
        using var testCert = CreateTestCertificate();
        var thumbprint = new CoseX509Thumbprint(testCert);

        using var otherKey = ECDsa.Create();
        var otherReq = new CertificateRequest(
            new X500DistinguishedName("CN=Other Certificate"),
            otherKey,
            HashAlgorithmName.SHA256);
        using var otherCert = otherReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        // Act
        bool result = thumbprint.Match(otherCert);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void Match_WithNullCertificate_ThrowsArgumentNullException()
    {
        // Arrange
        using var testCert = CreateTestCertificate();
        var thumbprint = new CoseX509Thumbprint(testCert);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => thumbprint.Match(null!));
    }

    [Test]
    public void Serialize_ProducesValidCBOR()
    {
        // Arrange
        using var testCert = CreateTestCertificate();
        var thumbprint = new CoseX509Thumbprint(testCert);
        var writer = new CborWriter();

        // Act
        byte[] encoded = thumbprint.Serialize(writer);

        // Assert
        Assert.That(encoded, Is.Not.Empty);

        // Verify we can deserialize it back
        var reader = new CborReader(encoded);
        var deserialized = CoseX509Thumbprint.Deserialize(reader);
        Assert.That(deserialized.HashId, Is.EqualTo(thumbprint.HashId));
        Assert.That(deserialized.Thumbprint.ToArray(), Is.EqualTo(thumbprint.Thumbprint.ToArray()));
    }

    [Test]
    public void Deserialize_WithValidCBOR_ReturnsThumbprint()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartArray(2);
        writer.WriteInt32(-16); // SHA256
        writer.WriteByteString(new byte[32]); // Dummy hash
        writer.WriteEndArray();

        var reader = new CborReader(writer.Encode());

        // Act
        var thumbprint = CoseX509Thumbprint.Deserialize(reader);

        // Assert
        Assert.That(thumbprint, Is.Not.Null);
        Assert.That(thumbprint.HashId, Is.EqualTo(-16));
        Assert.That(thumbprint.Thumbprint.Length, Is.EqualTo(32));
    }

    [Test]
    public void Deserialize_WithInvalidArrayLength_ThrowsCoseX509FormatException()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartArray(3); // Wrong size
        writer.WriteInt32(-16);
        writer.WriteByteString(new byte[32]);
        writer.WriteInt32(42);
        writer.WriteEndArray();

        var reader = new CborReader(writer.Encode());

        // Act & Assert
        Assert.Throws<CoseX509FormatException>(() => CoseX509Thumbprint.Deserialize(reader));
    }

    [Test]
    public void Deserialize_WithNonArray_ThrowsCoseX509FormatException()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteInt32(42);

        var reader = new CborReader(writer.Encode());

        // Act & Assert
        Assert.Throws<CoseX509FormatException>(() => CoseX509Thumbprint.Deserialize(reader));
    }

    [Test]
    public void Deserialize_WithUnsupportedHashId_ThrowsCoseX509FormatException()
    {
        // Arrange
        var writer = new CborWriter();
        writer.WriteStartArray(2);
        writer.WriteInt32(999); // Unsupported hash ID
        writer.WriteByteString(new byte[32]);
        writer.WriteEndArray();

        var reader = new CborReader(writer.Encode());

        // Act & Assert
        Assert.Throws<CoseX509FormatException>(() => CoseX509Thumbprint.Deserialize(reader));
    }

    [Test]
    public void Deserialize_WithNullReader_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => CoseX509Thumbprint.Deserialize(null!));
    }

    [Test]
    public void Serialize_WithNullWriter_ThrowsArgumentNullException()
    {
        // Arrange
        using var testCert = CreateTestCertificate();
        var thumbprint = new CoseX509Thumbprint(testCert);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => thumbprint.Serialize(null!));
    }

    [Test]
    public void RoundTrip_PreservesThumbprintData()
    {
        // Arrange
        using var testCert = CreateTestCertificate();
        var original = new CoseX509Thumbprint(testCert, HashAlgorithmName.SHA384);
        var writer = new CborWriter();

        // Act
        byte[] encoded = original.Serialize(writer);
        var reader = new CborReader(encoded);
        var deserialized = CoseX509Thumbprint.Deserialize(reader);

        // Assert
        Assert.That(deserialized.HashId, Is.EqualTo(original.HashId));
        Assert.That(deserialized.Thumbprint.ToArray(), Is.EqualTo(original.Thumbprint.ToArray()));
        Assert.That(deserialized.Match(testCert), Is.True);
    }
}