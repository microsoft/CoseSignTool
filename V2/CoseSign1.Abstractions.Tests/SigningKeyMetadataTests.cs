// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using NUnit.Framework;

namespace CoseSign1.Abstractions.Tests;

/// <summary>
/// Tests for SigningKeyMetadata class.
/// </summary>
[TestFixture]
public class SigningKeyMetadataTests
{
    [Test]
    public void Constructor_ShouldInitializeAllProperties()
    {
        // Arrange
        var coseAlgorithmId = -7; // ES256
        var keyType = CryptographicKeyType.ECDsa;
        var hashAlgorithm = HashAlgorithmName.SHA256;
        var keySizeInBits = 256;
        var isRemote = false;
        var additionalMetadata = new Dictionary<string, object>
        {
            { "CertificateThumbprint", "abc123" },
            { "KeyVersion", "v1" }
        };

        // Act
        var metadata = new SigningKeyMetadata(
            coseAlgorithmId,
            keyType,
            isRemote,
            hashAlgorithm,
            keySizeInBits,
            additionalMetadata);

        // Assert
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(coseAlgorithmId));
        Assert.That(metadata.KeyType, Is.EqualTo(keyType));
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(hashAlgorithm));
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(keySizeInBits));
        Assert.That(metadata.IsRemote, Is.EqualTo(isRemote));
        Assert.That(metadata.AdditionalMetadata, Is.EqualTo(additionalMetadata));
        Assert.That(metadata.AdditionalMetadata, Is.Not.SameAs(additionalMetadata), "Should be a defensive copy");
    }

    [Test]
    public void Constructor_WithNullOptionalParameters_ShouldUseDefaults()
    {
        // Arrange & Act
        var metadata = new SigningKeyMetadata(-7, CryptographicKeyType.ECDsa, false, null, null, null);

        // Assert
        Assert.That(metadata.HashAlgorithm, Is.Null);
        Assert.That(metadata.KeySizeInBits, Is.Null);
        Assert.That(metadata.AdditionalMetadata, Is.Not.Null);
        Assert.That(metadata.AdditionalMetadata, Is.Empty);
    }

    [Test]
    public void AdditionalMetadata_ShouldBeReadOnly()
    {
        // Arrange
        var metadata = new SigningKeyMetadata(
            -7,
            CryptographicKeyType.ECDsa,
            false,
            null,
            null,
            new Dictionary<string, object> { { "Key1", "Value1" } });

        // Act & Assert
        var additionalMetadata = metadata.AdditionalMetadata;
        Assert.That(additionalMetadata, Is.InstanceOf<IReadOnlyDictionary<string, object>>());
    }

    [Test]
    public void ToString_ShouldReturnMeaningfulRepresentation()
    {
        // Arrange
        var metadata = new SigningKeyMetadata(-7, CryptographicKeyType.ECDsa, true, HashAlgorithmName.SHA256, 256, null);

        // Act
        var result = metadata.ToString();

        // Assert
        Assert.That(result, Does.Contain("ECDsa"));
        Assert.That(result, Does.Contain("-7"));
        Assert.That(result, Does.Contain("True"));
    }

    [Test]
    public void CryptographicKeyType_ShouldHaveExpectedValues()
    {
        // Assert - verify enum values exist
        Assert.That(Enum.IsDefined(typeof(CryptographicKeyType), CryptographicKeyType.RSA), Is.True);
        Assert.That(Enum.IsDefined(typeof(CryptographicKeyType), CryptographicKeyType.ECDsa), Is.True);
        Assert.That(Enum.IsDefined(typeof(CryptographicKeyType), CryptographicKeyType.EdDSA), Is.True);
        Assert.That(Enum.IsDefined(typeof(CryptographicKeyType), CryptographicKeyType.MLDSA), Is.True);
        Assert.That(Enum.IsDefined(typeof(CryptographicKeyType), CryptographicKeyType.Other), Is.True);
    }
}
