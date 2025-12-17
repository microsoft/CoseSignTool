// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Tests;

/// <summary>
/// Tests for <see cref="KeyVaultAlgorithmMapper"/>.
/// </summary>
[TestFixture]
public class KeyVaultAlgorithmMapperTests
{
    #region MapRsaAlgorithm Tests - PSS Padding

    [Test]
    public void MapRsaAlgorithm_WithSHA256AndPss_ReturnsPS256()
    {
        // Act
        var algorithm = KeyVaultAlgorithmMapper.MapRsaAlgorithm(
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);

        // Assert
        Assert.That(algorithm, Is.EqualTo(SignatureAlgorithm.PS256));
    }

    [Test]
    public void MapRsaAlgorithm_WithSHA384AndPss_ReturnsPS384()
    {
        // Act
        var algorithm = KeyVaultAlgorithmMapper.MapRsaAlgorithm(
            HashAlgorithmName.SHA384,
            RSASignaturePadding.Pss);

        // Assert
        Assert.That(algorithm, Is.EqualTo(SignatureAlgorithm.PS384));
    }

    [Test]
    public void MapRsaAlgorithm_WithSHA512AndPss_ReturnsPS512()
    {
        // Act
        var algorithm = KeyVaultAlgorithmMapper.MapRsaAlgorithm(
            HashAlgorithmName.SHA512,
            RSASignaturePadding.Pss);

        // Assert
        Assert.That(algorithm, Is.EqualTo(SignatureAlgorithm.PS512));
    }

    #endregion

    #region MapRsaAlgorithm Tests - PKCS#1 Padding

    [Test]
    public void MapRsaAlgorithm_WithSHA256AndPkcs1_ReturnsRS256()
    {
        // Act
        var algorithm = KeyVaultAlgorithmMapper.MapRsaAlgorithm(
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Assert
        Assert.That(algorithm, Is.EqualTo(SignatureAlgorithm.RS256));
    }

    [Test]
    public void MapRsaAlgorithm_WithSHA384AndPkcs1_ReturnsRS384()
    {
        // Act
        var algorithm = KeyVaultAlgorithmMapper.MapRsaAlgorithm(
            HashAlgorithmName.SHA384,
            RSASignaturePadding.Pkcs1);

        // Assert
        Assert.That(algorithm, Is.EqualTo(SignatureAlgorithm.RS384));
    }

    [Test]
    public void MapRsaAlgorithm_WithSHA512AndPkcs1_ReturnsRS512()
    {
        // Act
        var algorithm = KeyVaultAlgorithmMapper.MapRsaAlgorithm(
            HashAlgorithmName.SHA512,
            RSASignaturePadding.Pkcs1);

        // Assert
        Assert.That(algorithm, Is.EqualTo(SignatureAlgorithm.RS512));
    }

    #endregion

    #region MapRsaAlgorithm Tests - Unsupported Combinations

    [Test]
    public void MapRsaAlgorithm_WithSHA1_ThrowsNotSupportedException()
    {
        // Act & Assert
        Assert.Throws<NotSupportedException>(() =>
            KeyVaultAlgorithmMapper.MapRsaAlgorithm(
                HashAlgorithmName.SHA1,
                RSASignaturePadding.Pss));
    }

    [Test]
    public void MapRsaAlgorithm_WithMD5_ThrowsNotSupportedException()
    {
        // Act & Assert
        Assert.Throws<NotSupportedException>(() =>
            KeyVaultAlgorithmMapper.MapRsaAlgorithm(
                HashAlgorithmName.MD5,
                RSASignaturePadding.Pss));
    }

    #endregion

    #region MapEcdsaAlgorithm Tests

    [Test]
    public void MapEcdsaAlgorithm_With32ByteHash_ReturnsES256()
    {
        // SHA-256 produces 32 bytes
        var algorithm = KeyVaultAlgorithmMapper.MapEcdsaAlgorithm(32);

        Assert.That(algorithm, Is.EqualTo(SignatureAlgorithm.ES256));
    }

    [Test]
    public void MapEcdsaAlgorithm_With48ByteHash_ReturnsES384()
    {
        // SHA-384 produces 48 bytes
        var algorithm = KeyVaultAlgorithmMapper.MapEcdsaAlgorithm(48);

        Assert.That(algorithm, Is.EqualTo(SignatureAlgorithm.ES384));
    }

    [Test]
    public void MapEcdsaAlgorithm_With64ByteHash_ReturnsES512()
    {
        // SHA-512 produces 64 bytes
        var algorithm = KeyVaultAlgorithmMapper.MapEcdsaAlgorithm(64);

        Assert.That(algorithm, Is.EqualTo(SignatureAlgorithm.ES512));
    }

    [Test]
    public void MapEcdsaAlgorithm_WithUnknownHashLength_DefaultsToES256()
    {
        // Unknown hash lengths default to ES256
        var algorithm = KeyVaultAlgorithmMapper.MapEcdsaAlgorithm(20); // SHA-1 length

        Assert.That(algorithm, Is.EqualTo(SignatureAlgorithm.ES256));
    }

    #endregion

    #region MapEcdsaAlgorithmFromHash Tests

    [Test]
    public void MapEcdsaAlgorithmFromHash_WithSHA256_ReturnsES256()
    {
        var algorithm = KeyVaultAlgorithmMapper.MapEcdsaAlgorithmFromHash(HashAlgorithmName.SHA256);

        Assert.That(algorithm, Is.EqualTo(SignatureAlgorithm.ES256));
    }

    [Test]
    public void MapEcdsaAlgorithmFromHash_WithSHA384_ReturnsES384()
    {
        var algorithm = KeyVaultAlgorithmMapper.MapEcdsaAlgorithmFromHash(HashAlgorithmName.SHA384);

        Assert.That(algorithm, Is.EqualTo(SignatureAlgorithm.ES384));
    }

    [Test]
    public void MapEcdsaAlgorithmFromHash_WithSHA512_ReturnsES512()
    {
        var algorithm = KeyVaultAlgorithmMapper.MapEcdsaAlgorithmFromHash(HashAlgorithmName.SHA512);

        Assert.That(algorithm, Is.EqualTo(SignatureAlgorithm.ES512));
    }

    [Test]
    public void MapEcdsaAlgorithmFromHash_WithSHA1_DefaultsToES256()
    {
        var algorithm = KeyVaultAlgorithmMapper.MapEcdsaAlgorithmFromHash(HashAlgorithmName.SHA1);

        Assert.That(algorithm, Is.EqualTo(SignatureAlgorithm.ES256));
    }

    [Test]
    public void MapEcdsaAlgorithmFromHash_WithMD5_DefaultsToES256()
    {
        var algorithm = KeyVaultAlgorithmMapper.MapEcdsaAlgorithmFromHash(HashAlgorithmName.MD5);

        Assert.That(algorithm, Is.EqualTo(SignatureAlgorithm.ES256));
    }

    #endregion

    #region Integration Tests

    [Test]
    public void MapRsaAlgorithm_AllValidSHA256Combinations_Work()
    {
        // Test both padding types with SHA256
        Assert.Multiple(() =>
        {
            Assert.That(
                KeyVaultAlgorithmMapper.MapRsaAlgorithm(HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
                Is.EqualTo(SignatureAlgorithm.PS256));
            Assert.That(
                KeyVaultAlgorithmMapper.MapRsaAlgorithm(HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                Is.EqualTo(SignatureAlgorithm.RS256));
        });
    }

    [Test]
    public void MapEcdsaAlgorithm_WithActualHashOutput_MapsCorrectly()
    {
        // Test with actual hash outputs
        Assert.Multiple(() =>
        {
            var sha256Hash = SHA256.HashData("test"u8);
            var sha384Hash = SHA384.HashData("test"u8);
            var sha512Hash = SHA512.HashData("test"u8);

            Assert.That(KeyVaultAlgorithmMapper.MapEcdsaAlgorithm(sha256Hash.Length), Is.EqualTo(SignatureAlgorithm.ES256));
            Assert.That(KeyVaultAlgorithmMapper.MapEcdsaAlgorithm(sha384Hash.Length), Is.EqualTo(SignatureAlgorithm.ES384));
            Assert.That(KeyVaultAlgorithmMapper.MapEcdsaAlgorithm(sha512Hash.Length), Is.EqualTo(SignatureAlgorithm.ES512));
        });
    }

    #endregion
}
