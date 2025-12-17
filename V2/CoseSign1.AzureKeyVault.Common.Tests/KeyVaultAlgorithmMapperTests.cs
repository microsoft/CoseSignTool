// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Common.Tests;

/// <summary>
/// Tests for <see cref="KeyVaultAlgorithmMapper"/>.
/// </summary>
[TestFixture]
public class KeyVaultAlgorithmMapperTests
{
    #region RSA PKCS1 Algorithm Mapping Tests

    [Test]
    public void MapRsaAlgorithm_Sha256WithPkcs1_ReturnsRS256()
    {
        // Arrange & Act
        var result = KeyVaultAlgorithmMapper.MapRsaAlgorithm(HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Assert
        Assert.That(result, Is.EqualTo(SignatureAlgorithm.RS256));
    }

    [Test]
    public void MapRsaAlgorithm_Sha384WithPkcs1_ReturnsRS384()
    {
        // Arrange & Act
        var result = KeyVaultAlgorithmMapper.MapRsaAlgorithm(HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);

        // Assert
        Assert.That(result, Is.EqualTo(SignatureAlgorithm.RS384));
    }

    [Test]
    public void MapRsaAlgorithm_Sha512WithPkcs1_ReturnsRS512()
    {
        // Arrange & Act
        var result = KeyVaultAlgorithmMapper.MapRsaAlgorithm(HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

        // Assert
        Assert.That(result, Is.EqualTo(SignatureAlgorithm.RS512));
    }

    #endregion

    #region RSA PSS Algorithm Mapping Tests

    [Test]
    public void MapRsaAlgorithm_Sha256WithPss_ReturnsPS256()
    {
        // Arrange & Act
        var result = KeyVaultAlgorithmMapper.MapRsaAlgorithm(HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        // Assert
        Assert.That(result, Is.EqualTo(SignatureAlgorithm.PS256));
    }

    [Test]
    public void MapRsaAlgorithm_Sha384WithPss_ReturnsPS384()
    {
        // Arrange & Act
        var result = KeyVaultAlgorithmMapper.MapRsaAlgorithm(HashAlgorithmName.SHA384, RSASignaturePadding.Pss);

        // Assert
        Assert.That(result, Is.EqualTo(SignatureAlgorithm.PS384));
    }

    [Test]
    public void MapRsaAlgorithm_Sha512WithPss_ReturnsPS512()
    {
        // Arrange & Act
        var result = KeyVaultAlgorithmMapper.MapRsaAlgorithm(HashAlgorithmName.SHA512, RSASignaturePadding.Pss);

        // Assert
        Assert.That(result, Is.EqualTo(SignatureAlgorithm.PS512));
    }

    #endregion

    #region RSA Unsupported Algorithm Tests

    [Test]
    public void MapRsaAlgorithm_UnsupportedHashAlgorithm_ThrowsNotSupportedException()
    {
        // Arrange & Act & Assert
        Assert.Throws<NotSupportedException>(() =>
            KeyVaultAlgorithmMapper.MapRsaAlgorithm(HashAlgorithmName.MD5, RSASignaturePadding.Pkcs1));
    }

    [Test]
    public void MapRsaAlgorithm_Sha1_ThrowsNotSupportedException()
    {
        // SHA-1 is not supported for security reasons
        Assert.Throws<NotSupportedException>(() =>
            KeyVaultAlgorithmMapper.MapRsaAlgorithm(HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1));
    }

    #endregion

    #region ECDSA Algorithm Mapping by Hash Length Tests

    [Test]
    public void MapEcdsaAlgorithm_HashLength32_ReturnsES256()
    {
        // SHA-256 produces 32-byte hash
        var result = KeyVaultAlgorithmMapper.MapEcdsaAlgorithm(32);

        Assert.That(result, Is.EqualTo(SignatureAlgorithm.ES256));
    }

    [Test]
    public void MapEcdsaAlgorithm_HashLength48_ReturnsES384()
    {
        // SHA-384 produces 48-byte hash
        var result = KeyVaultAlgorithmMapper.MapEcdsaAlgorithm(48);

        Assert.That(result, Is.EqualTo(SignatureAlgorithm.ES384));
    }

    [Test]
    public void MapEcdsaAlgorithm_HashLength64_ReturnsES512()
    {
        // SHA-512 produces 64-byte hash
        var result = KeyVaultAlgorithmMapper.MapEcdsaAlgorithm(64);

        Assert.That(result, Is.EqualTo(SignatureAlgorithm.ES512));
    }

    [Test]
    public void MapEcdsaAlgorithm_UnknownHashLength_DefaultsToES256()
    {
        // Unknown hash length should default to ES256
        var result = KeyVaultAlgorithmMapper.MapEcdsaAlgorithm(16);

        Assert.That(result, Is.EqualTo(SignatureAlgorithm.ES256));
    }

    #endregion

    #region ECDSA Algorithm Mapping from Hash Name Tests

    [Test]
    public void MapEcdsaAlgorithmFromHash_Sha256_ReturnsES256()
    {
        var result = KeyVaultAlgorithmMapper.MapEcdsaAlgorithmFromHash(HashAlgorithmName.SHA256);

        Assert.That(result, Is.EqualTo(SignatureAlgorithm.ES256));
    }

    [Test]
    public void MapEcdsaAlgorithmFromHash_Sha384_ReturnsES384()
    {
        var result = KeyVaultAlgorithmMapper.MapEcdsaAlgorithmFromHash(HashAlgorithmName.SHA384);

        Assert.That(result, Is.EqualTo(SignatureAlgorithm.ES384));
    }

    [Test]
    public void MapEcdsaAlgorithmFromHash_Sha512_ReturnsES512()
    {
        var result = KeyVaultAlgorithmMapper.MapEcdsaAlgorithmFromHash(HashAlgorithmName.SHA512);

        Assert.That(result, Is.EqualTo(SignatureAlgorithm.ES512));
    }

    [Test]
    public void MapEcdsaAlgorithmFromHash_UnsupportedAlgorithm_DefaultsToES256()
    {
        // MD5 or other unsupported algorithms should default to ES256
        var result = KeyVaultAlgorithmMapper.MapEcdsaAlgorithmFromHash(HashAlgorithmName.MD5);

        Assert.That(result, Is.EqualTo(SignatureAlgorithm.ES256));
    }

    #endregion

    #region Comprehensive Algorithm Coverage Tests

    [Test]
    [TestCase("SHA256", "Pkcs1", "RS256")]
    [TestCase("SHA384", "Pkcs1", "RS384")]
    [TestCase("SHA512", "Pkcs1", "RS512")]
    [TestCase("SHA256", "Pss", "PS256")]
    [TestCase("SHA384", "Pss", "PS384")]
    [TestCase("SHA512", "Pss", "PS512")]
    public void MapRsaAlgorithm_AllValidCombinations_ReturnCorrectAlgorithm(
        string hashName, string paddingName, string expectedAlgorithmName)
    {
        // Arrange
        var hashAlgorithm = new HashAlgorithmName(hashName);
        var padding = paddingName == "Pkcs1" ? RSASignaturePadding.Pkcs1 : RSASignaturePadding.Pss;
        var expectedAlgorithm = new SignatureAlgorithm(expectedAlgorithmName);

        // Act
        var result = KeyVaultAlgorithmMapper.MapRsaAlgorithm(hashAlgorithm, padding);

        // Assert
        Assert.That(result.ToString(), Is.EqualTo(expectedAlgorithm.ToString()));
    }

    [Test]
    [TestCase(32, "ES256")]
    [TestCase(48, "ES384")]
    [TestCase(64, "ES512")]
    public void MapEcdsaAlgorithm_AllValidHashLengths_ReturnCorrectAlgorithm(
        int hashLength, string expectedAlgorithmName)
    {
        // Act
        var result = KeyVaultAlgorithmMapper.MapEcdsaAlgorithm(hashLength);

        // Assert
        Assert.That(result.ToString(), Is.EqualTo(expectedAlgorithmName));
    }

    #endregion
}
