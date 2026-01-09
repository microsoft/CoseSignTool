// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Tests;

using CoseSign1.AzureKeyVault.Common;

/// <summary>
/// Tests for AzureKeyVaultSigningKey.
/// </summary>
[TestFixture]
public class AzureKeyVaultSigningKeyTests
{
    private const string TestKeyName = "test-signing-key";
    private const string TestKeyVersion = "v1";
    private readonly Uri TestVaultUri = new("https://test-vault.vault.azure.net");

    /// <summary>
    /// Creates a mock signing service for testing.
    /// </summary>
    private static Mock<ISigningService<SigningOptions>> CreateMockSigningService()
    {
        var mock = new Mock<ISigningService<SigningOptions>>();
        mock.Setup(s => s.ServiceMetadata).Returns(new SigningServiceMetadata("TestSigningService"));
        return mock;
    }

    #region Constructor Tests

    [Test]
    public void Constructor_WithNullSigningService_ThrowsArgumentNullException()
    {
        // Arrange
        var keyVaultKey = CreateTestRsaKey();
        var wrapper = new KeyVaultCryptoClientWrapper(keyVaultKey, new Mock<CryptographyClient>().Object);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new AzureKeyVaultSigningKey(null!, wrapper));
    }

    [Test]
    public void Constructor_WithNullCryptoWrapper_ThrowsArgumentNullException()
    {
        // Arrange
        var mockSigningService = CreateMockSigningService();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new AzureKeyVaultSigningKey(mockSigningService.Object, null!));
    }

    [Test]
    public void Constructor_WithValidParameters_CreatesInstance()
    {
        // Arrange
        var mockSigningService = CreateMockSigningService();
        var keyVaultKey = CreateTestRsaKey();
        var wrapper = new KeyVaultCryptoClientWrapper(keyVaultKey, new Mock<CryptographyClient>().Object);

        // Act
        var signingKey = new AzureKeyVaultSigningKey(mockSigningService.Object, wrapper);

        // Assert
        Assert.That(signingKey, Is.Not.Null);
    }

    #endregion

    #region RSA Key Metadata Tests

    [Test]
    public void Metadata_WithRsaKey_HasRsaKeyType()
    {
        // Arrange
        var mockSigningService = CreateMockSigningService();
        var keyVaultKey = CreateTestRsaKey(2048);
        var wrapper = new KeyVaultCryptoClientWrapper(keyVaultKey, new Mock<CryptographyClient>().Object);
        using var signingKey = new AzureKeyVaultSigningKey(mockSigningService.Object, wrapper);

        // Act
        var metadata = signingKey.Metadata;

        // Assert
        Assert.That(metadata.KeyType, Is.EqualTo(CryptographicKeyType.RSA));
        Assert.That(metadata.IsRemote, Is.True);
    }

    [Test]
    public void Metadata_With2048BitRsaKey_UsesPS256()
    {
        // Arrange - 2048-bit key
        var mockSigningService = CreateMockSigningService();
        var keyVaultKey = CreateTestRsaKey(2048);
        var wrapper = new KeyVaultCryptoClientWrapper(keyVaultKey, new Mock<CryptographyClient>().Object);
        using var signingKey = new AzureKeyVaultSigningKey(mockSigningService.Object, wrapper);

        // Act
        var metadata = signingKey.Metadata;

        // Assert - COSE algorithm -37 is PS256
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-37));
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA256));
    }

    [Test]
    public void Metadata_With4096BitRsaKey_UsesPS512()
    {
        // Arrange - 4096-bit key
        var mockSigningService = CreateMockSigningService();
        var keyVaultKey = CreateTestRsaKey(4096);
        var wrapper = new KeyVaultCryptoClientWrapper(keyVaultKey, new Mock<CryptographyClient>().Object);
        using var signingKey = new AzureKeyVaultSigningKey(mockSigningService.Object, wrapper);

        // Act
        var metadata = signingKey.Metadata;

        // Assert - COSE algorithm -39 is PS512
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-39));
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA512));
    }

    #endregion

    #region EC Key Metadata Tests

    [Test]
    public void Metadata_WithEcP256Key_UsesES256()
    {
        // Arrange
        var mockSigningService = CreateMockSigningService();
        var keyVaultKey = CreateTestEcKey(ECCurve.NamedCurves.nistP256);
        var wrapper = new KeyVaultCryptoClientWrapper(keyVaultKey, new Mock<CryptographyClient>().Object);
        using var signingKey = new AzureKeyVaultSigningKey(mockSigningService.Object, wrapper);

        // Act
        var metadata = signingKey.Metadata;

        // Assert - COSE algorithm -7 is ES256
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-7));
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA256));
    }

    [Test]
    public void Metadata_WithEcP384Key_UsesES384()
    {
        // Arrange
        var mockSigningService = CreateMockSigningService();
        var keyVaultKey = CreateTestEcKey(ECCurve.NamedCurves.nistP384);
        var wrapper = new KeyVaultCryptoClientWrapper(keyVaultKey, new Mock<CryptographyClient>().Object);
        using var signingKey = new AzureKeyVaultSigningKey(mockSigningService.Object, wrapper);

        // Act
        var metadata = signingKey.Metadata;

        // Assert - COSE algorithm -35 is ES384
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-35));
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA384));
    }

    [Test]
    public void Metadata_WithEcP521Key_UsesES512()
    {
        // Arrange
        var mockSigningService = CreateMockSigningService();
        var keyVaultKey = CreateTestEcKey(ECCurve.NamedCurves.nistP521);
        var wrapper = new KeyVaultCryptoClientWrapper(keyVaultKey, new Mock<CryptographyClient>().Object);
        using var signingKey = new AzureKeyVaultSigningKey(mockSigningService.Object, wrapper);

        // Act
        var metadata = signingKey.Metadata;

        // Assert - COSE algorithm -36 is ES512
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-36));
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA512));
    }

    [Test]
    public void Metadata_WithEcKey_HasECDsaKeyType()
    {
        // Arrange
        var mockSigningService = CreateMockSigningService();
        var keyVaultKey = CreateTestEcKey();
        var wrapper = new KeyVaultCryptoClientWrapper(keyVaultKey, new Mock<CryptographyClient>().Object);
        using var signingKey = new AzureKeyVaultSigningKey(mockSigningService.Object, wrapper);

        // Act
        var metadata = signingKey.Metadata;

        // Assert
        Assert.That(metadata.KeyType, Is.EqualTo(CryptographicKeyType.ECDsa));
        Assert.That(metadata.IsRemote, Is.True);
    }

    #endregion

    #region CoseKey Tests

    [Test]
    public void GetCoseKey_WithRsaKey_ReturnsValidCoseKey()
    {
        // Arrange
        var mockSigningService = CreateMockSigningService();
        var keyVaultKey = CreateTestRsaKey();
        var wrapper = new KeyVaultCryptoClientWrapper(keyVaultKey, new Mock<CryptographyClient>().Object);
        using var signingKey = new AzureKeyVaultSigningKey(mockSigningService.Object, wrapper);

        // Act
        var coseKey = signingKey.GetCoseKey();

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void GetCoseKey_CalledMultipleTimes_ReturnsCachedInstance()
    {
        // Arrange
        var mockSigningService = CreateMockSigningService();
        var keyVaultKey = CreateTestRsaKey();
        var wrapper = new KeyVaultCryptoClientWrapper(keyVaultKey, new Mock<CryptographyClient>().Object);
        using var signingKey = new AzureKeyVaultSigningKey(mockSigningService.Object, wrapper);

        // Act
        var coseKey1 = signingKey.GetCoseKey();
        var coseKey2 = signingKey.GetCoseKey();

        // Assert - should be the same instance due to caching
        Assert.That(coseKey1, Is.SameAs(coseKey2));
    }

    [Test]
    public void GetCoseKey_WithEcKey_ReturnsValidCoseKey()
    {
        // Arrange
        var mockSigningService = CreateMockSigningService();
        var keyVaultKey = CreateTestEcKey();
        var wrapper = new KeyVaultCryptoClientWrapper(keyVaultKey, new Mock<CryptographyClient>().Object);
        using var signingKey = new AzureKeyVaultSigningKey(mockSigningService.Object, wrapper);

        // Act
        var coseKey = signingKey.GetCoseKey();

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    #endregion

    #region KeyId Tests

    [Test]
    public void KeyId_ReturnsKeyVaultKeyUri()
    {
        // Arrange
        var mockSigningService = CreateMockSigningService();
        var keyVaultKey = CreateTestRsaKey();
        var wrapper = new KeyVaultCryptoClientWrapper(keyVaultKey, new Mock<CryptographyClient>().Object);
        using var signingKey = new AzureKeyVaultSigningKey(mockSigningService.Object, wrapper);

        // Act
        var keyId = signingKey.KeyId;

        // Assert
        Assert.That(keyId, Does.Contain(TestKeyName));
        Assert.That(keyId, Does.Contain(TestKeyVersion));
    }

    #endregion

    #region SigningService Reference Tests

    [Test]
    public void SigningService_ReturnsProvidedService()
    {
        // Arrange
        var mockSigningService = CreateMockSigningService();
        var keyVaultKey = CreateTestRsaKey();
        var wrapper = new KeyVaultCryptoClientWrapper(keyVaultKey, new Mock<CryptographyClient>().Object);
        using var signingKey = new AzureKeyVaultSigningKey(mockSigningService.Object, wrapper);

        // Act & Assert
        Assert.That(signingKey.SigningService, Is.SameAs(mockSigningService.Object));
    }

    #endregion

    #region Dispose Tests

    [Test]
    public void Dispose_IsIdempotent()
    {
        // Arrange
        var mockSigningService = CreateMockSigningService();
        var keyVaultKey = CreateTestRsaKey();
        var wrapper = new KeyVaultCryptoClientWrapper(keyVaultKey, new Mock<CryptographyClient>().Object);
        var signingKey = new AzureKeyVaultSigningKey(mockSigningService.Object, wrapper);

        // Act & Assert - calling Dispose multiple times should not throw
        Assert.DoesNotThrow(() =>
        {
            signingKey.Dispose();
            signingKey.Dispose();
            signingKey.Dispose();
        });
    }

    #endregion

    #region Helper Methods for KeyVaultKey Creation

    /// <summary>
    /// Creates a test RSA KeyVaultKey using the model factory.
    /// </summary>
    private KeyVaultKey CreateTestRsaKey(int keySize = 2048)
    {
        var keyId = new Uri($"{TestVaultUri}/keys/{TestKeyName}/{TestKeyVersion}");
        var rsa = RSA.Create(keySize);
        var jsonWebKey = new JsonWebKey(rsa, includePrivateParameters: false);

        return KeyModelFactory.KeyVaultKey(
            KeyModelFactory.KeyProperties(keyId, name: TestKeyName, version: TestKeyVersion),
            jsonWebKey);
    }

    /// <summary>
    /// Creates a test EC KeyVaultKey using the model factory.
    /// </summary>
    private KeyVaultKey CreateTestEcKey(ECCurve? curve = null)
    {
        var keyId = new Uri($"{TestVaultUri}/keys/{TestKeyName}/{TestKeyVersion}");
        var ecdsa = ECDsa.Create(curve ?? ECCurve.NamedCurves.nistP256);
        var jsonWebKey = new JsonWebKey(ecdsa, includePrivateParameters: false);

        return KeyModelFactory.KeyVaultKey(
            KeyModelFactory.KeyProperties(keyId, name: TestKeyName, version: TestKeyVersion),
            jsonWebKey);
    }

    #endregion
}
