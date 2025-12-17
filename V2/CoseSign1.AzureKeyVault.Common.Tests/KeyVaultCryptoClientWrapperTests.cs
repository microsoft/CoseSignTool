// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Azure.Core;

namespace CoseSign1.AzureKeyVault.Common.Tests;

/// <summary>
/// Tests for <see cref="KeyVaultCryptoClientWrapper"/>.
/// </summary>
[TestFixture]
public class KeyVaultCryptoClientWrapperTests
{
    private Mock<KeyClient> MockKeyClient = null!;
    private Mock<TokenCredential> MockCredential = null!;
    private const string TestKeyName = "test-signing-key";
    private const string TestKeyVersion = "v1";
    private readonly Uri TestVaultUri = new("https://test-vault.vault.azure.net");

    [SetUp]
    public void Setup()
    {
        MockKeyClient = new Mock<KeyClient>();
        MockCredential = new Mock<TokenCredential>();
    }

    #region Constructor Tests

    [Test]
    public void Constructor_WithNullKey_ThrowsArgumentNullException()
    {
        // Arrange
        var mockCryptoClient = new Mock<CryptographyClient>();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new KeyVaultCryptoClientWrapper(null!, mockCryptoClient.Object));
    }

    [Test]
    public void Constructor_WithNullCryptoClient_ThrowsArgumentNullException()
    {
        // Arrange
        var key = CreateTestRsaKey();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new KeyVaultCryptoClientWrapper(key, null!));
    }

    #endregion

    #region Property Tests

    [Test]
    public void KeyId_ReturnsKeyUri()
    {
        // Arrange
        var key = CreateTestRsaKey();
        var wrapper = CreateWrapper(key);

        // Act
        var keyId = wrapper.KeyId;

        // Assert
        Assert.That(keyId, Does.Contain("test-vault.vault.azure.net"));
        Assert.That(keyId, Does.Contain(TestKeyName));
    }

    [Test]
    public void KeyType_ReturnsCorrectType_ForRsaKey()
    {
        // Arrange
        var key = CreateTestRsaKey();
        var wrapper = CreateWrapper(key);

        // Act & Assert
        Assert.That(wrapper.KeyType, Is.EqualTo(KeyType.Rsa));
    }

    [Test]
    public void KeyType_ReturnsCorrectType_ForEcKey()
    {
        // Arrange
        var key = CreateTestEcKey();
        var wrapper = CreateWrapper(key);

        // Act & Assert
        Assert.That(wrapper.KeyType, Is.EqualTo(KeyType.Ec));
    }

    [Test]
    public void IsHsmProtected_ReturnsFalse_ForSoftwareKey()
    {
        // Arrange
        var key = CreateTestRsaKey();
        var wrapper = CreateWrapper(key);

        // Act & Assert
        Assert.That(wrapper.IsHsmProtected, Is.False);
    }

    [Test]
    public void IsHsmProtected_ReturnsTrue_ForHsmKey()
    {
        // Arrange
        var key = CreateTestRsaHsmKey();
        var wrapper = CreateWrapper(key);

        // Act & Assert
        Assert.That(wrapper.IsHsmProtected, Is.True);
    }

    [Test]
    public void Version_ReturnsCorrectVersion()
    {
        // Arrange
        var key = CreateTestRsaKey();
        var wrapper = CreateWrapper(key);

        // Act
        var version = wrapper.Version;

        // Assert
        Assert.That(version, Is.EqualTo(TestKeyVersion));
    }

    [Test]
    public void Name_ReturnsCorrectName()
    {
        // Arrange
        var key = CreateTestRsaKey();
        var wrapper = CreateWrapper(key);

        // Act
        var name = wrapper.Name;

        // Assert
        Assert.That(name, Is.EqualTo(TestKeyName));
    }

    [Test]
    public void KeyVaultKey_ReturnsUnderlyingKey()
    {
        // Arrange
        var key = CreateTestRsaKey();
        var wrapper = CreateWrapper(key);

        // Act
        var returnedKey = wrapper.KeyVaultKey;

        // Assert
        Assert.That(returnedKey, Is.SameAs(key));
    }

    #endregion

    #region RSA Signing Tests

    [Test]
    public async Task SignHashWithRsaAsync_CallsCryptoClient_WithCorrectAlgorithm()
    {
        // Arrange
        var key = CreateTestRsaKey();
        var mockCryptoClient = new Mock<CryptographyClient>();
        var expectedSignature = new byte[] { 1, 2, 3, 4 };
        var hash = SHA256.HashData(new byte[] { 0x00 });

        mockCryptoClient
            .Setup(x => x.SignAsync(
                It.Is<SignatureAlgorithm>(a => a.ToString() == "PS256"),
                It.IsAny<byte[]>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateSignResult(expectedSignature));

        var wrapper = new KeyVaultCryptoClientWrapper(key, mockCryptoClient.Object);

        // Act
        var result = await wrapper.SignHashWithRsaAsync(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        // Assert
        Assert.That(result, Is.EqualTo(expectedSignature));
        mockCryptoClient.Verify(x => x.SignAsync(
            It.Is<SignatureAlgorithm>(a => a.ToString() == "PS256"),
            hash,
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task SignDataWithRsaAsync_ComputesHashAndSigns()
    {
        // Arrange
        var key = CreateTestRsaKey();
        var mockCryptoClient = new Mock<CryptographyClient>();
        var expectedSignature = new byte[] { 5, 6, 7, 8 };
        var data = new byte[] { 0x01, 0x02, 0x03 };

        mockCryptoClient
            .Setup(x => x.SignAsync(
                It.IsAny<SignatureAlgorithm>(),
                It.IsAny<byte[]>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateSignResult(expectedSignature));

        var wrapper = new KeyVaultCryptoClientWrapper(key, mockCryptoClient.Object);

        // Act
        var result = await wrapper.SignDataWithRsaAsync(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        // Assert
        Assert.That(result, Is.EqualTo(expectedSignature));
        mockCryptoClient.Verify(x => x.SignAsync(
            It.IsAny<SignatureAlgorithm>(),
            It.Is<byte[]>(h => h.Length == 32), // SHA-256 produces 32-byte hash
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void SignHashWithRsa_WithEcKey_ThrowsNotSupportedException()
    {
        // Arrange
        var key = CreateTestEcKey();
        var wrapper = CreateWrapper(key);
        var hash = SHA256.HashData(new byte[] { 0x00 });

        // Act & Assert
        Assert.Throws<NotSupportedException>(() =>
            wrapper.SignHashWithRsa(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    }

    #endregion

    #region ECDSA Signing Tests

    [Test]
    public async Task SignHashWithEcdsaAsync_CallsCryptoClient_WithCorrectAlgorithm()
    {
        // Arrange
        var key = CreateTestEcKey();
        var mockCryptoClient = new Mock<CryptographyClient>();
        var expectedSignature = new byte[] { 9, 10, 11, 12 };
        var hash = SHA256.HashData(new byte[] { 0x00 }); // 32-byte hash

        mockCryptoClient
            .Setup(x => x.SignAsync(
                It.Is<SignatureAlgorithm>(a => a.ToString() == "ES256"),
                It.IsAny<byte[]>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateSignResult(expectedSignature));

        var wrapper = new KeyVaultCryptoClientWrapper(key, mockCryptoClient.Object);

        // Act
        var result = await wrapper.SignHashWithEcdsaAsync(hash);

        // Assert
        Assert.That(result, Is.EqualTo(expectedSignature));
        mockCryptoClient.Verify(x => x.SignAsync(
            It.Is<SignatureAlgorithm>(a => a.ToString() == "ES256"),
            hash,
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public async Task SignDataWithEcdsaAsync_ComputesHashAndSigns()
    {
        // Arrange
        var key = CreateTestEcKey();
        var mockCryptoClient = new Mock<CryptographyClient>();
        var expectedSignature = new byte[] { 13, 14, 15, 16 };
        var data = new byte[] { 0x01, 0x02, 0x03 };

        mockCryptoClient
            .Setup(x => x.SignAsync(
                It.IsAny<SignatureAlgorithm>(),
                It.IsAny<byte[]>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateSignResult(expectedSignature));

        var wrapper = new KeyVaultCryptoClientWrapper(key, mockCryptoClient.Object);

        // Act
        var result = await wrapper.SignDataWithEcdsaAsync(data, HashAlgorithmName.SHA256);

        // Assert
        Assert.That(result, Is.EqualTo(expectedSignature));
    }

    [Test]
    public void SignHashWithEcdsa_WithRsaKey_ThrowsNotSupportedException()
    {
        // Arrange
        var key = CreateTestRsaKey();
        var wrapper = CreateWrapper(key);
        var hash = SHA256.HashData(new byte[] { 0x00 });

        // Act & Assert
        Assert.Throws<NotSupportedException>(() =>
            wrapper.SignHashWithEcdsa(hash));
    }

    #endregion

    #region Generic Signing Tests

    [Test]
    public async Task SignHashAsync_WithRsaKey_UsesRsaSigning()
    {
        // Arrange
        var key = CreateTestRsaKey();
        var mockCryptoClient = new Mock<CryptographyClient>();
        var expectedSignature = new byte[] { 17, 18, 19, 20 };
        var hash = SHA256.HashData(new byte[] { 0x00 });

        mockCryptoClient
            .Setup(x => x.SignAsync(
                It.Is<SignatureAlgorithm>(a => a.ToString() == "PS256"),
                It.IsAny<byte[]>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateSignResult(expectedSignature));

        var wrapper = new KeyVaultCryptoClientWrapper(key, mockCryptoClient.Object);

        // Act
        var result = await wrapper.SignHashAsync(hash, HashAlgorithmName.SHA256);

        // Assert
        Assert.That(result, Is.EqualTo(expectedSignature));
    }

    [Test]
    public async Task SignHashAsync_WithEcKey_UsesEcdsaSigning()
    {
        // Arrange
        var key = CreateTestEcKey();
        var mockCryptoClient = new Mock<CryptographyClient>();
        var expectedSignature = new byte[] { 21, 22, 23, 24 };
        var hash = SHA256.HashData(new byte[] { 0x00 });

        mockCryptoClient
            .Setup(x => x.SignAsync(
                It.Is<SignatureAlgorithm>(a => a.ToString() == "ES256"),
                It.IsAny<byte[]>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateSignResult(expectedSignature));

        var wrapper = new KeyVaultCryptoClientWrapper(key, mockCryptoClient.Object);

        // Act
        var result = await wrapper.SignHashAsync(hash, HashAlgorithmName.SHA256);

        // Assert
        Assert.That(result, Is.EqualTo(expectedSignature));
    }

    #endregion

    #region Dispose Tests

    [Test]
    public void Dispose_ShouldNotThrow()
    {
        // Arrange
        var key = CreateTestRsaKey();
        var wrapper = CreateWrapper(key);

        // Act & Assert
        Assert.DoesNotThrow(() => wrapper.Dispose());
    }

    [Test]
    public void Dispose_CalledMultipleTimes_ShouldNotThrow()
    {
        // Arrange
        var key = CreateTestRsaKey();
        var wrapper = CreateWrapper(key);

        // Act & Assert
        Assert.DoesNotThrow(() =>
        {
            wrapper.Dispose();
            wrapper.Dispose();
        });
    }

    [Test]
    public void SignAfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var key = CreateTestRsaKey();
        var wrapper = CreateWrapper(key);
        var hash = SHA256.HashData(new byte[] { 0x00 });

        // Act
        wrapper.Dispose();

        // Assert
        Assert.Throws<ObjectDisposedException>(() =>
            wrapper.SignHashWithRsa(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    }

    #endregion

    #region Helper Methods

    private KeyVaultCryptoClientWrapper CreateWrapper(KeyVaultKey key)
    {
        var mockCryptoClient = new Mock<CryptographyClient>();
        return new KeyVaultCryptoClientWrapper(key, mockCryptoClient.Object);
    }

    private KeyVaultKey CreateTestRsaKey()
    {
        var keyId = new Uri($"{TestVaultUri}/keys/{TestKeyName}/{TestKeyVersion}");
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);

        var jsonWebKey = new JsonWebKey(rsa, includePrivateParameters: false);

        return KeyModelFactory.KeyVaultKey(
            KeyModelFactory.KeyProperties(keyId, name: TestKeyName, version: TestKeyVersion),
            jsonWebKey);
    }

    private KeyVaultKey CreateTestEcKey()
    {
        var keyId = new Uri($"{TestVaultUri}/keys/{TestKeyName}/{TestKeyVersion}");
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var jsonWebKey = new JsonWebKey(ecdsa, includePrivateParameters: false);

        return KeyModelFactory.KeyVaultKey(
            KeyModelFactory.KeyProperties(keyId, name: TestKeyName, version: TestKeyVersion),
            jsonWebKey);
    }

    private KeyVaultKey CreateTestRsaHsmKey()
    {
        var keyId = new Uri($"{TestVaultUri}/keys/{TestKeyName}/{TestKeyVersion}");
        using var rsa = RSA.Create(2048);

        var jsonWebKey = new JsonWebKey(rsa, includePrivateParameters: false)
        {
            KeyType = KeyType.RsaHsm
        };

        return KeyModelFactory.KeyVaultKey(
            KeyModelFactory.KeyProperties(keyId, name: TestKeyName, version: TestKeyVersion),
            jsonWebKey);
    }

    private static SignResult CreateSignResult(byte[] signature)
    {
        return CryptographyModelFactory.SignResult(
            keyId: "test-key-id",
            signature: signature,
            algorithm: SignatureAlgorithm.PS256);
    }

    #endregion
}
