// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using Azure;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using CoseSign1.AzureKeyVault.Common;
using Moq;

namespace CoseSign1.AzureKeyVault.Tests;

/// <summary>
/// Tests for <see cref="KeyVaultCryptoClientWrapper"/>.
/// </summary>
[TestFixture]
public class KeyVaultCryptoClientWrapperTests
{
    private const string TestKeyName = "test-signing-key";
    private const string TestKeyVersion = "v1";
    private readonly Uri TestVaultUri = new("https://test-vault.vault.azure.net");
    private readonly Uri TestKeyId = new("https://test-vault.vault.azure.net/keys/test-signing-key/v1");

    #region RSA Key Tests

    [Test]
    public void SignHashWithRsa_WithValidHash_ReturnsSignature()
    {
        // Arrange
        var expectedSignature = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var hash = SHA256.HashData("test data"u8);

        var mockCryptoClient = CreateMockCryptographyClient(expectedSignature);
        var rsaKey = CreateMockRsaKey();
        var wrapper = new KeyVaultCryptoClientWrapper(rsaKey, mockCryptoClient.Object);

        // Act
        var signature = wrapper.SignHashWithRsa(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        // Assert
        Assert.That(signature, Is.EqualTo(expectedSignature));
    }

    [Test]
    public async Task SignHashWithRsaAsync_WithValidHash_ReturnsSignature()
    {
        // Arrange
        var expectedSignature = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var hash = SHA256.HashData("test data"u8);

        var mockCryptoClient = CreateMockCryptographyClient(expectedSignature);
        var rsaKey = CreateMockRsaKey();
        var wrapper = new KeyVaultCryptoClientWrapper(rsaKey, mockCryptoClient.Object);

        // Act
        var signature = await wrapper.SignHashWithRsaAsync(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        // Assert
        Assert.That(signature, Is.EqualTo(expectedSignature));
    }

    [Test]
    public void SignHashWithRsa_WithEcKey_ThrowsNotSupportedException()
    {
        // Arrange
        var mockCryptoClient = CreateMockCryptographyClient(Array.Empty<byte>());
        var ecKey = CreateMockEcKey();
        var wrapper = new KeyVaultCryptoClientWrapper(ecKey, mockCryptoClient.Object);
        var hash = SHA256.HashData("test data"u8);

        // Act & Assert
        Assert.Throws<NotSupportedException>(() =>
            wrapper.SignHashWithRsa(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    }

    [Test]
    public async Task SignDataWithRsaAsync_ComputesHashAndSigns()
    {
        // Arrange
        var expectedSignature = new byte[] { 10, 20, 30, 40 };
        var data = "test data to sign"u8.ToArray();

        var mockCryptoClient = CreateMockCryptographyClient(expectedSignature);
        var rsaKey = CreateMockRsaKey();
        var wrapper = new KeyVaultCryptoClientWrapper(rsaKey, mockCryptoClient.Object);

        // Act
        var signature = await wrapper.SignDataWithRsaAsync(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        // Assert
        Assert.That(signature, Is.EqualTo(expectedSignature));
    }

    [Test]
    public void SignDataWithRsa_WithSHA384_UsesCorrectAlgorithm()
    {
        // Arrange
        var expectedSignature = new byte[] { 1, 2, 3, 4 };
        var data = "test data"u8.ToArray();

        var mockCryptoClient = new Mock<CryptographyClient>();
        mockCryptoClient
            .Setup(c => c.SignAsync(SignatureAlgorithm.PS384, It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateSignResult(SignatureAlgorithm.PS384, expectedSignature));

        var rsaKey = CreateMockRsaKey();
        var wrapper = new KeyVaultCryptoClientWrapper(rsaKey, mockCryptoClient.Object);

        // Act
        var signature = wrapper.SignDataWithRsa(data, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);

        // Assert
        Assert.That(signature, Is.EqualTo(expectedSignature));
        mockCryptoClient.Verify(c => c.SignAsync(SignatureAlgorithm.PS384, It.IsAny<byte[]>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void SignHashWithRsa_WithPkcs1Padding_UsesRSAlgorithm()
    {
        // Arrange
        var expectedSignature = new byte[] { 5, 6, 7, 8 };
        var hash = SHA256.HashData("test"u8);

        var mockCryptoClient = new Mock<CryptographyClient>();
        mockCryptoClient
            .Setup(c => c.SignAsync(SignatureAlgorithm.RS256, It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateSignResult(SignatureAlgorithm.RS256, expectedSignature));

        var rsaKey = CreateMockRsaKey();
        var wrapper = new KeyVaultCryptoClientWrapper(rsaKey, mockCryptoClient.Object);

        // Act
        var signature = wrapper.SignHashWithRsa(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Assert
        Assert.That(signature, Is.EqualTo(expectedSignature));
    }

    #endregion

    #region ECDSA Key Tests

    [Test]
    public void SignHashWithEcdsa_WithValidHash_ReturnsSignature()
    {
        // Arrange
        var expectedSignature = new byte[] { 11, 22, 33, 44 };
        var hash = SHA256.HashData("test data"u8);

        var mockCryptoClient = CreateMockCryptographyClient(expectedSignature);
        var ecKey = CreateMockEcKey();
        var wrapper = new KeyVaultCryptoClientWrapper(ecKey, mockCryptoClient.Object);

        // Act
        var signature = wrapper.SignHashWithEcdsa(hash);

        // Assert
        Assert.That(signature, Is.EqualTo(expectedSignature));
    }

    [Test]
    public async Task SignHashWithEcdsaAsync_WithValidHash_ReturnsSignature()
    {
        // Arrange
        var expectedSignature = new byte[] { 55, 66, 77, 88 };
        var hash = SHA384.HashData("test data"u8);

        var mockCryptoClient = CreateMockCryptographyClient(expectedSignature);
        var ecKey = CreateMockEcKey();
        var wrapper = new KeyVaultCryptoClientWrapper(ecKey, mockCryptoClient.Object);

        // Act
        var signature = await wrapper.SignHashWithEcdsaAsync(hash);

        // Assert
        Assert.That(signature, Is.EqualTo(expectedSignature));
    }

    [Test]
    public void SignHashWithEcdsa_WithRsaKey_ThrowsNotSupportedException()
    {
        // Arrange
        var mockCryptoClient = CreateMockCryptographyClient(Array.Empty<byte>());
        var rsaKey = CreateMockRsaKey();
        var wrapper = new KeyVaultCryptoClientWrapper(rsaKey, mockCryptoClient.Object);
        var hash = SHA256.HashData("test"u8);

        // Act & Assert
        Assert.Throws<NotSupportedException>(() => wrapper.SignHashWithEcdsa(hash));
    }

    [Test]
    public void SignHashWithEcdsa_WithSHA384Hash_UsesES384()
    {
        // Arrange
        var expectedSignature = new byte[] { 1, 2, 3 };
        var hash = SHA384.HashData("test"u8); // 48 bytes = ES384

        var mockCryptoClient = new Mock<CryptographyClient>();
        mockCryptoClient
            .Setup(c => c.SignAsync(SignatureAlgorithm.ES384, It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateSignResult(SignatureAlgorithm.ES384, expectedSignature));

        var ecKey = CreateMockEcKey();
        var wrapper = new KeyVaultCryptoClientWrapper(ecKey, mockCryptoClient.Object);

        // Act
        var signature = wrapper.SignHashWithEcdsa(hash);

        // Assert
        Assert.That(signature, Is.EqualTo(expectedSignature));
    }

    [Test]
    public void SignHashWithEcdsa_WithSHA512Hash_UsesES512()
    {
        // Arrange
        var expectedSignature = new byte[] { 7, 8, 9 };
        var hash = SHA512.HashData("test"u8); // 64 bytes = ES512

        var mockCryptoClient = new Mock<CryptographyClient>();
        mockCryptoClient
            .Setup(c => c.SignAsync(SignatureAlgorithm.ES512, It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateSignResult(SignatureAlgorithm.ES512, expectedSignature));

        var ecKey = CreateMockEcKey();
        var wrapper = new KeyVaultCryptoClientWrapper(ecKey, mockCryptoClient.Object);

        // Act
        var signature = wrapper.SignHashWithEcdsa(hash);

        // Assert
        Assert.That(signature, Is.EqualTo(expectedSignature));
    }

    [Test]
    public async Task SignDataWithEcdsaAsync_ComputesHashAndSigns()
    {
        // Arrange
        var expectedSignature = new byte[] { 99, 88, 77 };
        var data = "test data to sign"u8.ToArray();

        var mockCryptoClient = CreateMockCryptographyClient(expectedSignature);
        var ecKey = CreateMockEcKey();
        var wrapper = new KeyVaultCryptoClientWrapper(ecKey, mockCryptoClient.Object);

        // Act
        var signature = await wrapper.SignDataWithEcdsaAsync(data, HashAlgorithmName.SHA256);

        // Assert
        Assert.That(signature, Is.EqualTo(expectedSignature));
    }

    #endregion

    #region Generic SignHashAsync Tests

    [Test]
    public async Task SignHashAsync_WithRsaKey_DelegatesToRsaSigning()
    {
        // Arrange
        var expectedSignature = new byte[] { 100, 200 };
        var hash = SHA256.HashData("test"u8);

        var mockCryptoClient = CreateMockCryptographyClient(expectedSignature);
        var rsaKey = CreateMockRsaKey();
        var wrapper = new KeyVaultCryptoClientWrapper(rsaKey, mockCryptoClient.Object);

        // Act
        var signature = await wrapper.SignHashAsync(hash, HashAlgorithmName.SHA256);

        // Assert
        Assert.That(signature, Is.EqualTo(expectedSignature));
    }

    [Test]
    public async Task SignHashAsync_WithEcKey_DelegatesToEcdsaSigning()
    {
        // Arrange
        var expectedSignature = new byte[] { 111, 222 };
        var hash = SHA256.HashData("test"u8);

        var mockCryptoClient = CreateMockCryptographyClient(expectedSignature);
        var ecKey = CreateMockEcKey();
        var wrapper = new KeyVaultCryptoClientWrapper(ecKey, mockCryptoClient.Object);

        // Act
        var signature = await wrapper.SignHashAsync(hash, HashAlgorithmName.SHA256);

        // Assert
        Assert.That(signature, Is.EqualTo(expectedSignature));
    }

    [Test]
    public async Task SignHashAsync_WithRsaKeyAndCustomPadding_UsesSpecifiedPadding()
    {
        // Arrange
        var expectedSignature = new byte[] { 1, 1, 1 };
        var hash = SHA256.HashData("test"u8);

        var mockCryptoClient = new Mock<CryptographyClient>();
        mockCryptoClient
            .Setup(c => c.SignAsync(SignatureAlgorithm.RS256, It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateSignResult(SignatureAlgorithm.RS256, expectedSignature));

        var rsaKey = CreateMockRsaKey();
        var wrapper = new KeyVaultCryptoClientWrapper(rsaKey, mockCryptoClient.Object);

        // Act
        var signature = await wrapper.SignHashAsync(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Assert
        Assert.That(signature, Is.EqualTo(expectedSignature));
    }

    #endregion

    #region Property Tests

    [Test]
    public void KeyId_ReturnsKeyUri()
    {
        // Arrange
        var mockCryptoClient = CreateMockCryptographyClient(Array.Empty<byte>());
        var key = CreateMockRsaKey();
        var wrapper = new KeyVaultCryptoClientWrapper(key, mockCryptoClient.Object);

        // Act
        var keyId = wrapper.KeyId;

        // Assert
        Assert.That(keyId, Is.EqualTo(TestKeyId.ToString()));
    }

    [Test]
    public void KeyType_ReturnsCorrectType()
    {
        // Arrange - RSA
        var mockCryptoClient = CreateMockCryptographyClient(Array.Empty<byte>());
        var rsaKey = CreateMockRsaKey();
        var rsaWrapper = new KeyVaultCryptoClientWrapper(rsaKey, mockCryptoClient.Object);

        // Assert
        Assert.That(rsaWrapper.KeyType, Is.EqualTo(KeyType.Rsa));

        // Arrange - EC
        var ecKey = CreateMockEcKey();
        var ecWrapper = new KeyVaultCryptoClientWrapper(ecKey, mockCryptoClient.Object);

        // Assert
        Assert.That(ecWrapper.KeyType, Is.EqualTo(KeyType.Ec));
    }

    [Test]
    public void IsHsmProtected_ReturnsFalseForSoftwareKeys()
    {
        // Arrange
        var mockCryptoClient = CreateMockCryptographyClient(Array.Empty<byte>());
        var key = CreateMockRsaKey();
        var wrapper = new KeyVaultCryptoClientWrapper(key, mockCryptoClient.Object);

        // Act & Assert
        Assert.That(wrapper.IsHsmProtected, Is.False);
    }

    [Test]
    public void IsHsmProtected_ReturnsTrueForHsmKeys()
    {
        // Arrange
        var mockCryptoClient = CreateMockCryptographyClient(Array.Empty<byte>());
        var key = CreateMockRsaHsmKey();
        var wrapper = new KeyVaultCryptoClientWrapper(key, mockCryptoClient.Object);

        // Act & Assert
        Assert.That(wrapper.IsHsmProtected, Is.True);
    }

    [Test]
    public void Version_ReturnsKeyVersion()
    {
        // Arrange
        var mockCryptoClient = CreateMockCryptographyClient(Array.Empty<byte>());
        var key = CreateMockRsaKey();
        var wrapper = new KeyVaultCryptoClientWrapper(key, mockCryptoClient.Object);

        // Act & Assert
        Assert.That(wrapper.Version, Is.EqualTo(TestKeyVersion));
    }

    [Test]
    public void Name_ReturnsKeyName()
    {
        // Arrange
        var mockCryptoClient = CreateMockCryptographyClient(Array.Empty<byte>());
        var key = CreateMockRsaKey();
        var wrapper = new KeyVaultCryptoClientWrapper(key, mockCryptoClient.Object);

        // Act & Assert
        Assert.That(wrapper.Name, Is.EqualTo(TestKeyName));
    }

    [Test]
    public void KeyVaultKey_ReturnsUnderlyingKey()
    {
        // Arrange
        var mockCryptoClient = CreateMockCryptographyClient(Array.Empty<byte>());
        var key = CreateMockRsaKey();
        var wrapper = new KeyVaultCryptoClientWrapper(key, mockCryptoClient.Object);

        // Act & Assert
        Assert.That(wrapper.KeyVaultKey, Is.SameAs(key));
    }

    #endregion

    #region Constructor Validation Tests

    [Test]
    public void Constructor_WithNullKey_ThrowsArgumentNullException()
    {
        // Arrange
        var mockCryptoClient = CreateMockCryptographyClient(Array.Empty<byte>());

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new KeyVaultCryptoClientWrapper(null!, mockCryptoClient.Object));
    }

    [Test]
    public void Constructor_WithNullCryptoClient_ThrowsArgumentNullException()
    {
        // Arrange
        var key = CreateMockRsaKey();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new KeyVaultCryptoClientWrapper(key, null!));
    }

    #endregion

    #region Generic Signing Tests

    [Test]
    public async Task SignHashAsync_WithRsaKeyAndNullPadding_DefaultsToPss()
    {
        // Arrange
        var expectedSignature = new byte[] { 9, 9, 9 };
        var hash = SHA256.HashData("test"u8);

        var mockCryptoClient = new Mock<CryptographyClient>();
        mockCryptoClient
            .Setup(c => c.SignAsync(SignatureAlgorithm.PS256, It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateSignResult(SignatureAlgorithm.PS256, expectedSignature));

        var rsaKey = CreateMockRsaKey();
        var wrapper = new KeyVaultCryptoClientWrapper(rsaKey, mockCryptoClient.Object);

        // Act
        var signature = await wrapper.SignHashAsync(hash, HashAlgorithmName.SHA256, rsaPadding: null);

        // Assert
        Assert.That(signature, Is.EqualTo(expectedSignature));
        mockCryptoClient.Verify(c => c.SignAsync(SignatureAlgorithm.PS256, It.IsAny<byte[]>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Test]
    public void SignHashAsync_WithUnsupportedKeyType_ThrowsNotSupportedException()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var jsonWebKey = new JsonWebKey(rsa, includePrivateParameters: false)
        {
            KeyType = KeyType.Oct
        };

        var key = KeyModelFactory.KeyVaultKey(
            properties: KeyModelFactory.KeyProperties(
                id: TestKeyId,
                vaultUri: TestVaultUri,
                name: TestKeyName,
                version: TestKeyVersion),
            key: jsonWebKey);

        var mockCryptoClient = CreateMockCryptographyClient(Array.Empty<byte>());
        var wrapper = new KeyVaultCryptoClientWrapper(key, mockCryptoClient.Object);

        // Act & Assert
        Assert.ThrowsAsync<NotSupportedException>(async () =>
            await wrapper.SignHashAsync(SHA256.HashData("test"u8), HashAlgorithmName.SHA256, rsaPadding: RSASignaturePadding.Pss));
    }

    [Test]
    public void SignDataWithRsa_WithUnsupportedHashAlgorithm_ThrowsNotSupportedException()
    {
        // Arrange
        var mockCryptoClient = CreateMockCryptographyClient(Array.Empty<byte>());
        var rsaKey = CreateMockRsaKey();
        var wrapper = new KeyVaultCryptoClientWrapper(rsaKey, mockCryptoClient.Object);

        // Act & Assert
        Assert.ThrowsAsync<NotSupportedException>(async () =>
            await wrapper.SignDataWithRsaAsync("test"u8.ToArray(), HashAlgorithmName.MD5, RSASignaturePadding.Pss));
    }

    [Test]
    public async Task CreateAsync_WithKeyClient_ReturnsWrapperWithExpectedMetadata()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var jsonWebKey = new JsonWebKey(rsa, includePrivateParameters: false);
        var keyProperties = KeyModelFactory.KeyProperties(
            id: TestKeyId,
            vaultUri: TestVaultUri,
            name: TestKeyName,
            version: TestKeyVersion);

        var keyVaultKey = KeyModelFactory.KeyVaultKey(properties: keyProperties, key: jsonWebKey);

        var mockKeyClient = new Mock<KeyClient>(MockBehavior.Strict);
        mockKeyClient
            .Setup(c => c.GetKeyAsync(TestKeyName, TestKeyVersion, It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(keyVaultKey, new Mock<Response>().Object));

        var credential = new Mock<TokenCredential>(MockBehavior.Strict).Object;

        // Act
        using var wrapper = await KeyVaultCryptoClientWrapper.CreateAsync(
            mockKeyClient.Object,
            credential,
            TestKeyName,
            keyVersion: TestKeyVersion);

        // Assert
        Assert.That(wrapper.Name, Is.EqualTo(TestKeyName));
        Assert.That(wrapper.Version, Is.EqualTo(TestKeyVersion));
        Assert.That(wrapper.KeyId, Is.EqualTo(TestKeyId.ToString()));
    }

    [Test]
    public async Task SignHashAsync_WithEcKey_UsesEcdsaPath()
    {
        // Arrange
        var expectedSignature = new byte[] { 6, 6, 6 };
        var hash = SHA256.HashData("test"u8);

        var mockCryptoClient = new Mock<CryptographyClient>();
        mockCryptoClient
            .Setup(c => c.SignAsync(SignatureAlgorithm.ES256, It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateSignResult(SignatureAlgorithm.ES256, expectedSignature));

        var ecKey = CreateMockEcKey();
        var wrapper = new KeyVaultCryptoClientWrapper(ecKey, mockCryptoClient.Object);

        // Act
        var signature = await wrapper.SignHashAsync(hash, HashAlgorithmName.SHA256);

        // Assert
        Assert.That(signature, Is.EqualTo(expectedSignature));
        mockCryptoClient.Verify(c => c.SignAsync(SignatureAlgorithm.ES256, It.IsAny<byte[]>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    #endregion

    #region Dispose Tests

    [Test]
    public void Dispose_CalledMultipleTimes_DoesNotThrow()
    {
        // Arrange
        var mockCryptoClient = CreateMockCryptographyClient(Array.Empty<byte>());
        var key = CreateMockRsaKey();
        var wrapper = new KeyVaultCryptoClientWrapper(key, mockCryptoClient.Object);

        // Act & Assert
        Assert.DoesNotThrow(() =>
        {
            wrapper.Dispose();
            wrapper.Dispose();
            wrapper.Dispose();
        });
    }

    [Test]
    public void SignHashWithRsa_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var mockCryptoClient = CreateMockCryptographyClient(Array.Empty<byte>());
        var key = CreateMockRsaKey();
        var wrapper = new KeyVaultCryptoClientWrapper(key, mockCryptoClient.Object);
        wrapper.Dispose();
        var hash = SHA256.HashData("test"u8);

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() =>
            wrapper.SignHashWithRsa(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    }

    [Test]
    public void SignHashWithEcdsa_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var mockCryptoClient = CreateMockCryptographyClient(Array.Empty<byte>());
        var key = CreateMockEcKey();
        var wrapper = new KeyVaultCryptoClientWrapper(key, mockCryptoClient.Object);
        wrapper.Dispose();
        var hash = SHA256.HashData("test"u8);

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => wrapper.SignHashWithEcdsa(hash));
    }

    #endregion

    #region Helper Methods

    private Mock<CryptographyClient> CreateMockCryptographyClient(byte[] signatureToReturn)
    {
        var mock = new Mock<CryptographyClient>();

        // Setup for all signature algorithms
        mock.Setup(c => c.SignAsync(It.IsAny<SignatureAlgorithm>(), It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((SignatureAlgorithm alg, byte[] hash, CancellationToken ct) =>
                CreateSignResult(alg, signatureToReturn));

        return mock;
    }

    private static SignResult CreateSignResult(SignatureAlgorithm algorithm, byte[] signature)
    {
        // SignResult has a protected constructor, we need to use Azure.Core's model factory pattern
        // or create via reflection. Azure SDK provides MockableKeyVaultKeys for this.
        return CryptographyModelFactory.SignResult(
            keyId: "https://test-vault.vault.azure.net/keys/test-signing-key/v1",
            signature: signature,
            algorithm: algorithm);
    }

    private KeyVaultKey CreateMockRsaKey()
    {
        // Create RSA key material
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);

        var jsonWebKey = new JsonWebKey(rsa, includePrivateParameters: false);

        return KeyModelFactory.KeyVaultKey(
            properties: KeyModelFactory.KeyProperties(
                id: TestKeyId,
                vaultUri: TestVaultUri,
                name: TestKeyName,
                version: TestKeyVersion),
            key: jsonWebKey);
    }

    private KeyVaultKey CreateMockRsaHsmKey()
    {
        using var rsa = RSA.Create(2048);

        // Create HSM-backed key
        var jsonWebKey = new JsonWebKey(rsa, includePrivateParameters: false)
        {
            KeyType = KeyType.RsaHsm
        };

        return KeyModelFactory.KeyVaultKey(
            properties: KeyModelFactory.KeyProperties(
                id: TestKeyId,
                vaultUri: TestVaultUri,
                name: TestKeyName,
                version: TestKeyVersion),
            key: jsonWebKey);
    }

    private KeyVaultKey CreateMockEcKey()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var jsonWebKey = new JsonWebKey(ecdsa, includePrivateParameters: false);

        return KeyModelFactory.KeyVaultKey(
            properties: KeyModelFactory.KeyProperties(
                id: TestKeyId,
                vaultUri: TestVaultUri,
                name: TestKeyName,
                version: TestKeyVersion),
            key: jsonWebKey);
    }

    private KeyVaultKey CreateMockEcHsmKey()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var jsonWebKey = new JsonWebKey(ecdsa, includePrivateParameters: false)
        {
            KeyType = KeyType.EcHsm
        };

        return KeyModelFactory.KeyVaultKey(
            properties: KeyModelFactory.KeyProperties(
                id: TestKeyId,
                vaultUri: TestVaultUri,
                name: TestKeyName,
                version: TestKeyVersion),
            key: jsonWebKey);
    }

    #endregion
}
