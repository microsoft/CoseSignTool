// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Tests;

using System.Security.Cryptography;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using CoseSign1.AzureKeyVault.Common;
using Moq;
using NUnit.Framework;

/// <summary>
/// Tests for <see cref="KeyVaultRemoteRsa"/>.
/// </summary>
[TestFixture]
public class KeyVaultRemoteRsaTests
{
    private static readonly Uri TestKeyId = new("https://test-vault.vault.azure.net/keys/test-key/v1");

    #region Constructor Tests

    [Test]
    public void Constructor_WithNullPublicKey_ThrowsArgumentNullException()
    {
        // Arrange
        var mockWrapper = CreateMockWrapper(2048);

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            new KeyVaultRemoteRsa(null!, mockWrapper));
        Assert.That(ex.ParamName, Is.EqualTo("publicKey"));
    }

    [Test]
    public void Constructor_WithNullWrapper_ThrowsArgumentNullException()
    {
        // Arrange
        using var publicKey = RSA.Create(2048);

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            new KeyVaultRemoteRsa(publicKey, null!));
        Assert.That(ex.ParamName, Is.EqualTo("cryptoWrapper"));
    }

    [Test]
    public void Constructor_WithValidParameters_CreatesInstance()
    {
        // Arrange
        using var publicKey = RSA.Create(2048);
        var mockWrapper = CreateMockWrapper(2048);

        // Act
        using var remoteRsa = new KeyVaultRemoteRsa(publicKey, mockWrapper);

        // Assert
        Assert.That(remoteRsa, Is.Not.Null);
    }

    #endregion

    #region KeySize Tests

    [Test]
    public void KeySize_ReturnsPublicKeySize()
    {
        // Arrange
        using var publicKey = RSA.Create(2048);
        var mockWrapper = CreateMockWrapper(2048);

        // Act
        using var remoteRsa = new KeyVaultRemoteRsa(publicKey, mockWrapper);

        // Assert
        Assert.That(remoteRsa.KeySize, Is.EqualTo(2048));
    }

    [Test]
    public void KeySize_3072Bit_ReturnsCorrectSize()
    {
        // Arrange
        using var publicKey = RSA.Create(3072);
        var mockWrapper = CreateMockWrapper(3072);

        // Act
        using var remoteRsa = new KeyVaultRemoteRsa(publicKey, mockWrapper);

        // Assert
        Assert.That(remoteRsa.KeySize, Is.EqualTo(3072));
    }

    [Test]
    public void KeySize_4096Bit_ReturnsCorrectSize()
    {
        // Arrange
        using var publicKey = RSA.Create(4096);
        var mockWrapper = CreateMockWrapper(4096);

        // Act
        using var remoteRsa = new KeyVaultRemoteRsa(publicKey, mockWrapper);

        // Assert
        Assert.That(remoteRsa.KeySize, Is.EqualTo(4096));
    }

    #endregion

    #region ExportParameters Tests

    [Test]
    public void ExportParameters_PublicOnly_ReturnsParameters()
    {
        // Arrange
        using var publicKey = RSA.Create(2048);
        var mockWrapper = CreateMockWrapper(2048);
        using var remoteRsa = new KeyVaultRemoteRsa(publicKey, mockWrapper);

        // Act
        var parameters = remoteRsa.ExportParameters(includePrivateParameters: false);

        // Assert
        Assert.That(parameters.Modulus, Is.Not.Null);
        Assert.That(parameters.Exponent, Is.Not.Null);
        Assert.That(parameters.D, Is.Null); // No private key
        Assert.That(parameters.P, Is.Null);
        Assert.That(parameters.Q, Is.Null);
    }

    [Test]
    public void ExportParameters_WithPrivateParameters_ThrowsCryptographicException()
    {
        // Arrange
        using var publicKey = RSA.Create(2048);
        var mockWrapper = CreateMockWrapper(2048);
        using var remoteRsa = new KeyVaultRemoteRsa(publicKey, mockWrapper);

        // Act & Assert
        var ex = Assert.Throws<CryptographicException>(() =>
            remoteRsa.ExportParameters(includePrivateParameters: true));
        Assert.That(ex.Message, Does.Contain("Private key is not available"));
    }

    #endregion

    #region ImportParameters Tests

    [Test]
    public void ImportParameters_DelegatesToPublicKey()
    {
        // Arrange
        using var sourceKey = RSA.Create(2048);
        using var publicKey = RSA.Create(2048);
        var mockWrapper = CreateMockWrapper(2048);
        using var remoteRsa = new KeyVaultRemoteRsa(publicKey, mockWrapper);

        var parameters = sourceKey.ExportParameters(false);

        // Act & Assert - should not throw
        Assert.DoesNotThrow(() => remoteRsa.ImportParameters(parameters));
    }

    #endregion

    #region SignHash Tests

    [Test]
    public void SignHash_PS256_DelegatesToWrapper()
    {
        // Arrange
        using var publicKey = RSA.Create(2048);
        var expectedSignature = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var mockWrapper = CreateMockWrapper(2048, expectedSignature);
        using var remoteRsa = new KeyVaultRemoteRsa(publicKey, mockWrapper);

        var hash = SHA256.HashData("test data"u8.ToArray());

        // Act
        var signature = remoteRsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        // Assert
        Assert.That(signature, Is.EqualTo(expectedSignature));
    }

    [Test]
    public void SignHash_PS384_DelegatesToWrapper()
    {
        // Arrange
        using var publicKey = RSA.Create(3072);
        var expectedSignature = new byte[] { 10, 20, 30, 40 };
        var mockWrapper = CreateMockWrapper(3072, expectedSignature);
        using var remoteRsa = new KeyVaultRemoteRsa(publicKey, mockWrapper);

        var hash = SHA384.HashData("test data"u8.ToArray());

        // Act
        var signature = remoteRsa.SignHash(hash, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);

        // Assert
        Assert.That(signature, Is.EqualTo(expectedSignature));
    }

    [Test]
    public void SignHash_RS256_Pkcs1Padding_DelegatesToWrapper()
    {
        // Arrange
        using var publicKey = RSA.Create(2048);
        var expectedSignature = new byte[] { 5, 10, 15, 20 };
        var mockWrapper = CreateMockWrapper(2048, expectedSignature);
        using var remoteRsa = new KeyVaultRemoteRsa(publicKey, mockWrapper);

        var hash = SHA256.HashData("test data"u8.ToArray());

        // Act
        var signature = remoteRsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Assert
        Assert.That(signature, Is.EqualTo(expectedSignature));
    }

    #endregion

    #region VerifyHash Tests

    [Test]
    public void VerifyHash_UsesLocalPublicKey()
    {
        // Arrange - create a real key pair for signing/verification
        using var fullKey = RSA.Create(2048);
        var hash = SHA256.HashData("test data"u8.ToArray());
        var signature = fullKey.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        // Create wrapper with public key only
        using var publicKey = RSA.Create();
        publicKey.ImportParameters(fullKey.ExportParameters(false));
        var mockWrapper = CreateMockWrapper(2048);

        using var remoteRsa = new KeyVaultRemoteRsa(publicKey, mockWrapper);

        // Act
        var isValid = remoteRsa.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        // Assert
        Assert.That(isValid, Is.True);
    }

    [Test]
    public void VerifyHash_WithInvalidSignature_ReturnsFalse()
    {
        // Arrange
        using var publicKey = RSA.Create(2048);
        var mockWrapper = CreateMockWrapper(2048);
        using var remoteRsa = new KeyVaultRemoteRsa(publicKey, mockWrapper);

        var hash = SHA256.HashData("test data"u8.ToArray());
        var invalidSignature = new byte[256]; // All zeros, wrong signature

        // Act
        var isValid = remoteRsa.VerifyHash(hash, invalidSignature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        // Assert
        Assert.That(isValid, Is.False);
    }

    [Test]
    public void VerifyHash_Pkcs1Padding_UsesLocalPublicKey()
    {
        // Arrange - create a real key pair for signing/verification
        using var fullKey = RSA.Create(2048);
        var hash = SHA256.HashData("test data"u8.ToArray());
        var signature = fullKey.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Create wrapper with public key only
        using var publicKey = RSA.Create();
        publicKey.ImportParameters(fullKey.ExportParameters(false));
        var mockWrapper = CreateMockWrapper(2048);

        using var remoteRsa = new KeyVaultRemoteRsa(publicKey, mockWrapper);

        // Act
        var isValid = remoteRsa.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Assert
        Assert.That(isValid, Is.True);
    }

    #endregion

    #region Dispose Tests

    [Test]
    public void Dispose_CompletesSuccessfully()
    {
        // Arrange
        var publicKey = RSA.Create(2048);
        var mockWrapper = CreateMockWrapper(2048);
        var remoteRsa = new KeyVaultRemoteRsa(publicKey, mockWrapper);

        // Act & Assert - dispose should complete without throwing
        Assert.DoesNotThrow(() => remoteRsa.Dispose());
    }

    [Test]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        // Arrange
        using var publicKey = RSA.Create(2048);
        var mockWrapper = CreateMockWrapper(2048);
        var remoteRsa = new KeyVaultRemoteRsa(publicKey, mockWrapper);

        // Act & Assert
        Assert.DoesNotThrow(() =>
        {
            remoteRsa.Dispose();
            remoteRsa.Dispose();
            remoteRsa.Dispose();
        });
    }

    #endregion

    #region Helper Methods

    private static KeyVaultCryptoClientWrapper CreateMockWrapper(int keySize, byte[]? signatureResponse = null)
    {
        var mockCryptoClient = new Mock<CryptographyClient>();

        mockCryptoClient.Setup(c => c.SignAsync(
            It.IsAny<SignatureAlgorithm>(),
            It.IsAny<byte[]>(),
            It.IsAny<CancellationToken>()))
            .ReturnsAsync((SignatureAlgorithm alg, byte[] hash, CancellationToken ct) =>
                CryptographyModelFactory.SignResult(
                    keyId: TestKeyId.ToString(),
                    signature: signatureResponse ?? new byte[] { 1, 2, 3, 4 },
                    algorithm: alg));

        mockCryptoClient.Setup(c => c.Sign(
            It.IsAny<SignatureAlgorithm>(),
            It.IsAny<byte[]>(),
            It.IsAny<CancellationToken>()))
            .Returns((SignatureAlgorithm alg, byte[] hash, CancellationToken ct) =>
                CryptographyModelFactory.SignResult(
                    keyId: TestKeyId.ToString(),
                    signature: signatureResponse ?? new byte[] { 1, 2, 3, 4 },
                    algorithm: alg));

        using var rsa = RSA.Create(keySize);
        var keyVaultKey = KeyModelFactory.KeyVaultKey(
            properties: KeyModelFactory.KeyProperties(
                id: TestKeyId,
                vaultUri: new Uri("https://test-vault.vault.azure.net"),
                name: "test-key",
                version: "v1"),
            key: new JsonWebKey(rsa, includePrivateParameters: false));

        return new KeyVaultCryptoClientWrapper(keyVaultKey, mockCryptoClient.Object);
    }

    #endregion
}
