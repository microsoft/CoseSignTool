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
/// Tests for <see cref="KeyVaultRemoteECDsa"/>.
/// </summary>
[TestFixture]
public class KeyVaultRemoteECDsaTests
{
    private static readonly Uri TestKeyId = new("https://test-vault.vault.azure.net/keys/test-key/v1");

    #region Constructor Tests

    [Test]
    public void Constructor_WithNullPublicKey_ThrowsArgumentNullException()
    {
        // Arrange
        var mockWrapper = CreateMockWrapper(ECCurve.NamedCurves.nistP256);

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            new KeyVaultRemoteECDsa(null!, mockWrapper));
        Assert.That(ex.ParamName, Is.EqualTo("publicKey"));
    }

    [Test]
    public void Constructor_WithNullWrapper_ThrowsArgumentNullException()
    {
        // Arrange
        using var publicKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            new KeyVaultRemoteECDsa(publicKey, null!));
        Assert.That(ex.ParamName, Is.EqualTo("cryptoWrapper"));
    }

    [Test]
    public void Constructor_WithValidParameters_CreatesInstance()
    {
        // Arrange
        using var publicKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var mockWrapper = CreateMockWrapper(ECCurve.NamedCurves.nistP256);

        // Act
        using var remoteEcdsa = new KeyVaultRemoteECDsa(publicKey, mockWrapper);

        // Assert
        Assert.That(remoteEcdsa, Is.Not.Null);
    }

    #endregion

    #region KeySize Tests

    [Test]
    public void KeySize_ReturnsPublicKeySize()
    {
        // Arrange
        using var publicKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var mockWrapper = CreateMockWrapper(ECCurve.NamedCurves.nistP256);

        // Act
        using var remoteEcdsa = new KeyVaultRemoteECDsa(publicKey, mockWrapper);

        // Assert
        Assert.That(remoteEcdsa.KeySize, Is.EqualTo(publicKey.KeySize));
    }

    [Test]
    public void KeySize_P384_ReturnsCorrectSize()
    {
        // Arrange
        using var publicKey = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var mockWrapper = CreateMockWrapper(ECCurve.NamedCurves.nistP384);

        // Act
        using var remoteEcdsa = new KeyVaultRemoteECDsa(publicKey, mockWrapper);

        // Assert
        Assert.That(remoteEcdsa.KeySize, Is.EqualTo(384));
    }

    #endregion

    #region ExportParameters Tests

    [Test]
    public void ExportParameters_PublicOnly_ReturnsParameters()
    {
        // Arrange
        using var publicKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var mockWrapper = CreateMockWrapper(ECCurve.NamedCurves.nistP256);
        using var remoteEcdsa = new KeyVaultRemoteECDsa(publicKey, mockWrapper);

        // Act
        var parameters = remoteEcdsa.ExportParameters(includePrivateParameters: false);

        // Assert
        Assert.That(parameters.Q.X, Is.Not.Null);
        Assert.That(parameters.Q.Y, Is.Not.Null);
        Assert.That(parameters.D, Is.Null); // No private key
    }

    [Test]
    public void ExportParameters_WithPrivateParameters_ThrowsCryptographicException()
    {
        // Arrange
        using var publicKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var mockWrapper = CreateMockWrapper(ECCurve.NamedCurves.nistP256);
        using var remoteEcdsa = new KeyVaultRemoteECDsa(publicKey, mockWrapper);

        // Act & Assert
        var ex = Assert.Throws<CryptographicException>(() =>
            remoteEcdsa.ExportParameters(includePrivateParameters: true));
        Assert.That(ex.Message, Does.Contain("Private key is not available"));
    }

    #endregion

    #region ImportParameters Tests

    [Test]
    public void ImportParameters_DelegatesToPublicKey()
    {
        // Arrange
        using var sourceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var publicKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var mockWrapper = CreateMockWrapper(ECCurve.NamedCurves.nistP256);
        using var remoteEcdsa = new KeyVaultRemoteECDsa(publicKey, mockWrapper);

        var parameters = sourceKey.ExportParameters(false);

        // Act & Assert - should not throw
        Assert.DoesNotThrow(() => remoteEcdsa.ImportParameters(parameters));
    }

    #endregion

    #region SignHash Tests

    [Test]
    public void SignHash_DelegatesToWrapper()
    {
        // Arrange
        using var publicKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var expectedSignature = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var mockWrapper = CreateMockWrapper(ECCurve.NamedCurves.nistP256, expectedSignature);
        using var remoteEcdsa = new KeyVaultRemoteECDsa(publicKey, mockWrapper);

        var hash = SHA256.HashData("test data"u8.ToArray());

        // Act
        var signature = remoteEcdsa.SignHash(hash);

        // Assert
        Assert.That(signature, Is.EqualTo(expectedSignature));
    }

    #endregion

    #region VerifyHash Tests

    [Test]
    public void VerifyHash_UsesLocalPublicKey()
    {
        // Arrange - create a real key pair for signing/verification
        using var fullKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var hash = SHA256.HashData("test data"u8.ToArray());
        var signature = fullKey.SignHash(hash);

        // Create wrapper with public key only
        using var publicKey = ECDsa.Create();
        publicKey.ImportParameters(fullKey.ExportParameters(false));
        var mockWrapper = CreateMockWrapper(ECCurve.NamedCurves.nistP256);

        using var remoteEcdsa = new KeyVaultRemoteECDsa(publicKey, mockWrapper);

        // Act
        var isValid = remoteEcdsa.VerifyHash(hash, signature);

        // Assert
        Assert.That(isValid, Is.True);
    }

    [Test]
    public void VerifyHash_WithInvalidSignature_ReturnsFalse()
    {
        // Arrange
        using var publicKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var mockWrapper = CreateMockWrapper(ECCurve.NamedCurves.nistP256);
        using var remoteEcdsa = new KeyVaultRemoteECDsa(publicKey, mockWrapper);

        var hash = SHA256.HashData("test data"u8.ToArray());
        var invalidSignature = new byte[64]; // All zeros

        // Act
        var isValid = remoteEcdsa.VerifyHash(hash, invalidSignature);

        // Assert
        Assert.That(isValid, Is.False);
    }

    #endregion

    #region GenerateKey Tests

    [Test]
    public void GenerateKey_ThrowsNotSupportedException()
    {
        // Arrange
        using var publicKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var mockWrapper = CreateMockWrapper(ECCurve.NamedCurves.nistP256);
        using var remoteEcdsa = new KeyVaultRemoteECDsa(publicKey, mockWrapper);

        // Act & Assert
        var ex = Assert.Throws<NotSupportedException>(() =>
            remoteEcdsa.GenerateKey(ECCurve.NamedCurves.nistP256));
        Assert.That(ex.Message, Does.Contain("keys must be created in Azure Key Vault"));
    }

    #endregion

    #region Dispose Tests

    [Test]
    public void Dispose_CompletesSuccessfully()
    {
        // Arrange
        var publicKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var mockWrapper = CreateMockWrapper(ECCurve.NamedCurves.nistP256);
        var remoteEcdsa = new KeyVaultRemoteECDsa(publicKey, mockWrapper);

        // Act & Assert - dispose should complete without throwing
        Assert.DoesNotThrow(() => remoteEcdsa.Dispose());
    }

    [Test]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        // Arrange
        using var publicKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var mockWrapper = CreateMockWrapper(ECCurve.NamedCurves.nistP256);
        var remoteEcdsa = new KeyVaultRemoteECDsa(publicKey, mockWrapper);

        // Act & Assert
        Assert.DoesNotThrow(() =>
        {
            remoteEcdsa.Dispose();
            remoteEcdsa.Dispose();
            remoteEcdsa.Dispose();
        });
    }

    #endregion

    #region Helper Methods

    private static KeyVaultCryptoClientWrapper CreateMockWrapper(ECCurve curve, byte[]? signatureResponse = null)
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

        using var ecdsa = ECDsa.Create(curve);
        var keyVaultKey = KeyModelFactory.KeyVaultKey(
            properties: KeyModelFactory.KeyProperties(
                id: TestKeyId,
                vaultUri: new Uri("https://test-vault.vault.azure.net"),
                name: "test-key",
                version: "v1"),
            key: new JsonWebKey(ecdsa, includePrivateParameters: false));

        return new KeyVaultCryptoClientWrapper(keyVaultKey, mockCryptoClient.Object);
    }

    #endregion
}
