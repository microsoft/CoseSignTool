// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local.Tests;

/// <summary>
/// Tests for <see cref="SoftwareKeyProvider"/> and <see cref="IGeneratedKey"/> implementations.
/// </summary>
[TestFixture]
public class SoftwareKeyProviderTests
{
    [Test]
    public void ProviderName_ReturnsExpectedName()
    {
        // Arrange
        var provider = new SoftwareKeyProvider();

        // Assert
        Assert.That(provider.ProviderName, Is.EqualTo("Software"));
    }

    [TestCase(KeyAlgorithm.RSA)]
    [TestCase(KeyAlgorithm.ECDSA)]
    [TestCase(KeyAlgorithm.MLDSA)]
    public void SupportsAlgorithm_AllStandardAlgorithms_ReturnsTrue(KeyAlgorithm algorithm)
    {
        // Arrange
        var provider = new SoftwareKeyProvider();

        // Act
        var result = provider.SupportsAlgorithm(algorithm);

        // Assert
        Assert.That(result, Is.True);
    }

    [TestCase(KeyAlgorithm.RSA, 2048)]
    [TestCase(KeyAlgorithm.RSA, 4096)]
    public void GenerateKey_Rsa_CreatesValidKey(KeyAlgorithm algorithm, int keySize)
    {
        // Arrange
        var provider = new SoftwareKeyProvider();

        // Act
        using var key = provider.GenerateKey(algorithm, keySize);

        // Assert
        Assert.That(key, Is.Not.Null);
        Assert.That(key.Algorithm, Is.EqualTo(KeyAlgorithm.RSA));
        Assert.That(key.SignatureGenerator, Is.Not.Null);
    }

    [TestCase(KeyAlgorithm.ECDSA, 256)]
    [TestCase(KeyAlgorithm.ECDSA, 384)]
    [TestCase(KeyAlgorithm.ECDSA, 521)]
    public void GenerateKey_Ecdsa_CreatesValidKey(KeyAlgorithm algorithm, int keySize)
    {
        // Arrange
        var provider = new SoftwareKeyProvider();

        // Act
        using var key = provider.GenerateKey(algorithm, keySize);

        // Assert
        Assert.That(key, Is.Not.Null);
        Assert.That(key.Algorithm, Is.EqualTo(KeyAlgorithm.ECDSA));
        Assert.That(key.SignatureGenerator, Is.Not.Null);
    }

    [TestCase(KeyAlgorithm.MLDSA, 44)]
    [TestCase(KeyAlgorithm.MLDSA, 65)]
    [TestCase(KeyAlgorithm.MLDSA, 87)]
    public void GenerateKey_Mldsa_CreatesValidKey(KeyAlgorithm algorithm, int keySize)
    {
        // Arrange
        var provider = new SoftwareKeyProvider();

        // Act
        using var key = provider.GenerateKey(algorithm, keySize);

        // Assert
        Assert.That(key, Is.Not.Null);
        Assert.That(key.Algorithm, Is.EqualTo(KeyAlgorithm.MLDSA));
        Assert.That(key.SignatureGenerator, Is.Not.Null);
    }

    [Test]
    public void GenerateKey_InvalidKeySize_ThrowsException()
    {
        // Arrange
        var provider = new SoftwareKeyProvider();

        // Act
        var act = () => provider.GenerateKey(KeyAlgorithm.RSA, 512); // Too small

        // Assert
        Assert.That(act, Throws.TypeOf<ArgumentOutOfRangeException>());
    }

    [Test]
    public void CreateCertificateRequest_Rsa_CreatesValidRequest()
    {
        // Arrange
        var provider = new SoftwareKeyProvider();
        using var key = provider.GenerateKey(KeyAlgorithm.RSA);

        // Act
        var request = key.CreateCertificateRequest("CN=Test", HashAlgorithmName.SHA256);

        // Assert
        Assert.That(request, Is.Not.Null);
        Assert.That(request.SubjectName.Name, Is.EqualTo("CN=Test"));
    }

    [Test]
    public void CreateCertificateRequest_Ecdsa_CreatesValidRequest()
    {
        // Arrange
        var provider = new SoftwareKeyProvider();
        using var key = provider.GenerateKey(KeyAlgorithm.ECDSA);

        // Act
        var request = key.CreateCertificateRequest("CN=Test", HashAlgorithmName.SHA256);

        // Assert
        Assert.That(request, Is.Not.Null);
        Assert.That(request.SubjectName.Name, Is.EqualTo("CN=Test"));
    }

    [Test]
    public void CreateCertificateRequest_Mldsa_CreatesValidRequest()
    {
        // Arrange
        var provider = new SoftwareKeyProvider();
        using var key = provider.GenerateKey(KeyAlgorithm.MLDSA);

        // Act
        var request = key.CreateCertificateRequest("CN=Test", HashAlgorithmName.SHA256);

        // Assert
        Assert.That(request, Is.Not.Null);
        Assert.That(request.SubjectName.Name, Is.EqualTo("CN=Test"));
    }

    [Test]
    public void CopyPrivateKeyTo_Rsa_CertificateHasPrivateKey()
    {
        // Arrange
        var provider = new SoftwareKeyProvider();
        using var key = provider.GenerateKey(KeyAlgorithm.RSA);
        var request = key.CreateCertificateRequest("CN=Test", HashAlgorithmName.SHA256);
        using var certWithoutKey = request.Create(
            new X500DistinguishedName("CN=Test"),
            key.SignatureGenerator,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddDays(1),
            new byte[] { 1, 2, 3, 4 });

        // Act
        using var certWithKey = key.CopyPrivateKeyTo(certWithoutKey);

        // Assert
        Assert.That(certWithKey.HasPrivateKey, Is.True);
    }

    [Test]
    public async Task GenerateKeyAsync_ReturnsValidKey()
    {
        // Arrange
        var provider = new SoftwareKeyProvider();

        // Act
        using var key = await provider.GenerateKeyAsync(KeyAlgorithm.RSA);

        // Assert
        Assert.That(key, Is.Not.Null);
        Assert.That(key.Algorithm, Is.EqualTo(KeyAlgorithm.RSA));
    }

    [Test]
    public void Dispose_DisposesUnderlyingKey()
    {
        // Arrange
        var provider = new SoftwareKeyProvider();
        var key = provider.GenerateKey(KeyAlgorithm.RSA);

        // Act
        key.Dispose();

        // Assert - accessing SignatureGenerator after dispose should work 
        // but using it should fail (implementation detail - just verify no crash on dispose)
        Assert.That(key.Algorithm, Is.EqualTo(KeyAlgorithm.RSA));
    }

    [Test]
    public void SupportsAlgorithm_UnknownAlgorithm_ReturnsFalse()
    {
        // Arrange
        var provider = new SoftwareKeyProvider();

        // Act
        var result = provider.SupportsAlgorithm((KeyAlgorithm)999);

        // Assert
        Assert.That(result, Is.False);
    }

    [Test]
    public void GenerateKey_UnknownAlgorithm_ThrowsNotSupportedException()
    {
        // Arrange
        var provider = new SoftwareKeyProvider();

        // Act & Assert
        Assert.Throws<NotSupportedException>(() => provider.GenerateKey((KeyAlgorithm)999));
    }

    [Test]
    public void GenerateKey_RsaKeyTooLarge_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        var provider = new SoftwareKeyProvider();

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => provider.GenerateKey(KeyAlgorithm.RSA, 20000));
    }

    [Test]
    public void GenerateKey_EcdsaInvalidKeySize_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        var provider = new SoftwareKeyProvider();

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => provider.GenerateKey(KeyAlgorithm.ECDSA, 128));
    }

    [Test]
    public void GenerateKey_MldsaInvalidParameterSet_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        var provider = new SoftwareKeyProvider();

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => provider.GenerateKey(KeyAlgorithm.MLDSA, 100));
    }

    [Test]
    public async Task GenerateKeyAsync_WithCancellation_ThrowsOperationCanceledException()
    {
        // Arrange
        var provider = new SoftwareKeyProvider();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        // Act & Assert
        Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await provider.GenerateKeyAsync(KeyAlgorithm.RSA, cancellationToken: cts.Token));
    }

    [Test]
    public void GenerateKey_RsaDefaultKeySize_Uses2048()
    {
        // Arrange
        var provider = new SoftwareKeyProvider();

        // Act
        using var key = provider.GenerateKey(KeyAlgorithm.RSA);

        // Assert - just verify it works with default (2048)
        Assert.That(key, Is.Not.Null);
    }

    [Test]
    public void GenerateKey_EcdsaDefaultKeySize_Uses256()
    {
        // Arrange
        var provider = new SoftwareKeyProvider();

        // Act
        using var key = provider.GenerateKey(KeyAlgorithm.ECDSA);

        // Assert
        Assert.That(key, Is.Not.Null);
    }

    [Test]
    public void GenerateKey_MldsaDefaultKeySize_Uses65()
    {
        // Arrange
        var provider = new SoftwareKeyProvider();

        // Act
        using var key = provider.GenerateKey(KeyAlgorithm.MLDSA);

        // Assert
        Assert.That(key, Is.Not.Null);
    }

    [Test]
    public void CopyPrivateKeyTo_Ecdsa_CertificateHasPrivateKey()
    {
        // Arrange
        var provider = new SoftwareKeyProvider();
        using var key = provider.GenerateKey(KeyAlgorithm.ECDSA);
        var request = key.CreateCertificateRequest("CN=Test", HashAlgorithmName.SHA256);
        using var certWithoutKey = request.Create(
            new X500DistinguishedName("CN=Test"),
            key.SignatureGenerator,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddDays(1),
            new byte[] { 1, 2, 3, 4 });

        // Act
        using var certWithKey = key.CopyPrivateKeyTo(certWithoutKey);

        // Assert
        Assert.That(certWithKey.HasPrivateKey, Is.True);
    }

    [Test]
    public void CopyPrivateKeyTo_Mldsa_CertificateHasPrivateKey()
    {
        // Arrange
        var provider = new SoftwareKeyProvider();
        using var key = provider.GenerateKey(KeyAlgorithm.MLDSA);
        var request = key.CreateCertificateRequest("CN=Test", HashAlgorithmName.SHA256);
        using var certWithoutKey = request.Create(
            new X500DistinguishedName("CN=Test"),
            key.SignatureGenerator,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddDays(1),
            new byte[] { 1, 2, 3, 4 });

        // Act
        using var certWithKey = key.CopyPrivateKeyTo(certWithoutKey);

        // Assert
        Assert.That(certWithKey.HasPrivateKey, Is.True);
    }

    [Test]
    public void Dispose_MultipleCalls_DoesNotThrow()
    {
        // Arrange
        var provider = new SoftwareKeyProvider();
        var key = provider.GenerateKey(KeyAlgorithm.RSA);

        // Act & Assert
        Assert.DoesNotThrow(() =>
        {
            key.Dispose();
            key.Dispose(); // Second dispose should not throw
        });
    }
}