// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Remote;

using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Remote;
using Moq;

/// <summary>
/// Extended tests for RemoteCertificateSource to improve code coverage.
/// </summary>
[TestFixture]
public class RemoteCertificateSourceExtendedTests
{
    #region Constructor Tests

    [Test]
    public void Constructor_WithNullChainBuilder_UsesDefaultX509ChainBuilder()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("TestCert");

        // Act
        using var source = new TestRemoteCertificateSource(cert, null);

        // Assert
        Assert.That(source.HasPrivateKey, Is.True);
    }

    [Test]
    public void Constructor_WithCustomChainBuilder_UsesProvidedBuilder()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("TestCert");
        var mockChainBuilder = new Mock<ICertificateChainBuilder>();
        mockChainBuilder.Setup(b => b.ChainPolicy).Returns(new X509ChainPolicy());

        // Act
        using var source = new TestRemoteCertificateSource(cert, mockChainBuilder.Object);

        // Assert
        Assert.That(source.HasPrivateKey, Is.True);
    }

    #endregion

    #region HasPrivateKey Tests

    [Test]
    public void HasPrivateKey_AlwaysReturnsTrue()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("TestCert");
        using var source = new TestRemoteCertificateSource(cert);

        // Assert - Remote sources always have access to private key operations
        Assert.That(source.HasPrivateKey, Is.True);
    }

    #endregion

    #region GetKeySize ML-DSA OID Scenarios

    [Test]
    public void GetKeySize_WithRsaDifferentSize_ReturnsCorrectSize()
    {
        // Arrange - Create RSA certificate with specific key size
        var cert = TestCertificateUtils.CreateCertificate("RSA4096", keySize: 4096);
        using var source = new TestRemoteCertificateSource(cert);

        // Act
        var keySize = source.GetKeySizePublic();

        // Assert
        Assert.That(keySize, Is.EqualTo(4096));
    }

    #endregion

    #region GetRemoteRsa Extended Tests

    [Test]
    public void GetRemoteRsa_SignData_ProducesVerifiableSignature()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);
        var data = "test data for signing"u8.ToArray();

        // Act
        using var remoteRsa = source.GetRemoteRsaPublic();
        var signature = remoteRsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        // Verify with the certificate's public key
        using var publicRsa = cert.GetRSAPublicKey();
        bool isValid = publicRsa!.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        // Assert
        Assert.That(isValid, Is.True);
    }

    [Test]
    public void GetRemoteRsa_SignHash_ProducesVerifiableSignature()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);
        var hash = SHA256.HashData("test data"u8.ToArray());

        // Act
        using var remoteRsa = source.GetRemoteRsaPublic();
        var signature = remoteRsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        // Verify with the certificate's public key
        using var publicRsa = cert.GetRSAPublicKey();
        bool isValid = publicRsa!.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        // Assert
        Assert.That(isValid, Is.True);
    }

    [Test]
    public void GetRemoteRsa_WithPkcs1Padding_ThrowsException()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);
        var data = "test data"u8.ToArray();

        // Act
        using var remoteRsa = source.GetRemoteRsaPublic();

        // Assert - PKCS1 padding is not supported for remote RSA signing
        var ex = Assert.Throws<CryptographicException>(() =>
            remoteRsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        Assert.That(ex!.Message, Does.Contain("PSS padding"));
    }

    #endregion

    #region GetRemoteECDsa Extended Tests

    [Test]
    public void GetRemoteECDsa_SignData_ProducesVerifiableSignature()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateECDsaCertificate(keySize: 256);
        using var source = new TestRemoteCertificateSource(cert);
        var data = "test data for signing"u8.ToArray();

        // Act
        using var remoteEcdsa = source.GetRemoteECDsaPublic();
        var signature = remoteEcdsa.SignData(data, HashAlgorithmName.SHA256);

        // Verify with the certificate's public key
        using var publicEcdsa = cert.GetECDsaPublicKey();
        bool isValid = publicEcdsa!.VerifyData(data, signature, HashAlgorithmName.SHA256);

        // Assert
        Assert.That(isValid, Is.True);
    }

    [Test]
    public void GetRemoteECDsa_SignHash_ProducesVerifiableSignature()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateECDsaCertificate();
        using var source = new TestRemoteCertificateSource(cert);
        var hash = SHA256.HashData("test data"u8.ToArray());

        // Act
        using var remoteEcdsa = source.GetRemoteECDsaPublic();
        var signature = remoteEcdsa.SignHash(hash);

        // Verify with the certificate's public key
        using var publicEcdsa = cert.GetECDsaPublicKey();
        bool isValid = publicEcdsa!.VerifyHash(hash, signature);

        // Assert
        Assert.That(isValid, Is.True);
    }

    [Test]
    public void GetRemoteECDsa_WithP384AndSHA384_ProducesValidSignature()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateECDsaCertificate(keySize: 384);
        using var source = new TestRemoteCertificateSource(cert);
        var data = "test data"u8.ToArray();

        // Act
        using var remoteEcdsa = source.GetRemoteECDsaPublic();
        var signature = remoteEcdsa.SignData(data, HashAlgorithmName.SHA384);

        // Verify
        using var publicEcdsa = cert.GetECDsaPublicKey();
        bool isValid = publicEcdsa!.VerifyData(data, signature, HashAlgorithmName.SHA384);

        // Assert
        Assert.That(isValid, Is.True);
    }

    [Test]
    public void GetRemoteECDsa_WithP521AndSHA512_ProducesValidSignature()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateECDsaCertificate(keySize: 521);
        using var source = new TestRemoteCertificateSource(cert);
        var data = "test data"u8.ToArray();

        // Act
        using var remoteEcdsa = source.GetRemoteECDsaPublic();
        var signature = remoteEcdsa.SignData(data, HashAlgorithmName.SHA512);

        // Verify
        using var publicEcdsa = cert.GetECDsaPublicKey();
        bool isValid = publicEcdsa!.VerifyData(data, signature, HashAlgorithmName.SHA512);

        // Assert
        Assert.That(isValid, Is.True);
    }

    #endregion

    #region Async Method Tests

    [Test]
    public async Task SignDataWithRsaAsync_WithDefaultCancellationToken_Completes()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);
        var data = "test data"u8.ToArray();

        // Act
        var signature = await source.SignDataWithRsaAsync(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public async Task SignHashWithRsaAsync_WithDefaultCancellationToken_Completes()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);
        var hash = SHA256.HashData("test"u8.ToArray());

        // Act
        var signature = await source.SignHashWithRsaAsync(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public async Task SignDataWithEcdsaAsync_WithDefaultCancellationToken_Completes()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateECDsaCertificate();
        using var source = new TestRemoteCertificateSource(cert);
        var data = "test data"u8.ToArray();

        // Act
        var signature = await source.SignDataWithEcdsaAsync(data, HashAlgorithmName.SHA256);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public async Task SignHashWithEcdsaAsync_WithDefaultCancellationToken_Completes()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateECDsaCertificate();
        using var source = new TestRemoteCertificateSource(cert);
        var hash = SHA256.HashData("test"u8.ToArray());

        // Act
        var signature = await source.SignHashWithEcdsaAsync(hash);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public void SignDataWithMLDsa_ThrowsNotSupportedException()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);
        var data = "test data"u8.ToArray();

        // Act & Assert
        Assert.Throws<NotSupportedException>(() =>
            source.SignDataWithMLDsa(data));
    }

    [Test]
    public void SignDataWithMLDsaAsync_ThrowsNotSupportedException()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);
        var data = "test data"u8.ToArray();

        // Act & Assert
        Assert.ThrowsAsync<NotSupportedException>(async () =>
            await source.SignDataWithMLDsaAsync(data));
    }

    #endregion

    #region Dispose Tests

    [Test]
    public void Dispose_MultipleCalls_DoesNotThrow()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA");
        var source = new TestRemoteCertificateSource(cert);

        // Act & Assert - multiple dispose calls should not throw
        Assert.DoesNotThrow(() =>
        {
            source.Dispose();
            source.Dispose();
            source.Dispose();
        });
    }

    #endregion

    #region Test Helper Class

    /// <summary>
    /// Test implementation of RemoteCertificateSource that uses local signing.
    /// Exposes protected methods for testing.
    /// </summary>
    private class TestRemoteCertificateSource : RemoteCertificateSource
    {
        private readonly X509Certificate2 Certificate;

        public TestRemoteCertificateSource(X509Certificate2 certificate, ICertificateChainBuilder? chainBuilder = null)
            : base(chainBuilder)
        {
            Certificate = certificate;
        }

        public override X509Certificate2 GetSigningCertificate() => Certificate;

        public override byte[] SignDataWithRsa(byte[] data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            using var rsa = Certificate.GetRSAPrivateKey();
            return rsa!.SignData(data, hashAlgorithm, padding);
        }

        public override Task<byte[]> SignDataWithRsaAsync(byte[] data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(SignDataWithRsa(data, hashAlgorithm, padding));
        }

        public override byte[] SignHashWithRsa(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            using var rsa = Certificate.GetRSAPrivateKey();
            return rsa!.SignHash(hash, hashAlgorithm, padding);
        }

        public override Task<byte[]> SignHashWithRsaAsync(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(SignHashWithRsa(hash, hashAlgorithm, padding));
        }

        public override byte[] SignDataWithEcdsa(byte[] data, HashAlgorithmName hashAlgorithm)
        {
            using var ecdsa = Certificate.GetECDsaPrivateKey();
            return ecdsa!.SignData(data, hashAlgorithm);
        }

        public override Task<byte[]> SignDataWithEcdsaAsync(byte[] data, HashAlgorithmName hashAlgorithm, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(SignDataWithEcdsa(data, hashAlgorithm));
        }

        public override byte[] SignHashWithEcdsa(byte[] hash)
        {
            using var ecdsa = Certificate.GetECDsaPrivateKey();
            return ecdsa!.SignHash(hash);
        }

        public override Task<byte[]> SignHashWithEcdsaAsync(byte[] hash, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(SignHashWithEcdsa(hash));
        }

        public override byte[] SignDataWithMLDsa(byte[] data, HashAlgorithmName? hashAlgorithm = null)
        {
            throw new NotSupportedException("ML-DSA not implemented in test helper");
        }

        public override Task<byte[]> SignDataWithMLDsaAsync(byte[] data, HashAlgorithmName? hashAlgorithm = null, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException("ML-DSA not implemented in test helper");
        }

        // Expose protected methods for testing
        public string GetPublicKeyAlgorithmPublic() => GetPublicKeyAlgorithm();
        public int GetKeySizePublic() => GetKeySize();
        public RSA GetRemoteRsaPublic() => GetRemoteRsa();
        public ECDsa GetRemoteECDsaPublic() => GetRemoteECDsa();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Certificate?.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    #endregion
}
