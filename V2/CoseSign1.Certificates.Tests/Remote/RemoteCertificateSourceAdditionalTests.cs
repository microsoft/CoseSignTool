// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Remote;

using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Remote;

/// <summary>
/// Additional tests for RemoteCertificateSource to improve code coverage.
/// Focuses on error paths and edge cases.
/// </summary>
[TestFixture]
public class RemoteCertificateSourceAdditionalTests
{
    #region GetRemoteRsa Error Path Tests

    [Test]
    public void GetRemoteRsa_WithDifferentKeySizes_ReturnsCorrectKeySize()
    {
        // Arrange - Create RSA certificate with 3072 bit key
        var cert = TestCertificateUtils.CreateCertificate("RSA3072", keySize: 3072);
        using var source = new TestRemoteCertificateSource(cert);

        // Act
        using var remoteRsa = source.GetRemoteRsaPublic();

        // Assert
        Assert.That(remoteRsa.KeySize, Is.EqualTo(3072));
    }

    [Test]
    public void GetRemoteRsa_WithRsa4096_ReturnsCorrectKeySize()
    {
        // Arrange - Create RSA certificate with 4096 bit key
        var cert = TestCertificateUtils.CreateCertificate("RSA4096", keySize: 4096);
        using var source = new TestRemoteCertificateSource(cert);

        // Act
        using var remoteRsa = source.GetRemoteRsaPublic();

        // Assert
        Assert.That(remoteRsa.KeySize, Is.EqualTo(4096));
    }

    [Test]
    public void GetKeySize_WithRsa3072_Returns3072()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA3072", keySize: 3072);
        using var source = new TestRemoteCertificateSource(cert);

        // Act
        var keySize = source.GetKeySizePublic();

        // Assert
        Assert.That(keySize, Is.EqualTo(3072));
    }

    [Test]
    public void GetKeySize_WithRsa4096_Returns4096()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA4096", keySize: 4096);
        using var source = new TestRemoteCertificateSource(cert);

        // Act
        var keySize = source.GetKeySizePublic();

        // Assert
        Assert.That(keySize, Is.EqualTo(4096));
    }

    #endregion

    #region ChainBuilder Tests

    [Test]
    public void GetChainBuilder_ReturnsConfiguredBuilder()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("TestCert");
        using var source = new TestRemoteCertificateSource(cert);

        // Act
        var chainBuilder = source.GetChainBuilder();

        // Assert
        Assert.That(chainBuilder, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithCustomX509ChainBuilder_UsesProvidedBuilder()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("TestCert");
        var customChainBuilder = new X509ChainBuilder();

        // Act
        using var source = new TestRemoteCertificateSource(cert, customChainBuilder);
        var chainBuilder = source.GetChainBuilder();

        // Assert
        Assert.That(chainBuilder, Is.SameAs(customChainBuilder));
    }

    #endregion

    #region SignData Various Hash Algorithms

    [Test]
    public void SignDataWithRsa_WithSHA384_ProducesValidSignature()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA3072", keySize: 3072);
        using var source = new TestRemoteCertificateSource(cert);
        var data = "test data"u8.ToArray();

        // Act
        var signature = source.SignDataWithRsa(data, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);

        // Assert
        using var publicRsa = cert.GetRSAPublicKey();
        bool isValid = publicRsa!.VerifyData(data, signature, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
        Assert.That(isValid, Is.True);
    }

    [Test]
    public void SignDataWithRsa_WithSHA512_ProducesValidSignature()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA4096", keySize: 4096);
        using var source = new TestRemoteCertificateSource(cert);
        var data = "test data"u8.ToArray();

        // Act
        var signature = source.SignDataWithRsa(data, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);

        // Assert
        using var publicRsa = cert.GetRSAPublicKey();
        bool isValid = publicRsa!.VerifyData(data, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
        Assert.That(isValid, Is.True);
    }

    [Test]
    public void SignHashWithRsa_WithSHA384_ProducesValidSignature()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA3072", keySize: 3072);
        using var source = new TestRemoteCertificateSource(cert);
        var hash = SHA384.HashData("test data"u8.ToArray());

        // Act
        var signature = source.SignHashWithRsa(hash, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);

        // Assert
        using var publicRsa = cert.GetRSAPublicKey();
        bool isValid = publicRsa!.VerifyHash(hash, signature, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
        Assert.That(isValid, Is.True);
    }

    [Test]
    public void SignHashWithRsa_WithSHA512_ProducesValidSignature()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA4096", keySize: 4096);
        using var source = new TestRemoteCertificateSource(cert);
        var hash = SHA512.HashData("test data"u8.ToArray());

        // Act
        var signature = source.SignHashWithRsa(hash, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);

        // Assert
        using var publicRsa = cert.GetRSAPublicKey();
        bool isValid = publicRsa!.VerifyHash(hash, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
        Assert.That(isValid, Is.True);
    }

    #endregion

    #region Async Signing Methods With CancellationToken

    [Test]
    public async Task SignDataWithRsaAsync_WithCancellationToken_Completes()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);
        var data = "test data"u8.ToArray();
        using var cts = new CancellationTokenSource();

        // Act
        var signature = await source.SignDataWithRsaAsync(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss, cts.Token);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public async Task SignHashWithRsaAsync_WithCancellationToken_Completes()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);
        var hash = SHA256.HashData("test"u8.ToArray());
        using var cts = new CancellationTokenSource();

        // Act
        var signature = await source.SignHashWithRsaAsync(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss, cts.Token);

        // Assert
        Assert.That(signature, Is.Not.Null);
    }

    [Test]
    public async Task SignDataWithEcdsaAsync_WithCancellationToken_Completes()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateECDsaCertificate();
        using var source = new TestRemoteCertificateSource(cert);
        var data = "test data"u8.ToArray();
        using var cts = new CancellationTokenSource();

        // Act
        var signature = await source.SignDataWithEcdsaAsync(data, HashAlgorithmName.SHA256, cts.Token);

        // Assert
        Assert.That(signature, Is.Not.Null);
    }

    [Test]
    public async Task SignHashWithEcdsaAsync_WithCancellationToken_Completes()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateECDsaCertificate();
        using var source = new TestRemoteCertificateSource(cert);
        var hash = SHA256.HashData("test"u8.ToArray());
        using var cts = new CancellationTokenSource();

        // Act
        var signature = await source.SignHashWithEcdsaAsync(hash, cts.Token);

        // Assert
        Assert.That(signature, Is.Not.Null);
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
