// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Remote;
using CoseSign1.Tests.Common;

namespace CoseSign1.Certificates.Tests.Remote;

/// <summary>
/// Tests for RemoteCertificateSource protected methods and edge cases.
/// </summary>
[TestFixture]
public class RemoteCertificateSourceTests
{
    #region GetPublicKeyAlgorithm Tests

    [Test]
    public void GetPublicKeyAlgorithm_WithRsaCertificate_ReturnsRsaOid()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);

        // Act
        var algorithm = source.GetPublicKeyAlgorithmPublic();

        // Assert
        Assert.That(algorithm, Is.EqualTo("1.2.840.113549.1.1.1")); // RSA OID
    }

    [Test]
    public void GetPublicKeyAlgorithm_WithEcdsaCertificate_ReturnsEcdsaOid()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateECDsaCertificate();
        using var source = new TestRemoteCertificateSource(cert);

        // Act
        var algorithm = source.GetPublicKeyAlgorithmPublic();

        // Assert
        Assert.That(algorithm, Does.StartWith("1.2.840.10045.2.1")); // ECC OID
    }

    #endregion

    #region GetKeySize Tests

    [Test]
    public void GetKeySize_WithRsa2048Certificate_Returns2048()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA2048");
        using var source = new TestRemoteCertificateSource(cert);

        // Act
        var keySize = source.GetKeySizePublic();

        // Assert
        Assert.That(keySize, Is.EqualTo(2048));
    }

    [Test]
    public void GetKeySize_WithEcdsaP256Certificate_Returns256()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateECDsaCertificate(keySize: 256);
        using var source = new TestRemoteCertificateSource(cert);

        // Act
        var keySize = source.GetKeySizePublic();

        // Assert
        Assert.That(keySize, Is.EqualTo(256));
    }

    [Test]
    public void GetKeySize_WithEcdsaP384Certificate_Returns384()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateECDsaCertificate(keySize: 384);
        using var source = new TestRemoteCertificateSource(cert);

        // Act
        var keySize = source.GetKeySizePublic();

        // Assert
        Assert.That(keySize, Is.EqualTo(384));
    }

    [Test]
    public void GetKeySize_WithEcdsaP521Certificate_Returns521()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateECDsaCertificate(keySize: 521);
        using var source = new TestRemoteCertificateSource(cert);

        // Act
        var keySize = source.GetKeySizePublic();

        // Assert
        Assert.That(keySize, Is.EqualTo(521));
    }

    #endregion

    #region GetRemoteRsa Tests

    [Test]
    public void GetRemoteRsa_WithRsaCertificate_ReturnsRemoteRsaInstance()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);

        // Act
        using var remoteRsa = source.GetRemoteRsaPublic();

        // Assert
        Assert.That(remoteRsa, Is.Not.Null);
        Assert.That(remoteRsa, Is.InstanceOf<RSA>());
        Assert.That(remoteRsa.KeySize, Is.EqualTo(2048));
    }

    [Test]
    public void GetRemoteRsa_WithEcdsaCertificate_ThrowsInvalidOperationException()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateECDsaCertificate();
        using var source = new TestRemoteCertificateSource(cert);

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() => source.GetRemoteRsaPublic());
        Assert.That(ex!.Message, Does.Contain("RSA public key"));
    }

    [Test]
    public void GetRemoteRsa_CanExportParameters()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);

        // Act
        using var remoteRsa = source.GetRemoteRsaPublic();
        var parameters = remoteRsa.ExportParameters(includePrivateParameters: false);

        // Assert
        Assert.That(parameters.Modulus, Is.Not.Null);
        Assert.That(parameters.Exponent, Is.Not.Null);
        Assert.That(parameters.Modulus!.Length, Is.EqualTo(256)); // 2048 bits = 256 bytes
    }

    [Test]
    public void GetRemoteRsa_CanSignHash()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);
        var hash = SHA256.HashData("test"u8.ToArray());

        // Act
        using var remoteRsa = source.GetRemoteRsaPublic();
        var signature = remoteRsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    #endregion

    #region GetRemoteECDsa Tests

    [Test]
    public void GetRemoteECDsa_WithEcdsaCertificate_ReturnsRemoteECDsaInstance()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateECDsaCertificate();
        using var source = new TestRemoteCertificateSource(cert);

        // Act
        using var remoteEcdsa = source.GetRemoteECDsaPublic();

        // Assert
        Assert.That(remoteEcdsa, Is.Not.Null);
        Assert.That(remoteEcdsa, Is.InstanceOf<ECDsa>());
    }

    [Test]
    public void GetRemoteECDsa_WithRsaCertificate_ThrowsInvalidOperationException()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() => source.GetRemoteECDsaPublic());
        Assert.That(ex!.Message, Does.Contain("ECDsa public key"));
    }

    [Test]
    public void GetRemoteECDsa_WithP256_CanExportParameters()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateECDsaCertificate(keySize: 256);
        using var source = new TestRemoteCertificateSource(cert);

        // Act
        using var remoteEcdsa = source.GetRemoteECDsaPublic();
        var parameters = remoteEcdsa.ExportParameters(includePrivateParameters: false);

        // Assert
        Assert.That(parameters.Q.X, Is.Not.Null);
        Assert.That(parameters.Q.Y, Is.Not.Null);
        Assert.That(parameters.Curve.Oid.Value, Is.EqualTo("1.2.840.10045.3.1.7")); // P-256 OID
    }

    [Test]
    public void GetRemoteECDsa_WithP384_CanExportParameters()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateECDsaCertificate(keySize: 384);
        using var source = new TestRemoteCertificateSource(cert);

        // Act
        using var remoteEcdsa = source.GetRemoteECDsaPublic();
        var parameters = remoteEcdsa.ExportParameters(includePrivateParameters: false);

        // Assert
        Assert.That(parameters.Q.X, Is.Not.Null);
        Assert.That(parameters.Q.Y, Is.Not.Null);
        Assert.That(parameters.Curve.Oid.Value, Is.EqualTo("1.3.132.0.34")); // P-384 OID
    }

    [Test]
    public void GetRemoteECDsa_WithP521_CanExportParameters()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateECDsaCertificate(keySize: 521);
        using var source = new TestRemoteCertificateSource(cert);

        // Act
        using var remoteEcdsa = source.GetRemoteECDsaPublic();
        var parameters = remoteEcdsa.ExportParameters(includePrivateParameters: false);

        // Assert
        Assert.That(parameters.Q.X, Is.Not.Null);
        Assert.That(parameters.Q.Y, Is.Not.Null);
        Assert.That(parameters.Curve.Oid.Value, Is.EqualTo("1.3.132.0.35")); // P-521 OID
    }

    [Test]
    public void GetRemoteECDsa_CanSignHash()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateECDsaCertificate();
        using var source = new TestRemoteCertificateSource(cert);
        var hash = SHA256.HashData("test"u8.ToArray());

        // Act
        using var remoteEcdsa = source.GetRemoteECDsaPublic();
        var signature = remoteEcdsa.SignHash(hash);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public void GetRemoteECDsa_SignatureIsValid()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateECDsaCertificate();
        using var source = new TestRemoteCertificateSource(cert);
        var data = "test data"u8.ToArray();
        var hash = SHA256.HashData(data);

        // Act
        using var remoteEcdsa = source.GetRemoteECDsaPublic();
        var signature = remoteEcdsa.SignHash(hash);

        // Verify with the certificate's public key
        using var publicEcdsa = cert.GetECDsaPublicKey();
        bool isValid = publicEcdsa!.VerifyHash(hash, signature);

        // Assert
        Assert.That(isValid, Is.True);
    }

    #endregion

    #region Async Method Tests

    [Test]
    public async Task SignDataWithRsaAsync_WithCancellationToken_CompletesSuccessfully()
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
    public async Task SignHashWithRsaAsync_WithCancellationToken_CompletesSuccessfully()
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
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public async Task SignDataWithEcdsaAsync_WithCancellationToken_CompletesSuccessfully()
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
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public async Task SignHashWithEcdsaAsync_WithCancellationToken_CompletesSuccessfully()
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
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    #endregion

    #region Edge Cases

    [Test]
    public void GetRemoteRsa_MultipleCalls_ReturnsDifferentInstances()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);

        // Act
        using var rsa1 = source.GetRemoteRsaPublic();
        using var rsa2 = source.GetRemoteRsaPublic();

        // Assert
        Assert.That(rsa1, Is.Not.SameAs(rsa2));
    }

    [Test]
    public void GetRemoteECDsa_MultipleCalls_ReturnsDifferentInstances()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateECDsaCertificate();
        using var source = new TestRemoteCertificateSource(cert);

        // Act
        using var ecdsa1 = source.GetRemoteECDsaPublic();
        using var ecdsa2 = source.GetRemoteECDsaPublic();

        // Assert
        Assert.That(ecdsa1, Is.Not.SameAs(ecdsa2));
    }

    [Test]
    public void SignDataWithRsa_WithSHA384_ProducesValidSignature()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);
        var data = "test data"u8.ToArray();

        // Act
        var signature = source.SignDataWithRsa(data, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.EqualTo(256)); // 2048-bit RSA = 256 bytes
    }

    [Test]
    public void SignDataWithRsa_WithSHA512_ProducesValidSignature()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSA");
        using var source = new TestRemoteCertificateSource(cert);
        var data = "test data"u8.ToArray();

        // Act
        var signature = source.SignDataWithRsa(data, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.EqualTo(256)); // 2048-bit RSA = 256 bytes
    }

    [Test]
    public void SignDataWithEcdsa_WithSHA384_ProducesValidSignature()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateECDsaCertificate(keySize: 384);
        using var source = new TestRemoteCertificateSource(cert);
        var data = "test data"u8.ToArray();

        // Act
        var signature = source.SignDataWithEcdsa(data, HashAlgorithmName.SHA384);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public void SignDataWithEcdsa_WithSHA512_ProducesValidSignature()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateECDsaCertificate(keySize: 521);
        using var source = new TestRemoteCertificateSource(cert);
        var data = "test data"u8.ToArray();

        // Act
        var signature = source.SignDataWithEcdsa(data, HashAlgorithmName.SHA512);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    #endregion

    #region Test Helper Class

    /// <summary>
    /// Test implementation of RemoteCertificateSource that uses local signing.
    /// Exposes protected methods for testing.
    /// </summary>
    private class TestRemoteCertificateSource : RemoteCertificateSource
    {
        private readonly X509Certificate2 _certificate;

        public TestRemoteCertificateSource(X509Certificate2 certificate, ICertificateChainBuilder? chainBuilder = null)
            : base(chainBuilder)
        {
            _certificate = certificate;
        }

        public override X509Certificate2 GetSigningCertificate() => _certificate;

        public override byte[] SignDataWithRsa(byte[] data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            using var rsa = _certificate.GetRSAPrivateKey();
            return rsa!.SignData(data, hashAlgorithm, padding);
        }

        public override Task<byte[]> SignDataWithRsaAsync(byte[] data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(SignDataWithRsa(data, hashAlgorithm, padding));
        }

        public override byte[] SignHashWithRsa(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            using var rsa = _certificate.GetRSAPrivateKey();
            return rsa!.SignHash(hash, hashAlgorithm, padding);
        }

        public override Task<byte[]> SignHashWithRsaAsync(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(SignHashWithRsa(hash, hashAlgorithm, padding));
        }

        public override byte[] SignDataWithEcdsa(byte[] data, HashAlgorithmName hashAlgorithm)
        {
            using var ecdsa = _certificate.GetECDsaPrivateKey();
            return ecdsa!.SignData(data, hashAlgorithm);
        }

        public override Task<byte[]> SignDataWithEcdsaAsync(byte[] data, HashAlgorithmName hashAlgorithm, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(SignDataWithEcdsa(data, hashAlgorithm));
        }

        public override byte[] SignHashWithEcdsa(byte[] hash)
        {
            using var ecdsa = _certificate.GetECDsaPrivateKey();
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
                _certificate?.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    #endregion
}