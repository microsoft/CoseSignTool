// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Remote;

using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Remote;

[TestFixture]
[System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
public class RemoteRsaTests
{
    [Test]
    public void Constructor_WithValidParameters_CreatesInstance()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSATest", useEcc: false);
        using var source = new TestRemoteCertificateSource(cert);
        using var rsa = cert.GetRSAPublicKey()!;
        var parameters = rsa.ExportParameters(false);

        // Act
        using var remoteRsa = new RemoteRsa(source, parameters);

        // Assert
        Assert.That(remoteRsa, Is.Not.Null);
        Assert.That(remoteRsa.KeySize, Is.EqualTo(2048)); // Default RSA key size
    }

    [Test]
    public void Constructor_WithNullSource_ThrowsArgumentNullException()
    {
        // Arrange
        var parameters = new RSAParameters { Modulus = new byte[256] };

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new RemoteRsa(null!, parameters));
    }

    [Test]
    public void ExportParameters_WithIncludePrivateParametersFalse_ReturnsPublicParameters()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSAExportTest", useEcc: false);
        using var source = new TestRemoteCertificateSource(cert);
        using var rsa = cert.GetRSAPublicKey()!;
        var expectedParameters = rsa.ExportParameters(false);
        using var remoteRsa = new RemoteRsa(source, expectedParameters);

        // Act
        var exportedParams = remoteRsa.ExportParameters(false);

        // Assert
        Assert.That(exportedParams.Modulus, Is.EqualTo(expectedParameters.Modulus));
        Assert.That(exportedParams.Exponent, Is.EqualTo(expectedParameters.Exponent));
        Assert.That(exportedParams.D, Is.Null);
        Assert.That(exportedParams.P, Is.Null);
        Assert.That(exportedParams.Q, Is.Null);
    }

    [Test]
    public void ExportParameters_WithIncludePrivateParametersTrue_ThrowsCryptographicException()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSAExportPrivateTest", useEcc: false);
        using var source = new TestRemoteCertificateSource(cert);
        using var rsa = cert.GetRSAPublicKey()!;
        var parameters = rsa.ExportParameters(false);
        using var remoteRsa = new RemoteRsa(source, parameters);

        // Act & Assert
        var ex = Assert.Throws<CryptographicException>(() => remoteRsa.ExportParameters(true));
        Assert.That(ex!.Message, Does.Contain("Private key export is not supported"));
    }

    [Test]
    public void ImportParameters_ThrowsNotSupportedException()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSAImportTest", useEcc: false);
        using var source = new TestRemoteCertificateSource(cert);
        using var rsa = cert.GetRSAPublicKey()!;
        var parameters = rsa.ExportParameters(false);
        using var remoteRsa = new RemoteRsa(source, parameters);
        var newParameters = new RSAParameters();

        // Act & Assert
        var ex = Assert.Throws<NotSupportedException>(() => remoteRsa.ImportParameters(newParameters));
        Assert.That(ex!.Message, Does.Contain("Parameter import is not supported"));
    }

    [Test]
    public void SignHash_WithPssPadding_DelegatesToRemoteSource()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSASignTest", useEcc: false);
        using var source = new TestRemoteCertificateSource(cert);
        using var rsa = cert.GetRSAPublicKey()!;
        var parameters = rsa.ExportParameters(false);
        using var remoteRsa = new RemoteRsa(source, parameters);

        var data = new byte[] { 1, 2, 3, 4, 5 };
        var hash = SHA256.HashData(data);

        // Act
        var signature = remoteRsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));

        // Verify signature is valid
        using var publicRsa = cert.GetRSAPublicKey()!;
        bool isValid = publicRsa.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        Assert.That(isValid, Is.True);
    }

    [Test]
    public void SignHash_WithNonPssPadding_ThrowsCryptographicException()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSAPaddingTest", useEcc: false);
        using var source = new TestRemoteCertificateSource(cert);
        using var rsa = cert.GetRSAPublicKey()!;
        var parameters = rsa.ExportParameters(false);
        using var remoteRsa = new RemoteRsa(source, parameters);

        var hash = new byte[32];

        // Act & Assert
        var ex = Assert.Throws<CryptographicException>(() =>
            remoteRsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        Assert.That(ex!.Message, Does.Contain("Only PSS padding is supported"));
    }

    [Test]
    public void Decrypt_ThrowsNotSupportedException()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSADecryptTest", useEcc: false);
        using var source = new TestRemoteCertificateSource(cert);
        using var rsa = cert.GetRSAPublicKey()!;
        var parameters = rsa.ExportParameters(false);
        using var remoteRsa = new RemoteRsa(source, parameters);

        // Act & Assert
        var ex = Assert.Throws<NotSupportedException>(() =>
            remoteRsa.Decrypt(new byte[10], RSAEncryptionPadding.OaepSHA256));
        Assert.That(ex!.Message, Does.Contain("Decryption is not supported"));
    }

    [Test]
    public void Encrypt_ThrowsNotSupportedException()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSAEncryptTest", useEcc: false);
        using var source = new TestRemoteCertificateSource(cert);
        using var rsa = cert.GetRSAPublicKey()!;
        var parameters = rsa.ExportParameters(false);
        using var remoteRsa = new RemoteRsa(source, parameters);

        // Act & Assert
        var ex = Assert.Throws<NotSupportedException>(() =>
            remoteRsa.Encrypt(new byte[10], RSAEncryptionPadding.OaepSHA256));
        Assert.That(ex!.Message, Does.Contain("Encryption is not supported"));
    }

    [Test]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSADisposeTest", useEcc: false);
        using var source = new TestRemoteCertificateSource(cert);
        using var rsa = cert.GetRSAPublicKey()!;
        var parameters = rsa.ExportParameters(false);
        var remoteRsa = new RemoteRsa(source, parameters);

        // Act & Assert
        remoteRsa.Dispose();
        Assert.DoesNotThrow(() => remoteRsa.Dispose());
        Assert.DoesNotThrow(() => remoteRsa.Dispose());
    }

    [Test]
    public void KeySize_ReflectsModulusLength()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSAKeySizeTest", useEcc: false, keySize: 2048);
        using var source = new TestRemoteCertificateSource(cert);
        using var rsa = cert.GetRSAPublicKey()!;
        var parameters = rsa.ExportParameters(false);
        using var remoteRsa = new RemoteRsa(source, parameters);

        // Act & Assert
        Assert.That(remoteRsa.KeySize, Is.EqualTo(2048));
    }

    [Test]
    public void SignHash_WithDifferentHashAlgorithms_ProducesValidSignatures()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("RSAMultiHashTest", useEcc: false);
        using var source = new TestRemoteCertificateSource(cert);
        using var rsa = cert.GetRSAPublicKey()!;
        var parameters = rsa.ExportParameters(false);
        using var remoteRsa = new RemoteRsa(source, parameters);
        var data = new byte[] { 1, 2, 3, 4, 5 };

        // Act & Assert - SHA256
        var hash256 = SHA256.HashData(data);
        var sig256 = remoteRsa.SignHash(hash256, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        using var verifyRsa256 = cert.GetRSAPublicKey()!;
        Assert.That(verifyRsa256.VerifyHash(hash256, sig256, HashAlgorithmName.SHA256, RSASignaturePadding.Pss), Is.True);

        // Act & Assert - SHA384
        var hash384 = SHA384.HashData(data);
        var sig384 = remoteRsa.SignHash(hash384, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
        using var verifyRsa384 = cert.GetRSAPublicKey()!;
        Assert.That(verifyRsa384.VerifyHash(hash384, sig384, HashAlgorithmName.SHA384, RSASignaturePadding.Pss), Is.True);

        // Act & Assert - SHA512
        var hash512 = SHA512.HashData(data);
        var sig512 = remoteRsa.SignHash(hash512, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
        using var verifyRsa512 = cert.GetRSAPublicKey()!;
        Assert.That(verifyRsa512.VerifyHash(hash512, sig512, HashAlgorithmName.SHA512, RSASignaturePadding.Pss), Is.True);
    }

    // Test implementation of RemoteCertificateSource
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
            throw new NotSupportedException("ML-DSA not supported in this test helper");
        }

        public override Task<byte[]> SignDataWithMLDsaAsync(byte[] data, HashAlgorithmName? hashAlgorithm = null, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException("ML-DSA not supported in this test helper");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Certificate?.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
