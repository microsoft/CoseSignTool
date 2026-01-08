// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Remote;

namespace CoseSign1.Certificates.Tests.Remote;

[TestFixture]
[System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
public class RemoteECDsaTests
{
    [Test]
    public void Constructor_WithValidParameters_CreatesInstance()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("ECTest", useEcc: true);
        using var source = new TestRemoteCertificateSource(cert);
        using var ecdsa = cert.GetECDsaPublicKey()!;
        var parameters = ecdsa.ExportParameters(false);

        // Act
        using var remoteEcdsa = new RemoteECDsa(source, parameters);

        // Assert
        Assert.That(remoteEcdsa, Is.Not.Null);
        Assert.That(remoteEcdsa.KeySize, Is.EqualTo(256)); // Default EC key size
    }

    [Test]
    public void Constructor_WithNullSource_ThrowsArgumentNullException()
    {
        // Arrange
        var parameters = new ECParameters { Curve = ECCurve.NamedCurves.nistP256 };

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new RemoteECDsa(null!, parameters));
    }

    [Test]
    public void ExportParameters_WithIncludePrivateParametersFalse_ReturnsPublicParameters()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("ECExportTest", useEcc: true);
        using var source = new TestRemoteCertificateSource(cert);
        using var ecdsa = cert.GetECDsaPublicKey()!;
        var expectedParameters = ecdsa.ExportParameters(false);
        using var remoteEcdsa = new RemoteECDsa(source, expectedParameters);

        // Act
        var exportedParams = remoteEcdsa.ExportParameters(false);

        // Assert
        Assert.That(exportedParams.Q.X, Is.EqualTo(expectedParameters.Q.X));
        Assert.That(exportedParams.Q.Y, Is.EqualTo(expectedParameters.Q.Y));
        Assert.That(exportedParams.D, Is.Null);
    }

    [Test]
    public void ExportParameters_WithIncludePrivateParametersTrue_ThrowsCryptographicException()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("ECExportPrivateTest", useEcc: true);
        using var source = new TestRemoteCertificateSource(cert);
        using var ecdsa = cert.GetECDsaPublicKey()!;
        var parameters = ecdsa.ExportParameters(false);
        using var remoteEcdsa = new RemoteECDsa(source, parameters);

        // Act & Assert
        var ex = Assert.Throws<CryptographicException>(() => remoteEcdsa.ExportParameters(true));
        Assert.That(ex!.Message, Does.Contain("Private key export is not supported"));
    }

    [Test]
    public void ImportParameters_ThrowsNotSupportedException()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("ECImportTest", useEcc: true);
        using var source = new TestRemoteCertificateSource(cert);
        using var ecdsa = cert.GetECDsaPublicKey()!;
        var parameters = ecdsa.ExportParameters(false);
        using var remoteEcdsa = new RemoteECDsa(source, parameters);
        var newParameters = new ECParameters();

        // Act & Assert
        var ex = Assert.Throws<NotSupportedException>(() => remoteEcdsa.ImportParameters(newParameters));
        Assert.That(ex!.Message, Does.Contain("Parameter import is not supported"));
    }

    [Test]
    public void SignHash_DelegatesToRemoteSource()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("ECSignTest", useEcc: true);
        using var source = new TestRemoteCertificateSource(cert);
        using var ecdsa = cert.GetECDsaPublicKey()!;
        var parameters = ecdsa.ExportParameters(false);
        using var remoteEcdsa = new RemoteECDsa(source, parameters);

        var data = new byte[] { 1, 2, 3, 4, 5 };
        var hash = SHA256.HashData(data);

        // Act
        var signature = remoteEcdsa.SignHash(hash);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));

        // Verify signature is valid
        using var publicEcdsa = cert.GetECDsaPublicKey()!;
        bool isValid = publicEcdsa.VerifyHash(hash, signature);
        Assert.That(isValid, Is.True);
    }

    [Test]
    public void SignHash_WithSHA256Hash_ProducesValidSignature()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("ECSHA256Test", useEcc: true);
        using var source = new TestRemoteCertificateSource(cert);
        using var ecdsa = cert.GetECDsaPublicKey()!;
        var parameters = ecdsa.ExportParameters(false);
        using var remoteEcdsa = new RemoteECDsa(source, parameters);

        var hash = new byte[32]; // SHA256 hash length
        RandomNumberGenerator.Fill(hash);

        // Act
        var signature = remoteEcdsa.SignHash(hash);

        // Assert
        using var verifyEcdsa = cert.GetECDsaPublicKey()!;
        Assert.That(verifyEcdsa.VerifyHash(hash, signature), Is.True);
    }

    [Test]
    public void SignHash_WithSHA384Hash_ProducesValidSignature()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("ECSHA384Test", useEcc: true, keySize: 384);
        using var source = new TestRemoteCertificateSource(cert);
        using var ecdsa = cert.GetECDsaPublicKey()!;
        var parameters = ecdsa.ExportParameters(false);
        using var remoteEcdsa = new RemoteECDsa(source, parameters);

        var hash = new byte[48]; // SHA384 hash length
        RandomNumberGenerator.Fill(hash);

        // Act
        var signature = remoteEcdsa.SignHash(hash);

        // Assert
        using var verifyEcdsa = cert.GetECDsaPublicKey()!;
        Assert.That(verifyEcdsa.VerifyHash(hash, signature), Is.True);
    }

    [Test]
    public void SignHash_WithSHA512Hash_ProducesValidSignature()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("ECSHA512Test", useEcc: true, keySize: 521);
        using var source = new TestRemoteCertificateSource(cert);
        using var ecdsa = cert.GetECDsaPublicKey()!;
        var parameters = ecdsa.ExportParameters(false);
        using var remoteEcdsa = new RemoteECDsa(source, parameters);

        var hash = new byte[64]; // SHA512 hash length
        RandomNumberGenerator.Fill(hash);

        // Act
        var signature = remoteEcdsa.SignHash(hash);

        // Assert
        using var verifyEcdsa = cert.GetECDsaPublicKey()!;
        Assert.That(verifyEcdsa.VerifyHash(hash, signature), Is.True);
    }

    [Test]
    public void VerifyHash_ThrowsNotSupportedException()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("ECVerifyTest", useEcc: true);
        using var source = new TestRemoteCertificateSource(cert);
        using var ecdsa = cert.GetECDsaPublicKey()!;
        var parameters = ecdsa.ExportParameters(false);
        using var remoteEcdsa = new RemoteECDsa(source, parameters);

        // Act & Assert
        var ex = Assert.Throws<NotSupportedException>(() =>
            remoteEcdsa.VerifyHash(new byte[32], new byte[64]));
        Assert.That(ex!.Message, Does.Contain("Verification should be performed using public key directly"));
    }

    [Test]
    public void GenerateKey_ThrowsNotSupportedException()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("ECGenerateTest", useEcc: true);
        using var source = new TestRemoteCertificateSource(cert);
        using var ecdsa = cert.GetECDsaPublicKey()!;
        var parameters = ecdsa.ExportParameters(false);
        using var remoteEcdsa = new RemoteECDsa(source, parameters);

        // Act & Assert
        var ex = Assert.Throws<NotSupportedException>(() =>
            remoteEcdsa.GenerateKey(ECCurve.NamedCurves.nistP256));
        Assert.That(ex!.Message, Does.Contain("Key generation is not supported"));
    }

    [Test]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("ECDisposeTest", useEcc: true);
        using var source = new TestRemoteCertificateSource(cert);
        using var ecdsa = cert.GetECDsaPublicKey()!;
        var parameters = ecdsa.ExportParameters(false);
        var remoteEcdsa = new RemoteECDsa(source, parameters);

        // Act & Assert
        remoteEcdsa.Dispose();
        Assert.DoesNotThrow(() => remoteEcdsa.Dispose());
        Assert.DoesNotThrow(() => remoteEcdsa.Dispose());
    }

    [Test]
    public void KeySize_ReflectsCurveSize_P256()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("ECP256Test", useEcc: true, keySize: 256);
        using var source = new TestRemoteCertificateSource(cert);
        using var ecdsa = cert.GetECDsaPublicKey()!;
        var parameters = ecdsa.ExportParameters(false);
        using var remoteEcdsa = new RemoteECDsa(source, parameters);

        // Act & Assert
        Assert.That(remoteEcdsa.KeySize, Is.EqualTo(256));
    }

    [Test]
    [Platform("Win")]  // P-384 curve handling may differ on Linux
    public void KeySize_ReflectsCurveSize_P384()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("ECP384Test", useEcc: true, keySize: 384);
        using var source = new TestRemoteCertificateSource(cert);
        using var ecdsa = cert.GetECDsaPublicKey()!;
        var parameters = ecdsa.ExportParameters(false);
        using var remoteEcdsa = new RemoteECDsa(source, parameters);

        // Act & Assert
        Assert.That(remoteEcdsa.KeySize, Is.EqualTo(384));
    }

    [Test]
    [Platform("Win")]  // P-521 curve handling may differ on Linux
    public void KeySize_ReflectsCurveSize_P521()
    {
        // Arrange
        var cert = TestCertificateUtils.CreateCertificate("ECP521Test", useEcc: true, keySize: 521);
        using var source = new TestRemoteCertificateSource(cert);
        using var ecdsa = cert.GetECDsaPublicKey()!;
        var parameters = ecdsa.ExportParameters(false);
        using var remoteEcdsa = new RemoteECDsa(source, parameters);

        // Act & Assert
        Assert.That(remoteEcdsa.KeySize, Is.EqualTo(521));
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
