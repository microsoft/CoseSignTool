// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma warning disable SYSLIB5006 // ML-DSA APIs are marked as preview

namespace CoseSign1.Certificates.Tests.Remote;

using CoseSign1.Abstractions;
using CoseSign1.Certificates.Remote;
using CoseSign1.Tests.Common;
using Moq;

/// <summary>
/// Tests for ML-DSA (Post-Quantum Cryptography) support in Remote certificate classes.
/// These tests require .NET 10+ and Windows platform for ML-DSA support.
/// </summary>
[TestFixture]
[Category("MLDSA")]
[Category("PostQuantum")]
public class RemoteMlDsaCertificateTests
{
    private X509Certificate2? _mlDsaCert44;
    private X509Certificate2? _mlDsaCert65;
    private X509Certificate2? _mlDsaCert87;

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        PlatformHelper.SkipIfMLDsaNotSupported("ML-DSA tests require Windows platform");

        _mlDsaCert44 = TestCertificateUtils.CreateMLDsaCertificate("MLDSA44Test", mlDsaParameterSet: 44);
        _mlDsaCert65 = TestCertificateUtils.CreateMLDsaCertificate("MLDSA65Test", mlDsaParameterSet: 65);
        _mlDsaCert87 = TestCertificateUtils.CreateMLDsaCertificate("MLDSA87Test", mlDsaParameterSet: 87);
    }

    [OneTimeTearDown]
    public void OneTimeTearDown()
    {
        _mlDsaCert44?.Dispose();
        _mlDsaCert65?.Dispose();
        _mlDsaCert87?.Dispose();
    }

    #region RemoteCertificateSigningKey ML-DSA Metadata Tests

    [Test]
    public void Metadata_WithMLDsa44Certificate_ReturnsCorrectMetadata()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var source = new TestMLDsaRemoteCertificateSource(_mlDsaCert44!);
        var signingService = new Mock<ISigningService<SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var metadata = key.Metadata;

        // Assert
        Assert.That(metadata.KeyType, Is.EqualTo(CryptographicKeyType.MLDSA));
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-48)); // ML-DSA-44
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(44));
        Assert.That(metadata.IsRemote, Is.True);
    }

    [Test]
    public void Metadata_WithMLDsa65Certificate_ReturnsCorrectMetadata()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var source = new TestMLDsaRemoteCertificateSource(_mlDsaCert65!);
        var signingService = new Mock<ISigningService<SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var metadata = key.Metadata;

        // Assert
        Assert.That(metadata.KeyType, Is.EqualTo(CryptographicKeyType.MLDSA));
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-49)); // ML-DSA-65
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(65));
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA384));
    }

    [Test]
    public void Metadata_WithMLDsa87Certificate_ReturnsCorrectMetadata()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var source = new TestMLDsaRemoteCertificateSource(_mlDsaCert87!);
        var signingService = new Mock<ISigningService<SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var metadata = key.Metadata;

        // Assert
        Assert.That(metadata.KeyType, Is.EqualTo(CryptographicKeyType.MLDSA));
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-50)); // ML-DSA-87
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(87));
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA512));
    }

    [Test]
    public void Metadata_WithMLDsaCertificate_IncludesPublicKeyAlgorithmOid()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var source = new TestMLDsaRemoteCertificateSource(_mlDsaCert65!);
        var signingService = new Mock<ISigningService<SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var metadata = key.Metadata;

        // Assert
        Assert.That(metadata.AdditionalMetadata, Is.Not.Null);
        Assert.That(metadata.AdditionalMetadata, Contains.Key("PublicKeyAlgorithmOid"));
        var oid = metadata.AdditionalMetadata!["PublicKeyAlgorithmOid"] as string;
        Assert.That(oid, Does.StartWith("2.16.840.1.101.3.4.3.")); // ML-DSA OID prefix
    }

    #endregion

    #region RemoteCertificateSigningKey GetCoseKey ML-DSA Tests

    [Test]
    public void GetCoseKey_WithMLDsa44Certificate_ReturnsCoseKey()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var source = new TestMLDsaRemoteCertificateSource(_mlDsaCert44!);
        var signingService = new Mock<ISigningService<SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var coseKey = key.GetCoseKey();

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void GetCoseKey_WithMLDsa65Certificate_ReturnsCoseKey()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var source = new TestMLDsaRemoteCertificateSource(_mlDsaCert65!);
        var signingService = new Mock<ISigningService<SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var coseKey = key.GetCoseKey();

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void GetCoseKey_WithMLDsa87Certificate_ReturnsCoseKey()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var source = new TestMLDsaRemoteCertificateSource(_mlDsaCert87!);
        var signingService = new Mock<ISigningService<SigningOptions>>().Object;
        using var key = new RemoteCertificateSigningKey(source, signingService);

        // Act
        var coseKey = key.GetCoseKey();

        // Assert
        Assert.That(coseKey, Is.Not.Null);
    }

    #endregion

    #region RemoteCertificateSource GetRemoteMLDsa Tests

    [Test]
    public void GetRemoteMLDsa_WithMLDsa44Certificate_ReturnsMLDsaInstance()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var source = new TestMLDsaRemoteCertificateSource(_mlDsaCert44!);

        // Act
        using var remoteMlDsa = source.GetRemoteMLDsaPublic();

        // Assert
        Assert.That(remoteMlDsa, Is.Not.Null);
    }

    [Test]
    public void GetRemoteMLDsa_WithMLDsa65Certificate_ReturnsMLDsaInstance()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var source = new TestMLDsaRemoteCertificateSource(_mlDsaCert65!);

        // Act
        using var remoteMlDsa = source.GetRemoteMLDsaPublic();

        // Assert
        Assert.That(remoteMlDsa, Is.Not.Null);
    }

    [Test]
    public void GetRemoteMLDsa_WithMLDsa87Certificate_ReturnsMLDsaInstance()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var source = new TestMLDsaRemoteCertificateSource(_mlDsaCert87!);

        // Act
        using var remoteMlDsa = source.GetRemoteMLDsaPublic();

        // Assert
        Assert.That(remoteMlDsa, Is.Not.Null);
    }

    #endregion

    #region RemoteCertificateSource GetKeySize ML-DSA Tests

    [Test]
    public void GetKeySize_WithMLDsa44Certificate_Returns44()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var source = new TestMLDsaRemoteCertificateSource(_mlDsaCert44!);

        // Act
        var keySize = source.GetKeySizePublic();

        // Assert
        Assert.That(keySize, Is.EqualTo(44));
    }

    [Test]
    public void GetKeySize_WithMLDsa65Certificate_Returns65()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var source = new TestMLDsaRemoteCertificateSource(_mlDsaCert65!);

        // Act
        var keySize = source.GetKeySizePublic();

        // Assert
        Assert.That(keySize, Is.EqualTo(65));
    }

    [Test]
    public void GetKeySize_WithMLDsa87Certificate_Returns87()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var source = new TestMLDsaRemoteCertificateSource(_mlDsaCert87!);

        // Act
        var keySize = source.GetKeySizePublic();

        // Assert
        Assert.That(keySize, Is.EqualTo(87));
    }

    #endregion

    #region RemoteCertificateSource GetPublicKeyAlgorithm ML-DSA Tests

    [Test]
    public void GetPublicKeyAlgorithm_WithMLDsaCertificate_ReturnsMLDsaOid()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var source = new TestMLDsaRemoteCertificateSource(_mlDsaCert65!);

        // Act
        var algorithm = source.GetPublicKeyAlgorithmPublic();

        // Assert
        Assert.That(algorithm, Does.StartWith("2.16.840.1.101.3.4.3.")); // ML-DSA OID prefix
    }

    #endregion

    #region RemoteMLDsa Core Methods Tests

    [Test]
    public void SignData_WithMLDsa65_ReturnsValidSignature()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var source = new TestMLDsaRemoteCertificateSource(_mlDsaCert65!);
        using var remoteMlDsa = source.GetRemoteMLDsaPublic();
        var data = "Test data for signing"u8.ToArray();

        // Act
        var signature = remoteMlDsa.SignData(data);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public void SignData_WithMLDsa44_ReturnsValidSignature()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var source = new TestMLDsaRemoteCertificateSource(_mlDsaCert44!);
        using var remoteMlDsa = source.GetRemoteMLDsaPublic();
        var data = "Test data for signing with ML-DSA-44"u8.ToArray();

        // Act
        var signature = remoteMlDsa.SignData(data);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public void SignData_WithMLDsa87_ReturnsValidSignature()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var source = new TestMLDsaRemoteCertificateSource(_mlDsaCert87!);
        using var remoteMlDsa = source.GetRemoteMLDsaPublic();
        var data = "Test data for signing with ML-DSA-87"u8.ToArray();

        // Act
        var signature = remoteMlDsa.SignData(data);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public void VerifyData_ReturnsNotSupported_OrFalse()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var source = new TestMLDsaRemoteCertificateSource(_mlDsaCert65!);
        using var remoteMlDsa = source.GetRemoteMLDsaPublic();
        var data = "Test data"u8.ToArray();
        var signature = new byte[4627]; // ML-DSA-65 signature size

        // Act & Assert
        // Either throws NotSupportedException or returns false (depending on implementation path)
        try
        {
            var result = remoteMlDsa.VerifyData(data, signature);
            Assert.That(result, Is.False, "Verification with invalid signature should return false");
        }
        catch (NotSupportedException)
        {
            // This is also acceptable behavior for remote signing
            Assert.Pass("Verification threw NotSupportedException as expected");
        }
    }

    [Test]
    public void ExportMLDsaPublicKey_ReturnsPublicKey()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var source = new TestMLDsaRemoteCertificateSource(_mlDsaCert65!);
        using var remoteMlDsa = source.GetRemoteMLDsaPublic();

        // Act
        var publicKey = remoteMlDsa.ExportMLDsaPublicKey();

        // Assert
        Assert.That(publicKey, Is.Not.Null);
        Assert.That(publicKey.Length, Is.GreaterThan(0));
    }

    [Test]
    public void TryExportPkcs8PrivateKey_ThrowsCryptographicException()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var source = new TestMLDsaRemoteCertificateSource(_mlDsaCert65!);
        using var remoteMlDsa = source.GetRemoteMLDsaPublic();
        var destination = new byte[10000];

        // Act & Assert
        Assert.Throws<CryptographicException>(() => remoteMlDsa.TryExportPkcs8PrivateKey(destination, out _));
    }

    [Test]
    public void ExportMLDsaPrivateSeed_ThrowsCryptographicException()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var source = new TestMLDsaRemoteCertificateSource(_mlDsaCert65!);
        using var remoteMlDsa = source.GetRemoteMLDsaPublic();

        // Act & Assert
        Assert.Throws<CryptographicException>(() => remoteMlDsa.ExportMLDsaPrivateSeed());
    }

#if WINDOWS
    [Test]
    public void ExportMLDsaPrivateKey_ThrowsCryptographicException()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var source = new TestMLDsaRemoteCertificateSource(_mlDsaCert65!);
        using var remoteMlDsa = source.GetRemoteMLDsaPublic();

        // Act & Assert
        Assert.Throws<CryptographicException>(() => remoteMlDsa.ExportMLDsaPrivateKey());
    }
#endif

    [Test]
    public void Dispose_MultipleTimes_DoesNotThrow()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var source = new TestMLDsaRemoteCertificateSource(_mlDsaCert65!);
        var remoteMlDsa = source.GetRemoteMLDsaPublic();

        // Act & Assert
        Assert.DoesNotThrow(() =>
        {
            remoteMlDsa.Dispose();
            remoteMlDsa.Dispose(); // Second dispose should not throw
        });
    }

    #endregion

    #region Test Helper Class

    /// <summary>
    /// Test implementation of RemoteCertificateSource for ML-DSA certificates.
    /// </summary>
#pragma warning disable SYSLIB5006 // ML-DSA APIs are marked as preview
    private class TestMLDsaRemoteCertificateSource : RemoteCertificateSource
    {
        private readonly X509Certificate2 Certificate;

        public TestMLDsaRemoteCertificateSource(X509Certificate2 certificate)
            : base()
        {
            Certificate = certificate;
        }

        public override X509Certificate2 GetSigningCertificate() => Certificate;

        public override byte[] SignDataWithRsa(byte[] data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
            => throw new NotSupportedException("This is an ML-DSA certificate");

        public override Task<byte[]> SignDataWithRsaAsync(byte[] data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, CancellationToken cancellationToken = default)
            => throw new NotSupportedException("This is an ML-DSA certificate");

        public override byte[] SignHashWithRsa(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
            => throw new NotSupportedException("This is an ML-DSA certificate");

        public override Task<byte[]> SignHashWithRsaAsync(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, CancellationToken cancellationToken = default)
            => throw new NotSupportedException("This is an ML-DSA certificate");

        public override byte[] SignDataWithEcdsa(byte[] data, HashAlgorithmName hashAlgorithm)
            => throw new NotSupportedException("This is an ML-DSA certificate");

        public override Task<byte[]> SignDataWithEcdsaAsync(byte[] data, HashAlgorithmName hashAlgorithm, CancellationToken cancellationToken = default)
            => throw new NotSupportedException("This is an ML-DSA certificate");

        public override byte[] SignHashWithEcdsa(byte[] hash)
            => throw new NotSupportedException("This is an ML-DSA certificate");

        public override Task<byte[]> SignHashWithEcdsaAsync(byte[] hash, CancellationToken cancellationToken = default)
            => throw new NotSupportedException("This is an ML-DSA certificate");

        public override byte[] SignDataWithMLDsa(byte[] data, HashAlgorithmName? hashAlgorithm = null)
        {
            using var mlDsa = Certificate.GetMLDsaPrivateKey();
            return mlDsa!.SignData(data);
        }

        public override Task<byte[]> SignDataWithMLDsaAsync(byte[] data, HashAlgorithmName? hashAlgorithm = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(SignDataWithMLDsa(data, hashAlgorithm));
        }

        // Expose protected methods for testing
        public string GetPublicKeyAlgorithmPublic() => GetPublicKeyAlgorithm();
        public int GetKeySizePublic() => GetKeySize();
        public MLDsa GetRemoteMLDsaPublic() => GetRemoteMLDsa();

        protected override void Dispose(bool disposing)
        {
            // Don't dispose the certificate - it's managed by the test fixture
            base.Dispose(disposing);
        }
    }
#pragma warning restore SYSLIB5006

    #endregion
}
