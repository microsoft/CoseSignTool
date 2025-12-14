// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Local;
using CoseSign1.Certificates.Remote;
using NUnit.Framework;

#pragma warning disable CA2252 // Preview Features
#pragma warning disable SYSLIB5006 // ML-DSA APIs are marked as preview

namespace CoseSign1.Certificates.Tests.Remote;

[TestFixture]
public class RemoteMLDsaTests
{
    [Test]
    public void Constructor_WithMLDsa44_CreatesInstance()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        using var cert = factory.CreateCertificate(o => o
            .WithKeyAlgorithm(KeyAlgorithm.MLDSA)
            .WithKeySize(44));

        using var source = new TestMLDsaRemoteCertificateSource(cert);
        using var mldsa = cert.GetMLDsaPrivateKey();
        var publicKey = new byte[mldsa!.Algorithm.PublicKeySizeInBytes];
        mldsa.ExportMLDsaPublicKey(publicKey);

        // Act
        using var remoteMLDsa = new RemoteMLDsa(source, publicKey, 44);

        // Assert
        Assert.That(remoteMLDsa, Is.Not.Null);
        Assert.That(remoteMLDsa.Algorithm, Is.EqualTo(MLDsaAlgorithm.MLDsa44));
    }

    [Test]
    public void Constructor_WithMLDsa65_CreatesInstance()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        using var cert = factory.CreateCertificate(o => o
            .WithKeyAlgorithm(KeyAlgorithm.MLDSA)
            .WithKeySize(65));

        using var source = new TestMLDsaRemoteCertificateSource(cert);
        using var mldsa = cert.GetMLDsaPrivateKey();
        var publicKey = new byte[mldsa!.Algorithm.PublicKeySizeInBytes];
        mldsa.ExportMLDsaPublicKey(publicKey);

        // Act
        using var remoteMLDsa = new RemoteMLDsa(source, publicKey, 65);

        // Assert
        Assert.That(remoteMLDsa, Is.Not.Null);
        Assert.That(remoteMLDsa.Algorithm, Is.EqualTo(MLDsaAlgorithm.MLDsa65));
    }

    [Test]
    public void Constructor_WithMLDsa87_CreatesInstance()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        using var cert = factory.CreateCertificate(o => o
            .WithKeyAlgorithm(KeyAlgorithm.MLDSA)
            .WithKeySize(87));

        using var source = new TestMLDsaRemoteCertificateSource(cert);
        using var mldsa = cert.GetMLDsaPrivateKey();
        var publicKey = new byte[mldsa!.Algorithm.PublicKeySizeInBytes];
        mldsa.ExportMLDsaPublicKey(publicKey);

        // Act
        using var remoteMLDsa = new RemoteMLDsa(source, publicKey, 87);

        // Assert
        Assert.That(remoteMLDsa, Is.Not.Null);
        Assert.That(remoteMLDsa.Algorithm, Is.EqualTo(MLDsaAlgorithm.MLDsa87));
    }

    [Test]
    public void Constructor_WithNullSource_ThrowsArgumentNullException()
    {
        // Arrange
        var publicKey = new byte[1312]; // ML-DSA-44 public key size

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new RemoteMLDsa(null!, publicKey, 44));
    }

    [Test]
    public void Constructor_WithNullPublicKey_ThrowsArgumentNullException()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        using var cert = factory.CreateCertificate(o => o
            .WithKeyAlgorithm(KeyAlgorithm.MLDSA)
            .WithKeySize(44));
        using var source = new TestMLDsaRemoteCertificateSource(cert);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new RemoteMLDsa(source, null!, 44));
    }

    [Test]
    public void SignData_DelegatesToRemoteSource()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        using var cert = factory.CreateCertificate(o => o
            .WithKeyAlgorithm(KeyAlgorithm.MLDSA)
            .WithKeySize(44));

        using var source = new TestMLDsaRemoteCertificateSource(cert);
        using var mldsa = cert.GetMLDsaPrivateKey();
        var publicKey = new byte[mldsa!.Algorithm.PublicKeySizeInBytes];
        mldsa.ExportMLDsaPublicKey(publicKey);

        using var remoteMLDsa = new RemoteMLDsa(source, publicKey, 44);
        var data = "Test data"u8.ToArray();

        // Act
        var signature = remoteMLDsa.SignData(data);

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature, Has.Length.GreaterThan(0));
        Assert.That(source.SignDataCalled, Is.True);
    }

    [Test]
    public void SignPreHash_WithSHA256_DelegatesToRemoteSource()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        using var cert = factory.CreateCertificate(o => o
            .WithKeyAlgorithm(KeyAlgorithm.MLDSA)
            .WithKeySize(44));

        using var source = new TestMLDsaRemoteCertificateSource(cert);
        using var mldsa = cert.GetMLDsaPrivateKey();
        var publicKey = new byte[mldsa!.Algorithm.PublicKeySizeInBytes];
        mldsa.ExportMLDsaPublicKey(publicKey);

        using var remoteMLDsa = new RemoteMLDsa(source, publicKey, 44);
        var hash = SHA256.HashData("Test data"u8.ToArray());

        // Act - Use OID for SHA256 (2.16.840.1.101.3.4.2.1)
        var signature = remoteMLDsa.SignPreHash(hash, "2.16.840.1.101.3.4.2.1");

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature, Has.Length.GreaterThan(0));
        Assert.That(source.SignDataCalled, Is.True);
    }

    [Test]
    public void SignPreHash_WithSHA384_DelegatesToRemoteSource()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        using var cert = factory.CreateCertificate(o => o
            .WithKeyAlgorithm(KeyAlgorithm.MLDSA)
            .WithKeySize(65));

        using var source = new TestMLDsaRemoteCertificateSource(cert);
        using var mldsa = cert.GetMLDsaPrivateKey();
        var publicKey = new byte[mldsa!.Algorithm.PublicKeySizeInBytes];
        mldsa.ExportMLDsaPublicKey(publicKey);

        using var remoteMLDsa = new RemoteMLDsa(source, publicKey, 65);
        var hash = SHA384.HashData("Test data"u8.ToArray());

        // Act - Use OID for SHA384 (2.16.840.1.101.3.4.2.2)
        var signature = remoteMLDsa.SignPreHash(hash, "2.16.840.1.101.3.4.2.2");

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature, Has.Length.GreaterThan(0));
        Assert.That(source.SignDataCalled, Is.True);
    }

    [Test]
    public void SignPreHash_WithSHA512_DelegatesToRemoteSource()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        using var cert = factory.CreateCertificate(o => o
            .WithKeyAlgorithm(KeyAlgorithm.MLDSA)
            .WithKeySize(87));

        using var source = new TestMLDsaRemoteCertificateSource(cert);
        using var mldsa = cert.GetMLDsaPrivateKey();
        var publicKey = new byte[mldsa!.Algorithm.PublicKeySizeInBytes];
        mldsa.ExportMLDsaPublicKey(publicKey);

        using var remoteMLDsa = new RemoteMLDsa(source, publicKey, 87);
        var hash = SHA512.HashData("Test data"u8.ToArray());

        // Act - Use OID for SHA512 (2.16.840.1.101.3.4.2.3)
        var signature = remoteMLDsa.SignPreHash(hash, "2.16.840.1.101.3.4.2.3");

        // Assert
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature, Has.Length.GreaterThan(0));
        Assert.That(source.SignDataCalled, Is.True);
    }

    [Test]
    public void ExportMLDsaPublicKey_ReturnsPublicKey()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        using var cert = factory.CreateCertificate(o => o
            .WithKeyAlgorithm(KeyAlgorithm.MLDSA)
            .WithKeySize(44));

        using var source = new TestMLDsaRemoteCertificateSource(cert);
        using var mldsa = cert.GetMLDsaPrivateKey();
        var publicKey = new byte[mldsa!.Algorithm.PublicKeySizeInBytes];
        mldsa.ExportMLDsaPublicKey(publicKey);

        using var remoteMLDsa = new RemoteMLDsa(source, publicKey, 44);

        // Act
        var exportedKey = new byte[remoteMLDsa.Algorithm.PublicKeySizeInBytes];
        remoteMLDsa.ExportMLDsaPublicKey(exportedKey);

        // Assert
        Assert.That(exportedKey, Is.EqualTo(publicKey));
    }

    [Test]
    public void ExportMLDsaPrivateKey_ThrowsCryptographicException()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        using var cert = factory.CreateCertificate(o => o
            .WithKeyAlgorithm(KeyAlgorithm.MLDSA)
            .WithKeySize(44));

        using var source = new TestMLDsaRemoteCertificateSource(cert);
        using var mldsa = cert.GetMLDsaPrivateKey();
        var publicKey = new byte[mldsa!.Algorithm.PublicKeySizeInBytes];
        mldsa.ExportMLDsaPublicKey(publicKey);

        using var remoteMLDsa = new RemoteMLDsa(source, publicKey, 44);
        var destination = new byte[remoteMLDsa.Algorithm.PrivateKeySizeInBytes];

        // Act & Assert
        Assert.Throws<CryptographicException>(() => remoteMLDsa.ExportMLDsaPrivateKey(destination));
    }

    [Test]
    public void ExportMLDsaPrivateSeed_ThrowsCryptographicException()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        using var cert = factory.CreateCertificate(o => o
            .WithKeyAlgorithm(KeyAlgorithm.MLDSA)
            .WithKeySize(44));

        using var source = new TestMLDsaRemoteCertificateSource(cert);
        using var mldsa = cert.GetMLDsaPrivateKey();
        var publicKey = new byte[mldsa!.Algorithm.PublicKeySizeInBytes];
        mldsa.ExportMLDsaPublicKey(publicKey);

        using var remoteMLDsa = new RemoteMLDsa(source, publicKey, 44);
        var destination = new byte[32]; // Seed size

        // Act & Assert
        Assert.Throws<CryptographicException>(() => remoteMLDsa.ExportMLDsaPrivateSeed(destination));
    }

    [Test]
    public void TryExportPkcs8PrivateKey_ThrowsCryptographicException()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        using var cert = factory.CreateCertificate(o => o
            .WithKeyAlgorithm(KeyAlgorithm.MLDSA)
            .WithKeySize(44));

        using var source = new TestMLDsaRemoteCertificateSource(cert);
        using var mldsa = cert.GetMLDsaPrivateKey();
        var publicKey = new byte[mldsa!.Algorithm.PublicKeySizeInBytes];
        mldsa.ExportMLDsaPublicKey(publicKey);

        using var remoteMLDsa = new RemoteMLDsa(source, publicKey, 44);
        var destination = new byte[10000];

        // Act & Assert
        Assert.Throws<CryptographicException>(() => remoteMLDsa.TryExportPkcs8PrivateKey(destination, out _));
    }

    [Test]
    public void VerifyData_ThrowsNotSupportedException()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        using var cert = factory.CreateCertificate(o => o
            .WithKeyAlgorithm(KeyAlgorithm.MLDSA)
            .WithKeySize(44));

        using var source = new TestMLDsaRemoteCertificateSource(cert);
        using var mldsa = cert.GetMLDsaPrivateKey();
        var publicKey = new byte[mldsa!.Algorithm.PublicKeySizeInBytes];
        mldsa.ExportMLDsaPublicKey(publicKey);

        using var remoteMLDsa = new RemoteMLDsa(source, publicKey, 44);
        var data = "Test data"u8.ToArray();
        var signature = new byte[remoteMLDsa.Algorithm.SignatureSizeInBytes];

        // Act & Assert
        Assert.Throws<NotSupportedException>(() => remoteMLDsa.VerifyData(data, signature));
    }

    [Test]
    public void VerifyPreHash_ThrowsNotSupportedException()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        using var cert = factory.CreateCertificate(o => o
            .WithKeyAlgorithm(KeyAlgorithm.MLDSA)
            .WithKeySize(44));

        using var source = new TestMLDsaRemoteCertificateSource(cert);
        using var mldsa = cert.GetMLDsaPrivateKey();
        var publicKey = new byte[mldsa!.Algorithm.PublicKeySizeInBytes];
        mldsa.ExportMLDsaPublicKey(publicKey);

        using var remoteMLDsa = new RemoteMLDsa(source, publicKey, 44);
        var hash = SHA256.HashData("Test data"u8.ToArray());
        var signature = new byte[remoteMLDsa.Algorithm.SignatureSizeInBytes];

        // Act & Assert - Use OID for SHA256 (2.16.840.1.101.3.4.2.1)
        Assert.Throws<NotSupportedException>(() => remoteMLDsa.VerifyPreHash(hash, signature, "2.16.840.1.101.3.4.2.1"));
    }

    [Test]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        // Arrange
        var factory = new EphemeralCertificateFactory();
        using var cert = factory.CreateCertificate(o => o
            .WithKeyAlgorithm(KeyAlgorithm.MLDSA)
            .WithKeySize(44));

        using var source = new TestMLDsaRemoteCertificateSource(cert);
        using var mldsa = cert.GetMLDsaPrivateKey();
        var publicKey = new byte[mldsa!.Algorithm.PublicKeySizeInBytes];
        mldsa.ExportMLDsaPublicKey(publicKey);

        var remoteMLDsa = new RemoteMLDsa(source, publicKey, 44);

        // Act & Assert - should not throw
        Assert.DoesNotThrow(() =>
        {
            remoteMLDsa.Dispose();
            remoteMLDsa.Dispose();
            remoteMLDsa.Dispose();
        });
    }

    /// <summary>
    /// Test implementation of RemoteCertificateSource for ML-DSA testing.
    /// </summary>
    private sealed class TestMLDsaRemoteCertificateSource : RemoteCertificateSource
    {
        private readonly X509Certificate2 Certificate;
        public bool SignDataCalled { get; private set; }

        public TestMLDsaRemoteCertificateSource(X509Certificate2 certificate)
            : base(null)
        {
            Certificate = certificate;
        }

        public override X509Certificate2 GetSigningCertificate() => Certificate;

        public override byte[] SignDataWithRsa(byte[] data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
            => throw new NotSupportedException("RSA not supported in ML-DSA test helper");

        public override Task<byte[]> SignDataWithRsaAsync(byte[] data, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, CancellationToken cancellationToken = default)
            => throw new NotSupportedException("RSA not supported in ML-DSA test helper");

        public override byte[] SignHashWithRsa(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
            => throw new NotSupportedException("RSA not supported in ML-DSA test helper");

        public override Task<byte[]> SignHashWithRsaAsync(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, CancellationToken cancellationToken = default)
            => throw new NotSupportedException("RSA not supported in ML-DSA test helper");

        public override byte[] SignDataWithEcdsa(byte[] data, HashAlgorithmName hashAlgorithm)
            => throw new NotSupportedException("ECDSA not supported in ML-DSA test helper");

        public override Task<byte[]> SignDataWithEcdsaAsync(byte[] data, HashAlgorithmName hashAlgorithm, CancellationToken cancellationToken = default)
            => throw new NotSupportedException("ECDSA not supported in ML-DSA test helper");

        public override byte[] SignHashWithEcdsa(byte[] hash)
            => throw new NotSupportedException("ECDSA not supported in ML-DSA test helper");

        public override Task<byte[]> SignHashWithEcdsaAsync(byte[] hash, CancellationToken cancellationToken = default)
            => throw new NotSupportedException("ECDSA not supported in ML-DSA test helper");

        public override byte[] SignDataWithMLDsa(byte[] data, HashAlgorithmName? hashAlgorithm = null)
        {
            SignDataCalled = true;
            using var mldsa = Certificate.GetMLDsaPrivateKey();
            return mldsa!.SignData(data);
        }

        public override Task<byte[]> SignDataWithMLDsaAsync(byte[] data, HashAlgorithmName? hashAlgorithm = null, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(SignDataWithMLDsa(data, hashAlgorithm));
        }

        protected override void Dispose(bool disposing)
        {
            // Don't dispose the certificate - it's owned by the test
            base.Dispose(disposing);
        }
    }
}

#pragma warning restore SYSLIB5006
#pragma warning restore CA2252