// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Remote;
using CoseSign1.Tests.Common;
using NUnit.Framework;

namespace CoseSign1.Certificates.Tests.Remote;

[TestFixture]
[System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
public class RemoteSigningTests
{
    [Test]
    public void RemoteCertificateSource_HasPrivateKey_AlwaysReturnsTrue()
    {
        var cert = TestCertificateUtils.CreateCertificate("RemoteTest");
        using var source = new TestRemoteCertificateSource(cert);

        Assert.That(source.HasPrivateKey, Is.True);
    }

    [Test]
    public void RemoteCertificateSource_Constructor_WithDefaultChainBuilder_CreatesInstance()
    {
        var cert = TestCertificateUtils.CreateCertificate("RemoteTest");
        using var source = new TestRemoteCertificateSource(cert);

        Assert.That(source, Is.Not.Null);
    }

    [Test]
    public void RemoteCertificateSource_Constructor_WithCustomChainBuilder_UsesCustomBuilder()
    {
        var customBuilder = new X509ChainBuilder();
        var cert = TestCertificateUtils.CreateCertificate("Test");
        using var source = new TestRemoteCertificateSource(cert, customBuilder);

        Assert.That(source, Is.Not.Null);
    }

    [Test]
    public void RemoteCertificateSource_SignDataWithRsa_ValidData_ReturnsSignature()
    {
        var cert = TestCertificateUtils.CreateCertificate("RSATest");
        using var source = new TestRemoteCertificateSource(cert);
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var signature = source.SignDataWithRsa(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public async Task RemoteCertificateSource_SignDataWithRsaAsync_ValidData_ReturnsSignature()
    {
        var cert = TestCertificateUtils.CreateCertificate("RSATest");
        using var source = new TestRemoteCertificateSource(cert);
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var signature = await source.SignDataWithRsaAsync(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public void RemoteCertificateSource_SignHashWithRsa_ValidHash_ReturnsSignature()
    {
        var cert = TestCertificateUtils.CreateCertificate("RSATest");
        using var source = new TestRemoteCertificateSource(cert);
        var hash = SHA256.HashData(new byte[] { 1, 2, 3 });
        var signature = source.SignHashWithRsa(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public async Task RemoteCertificateSource_SignHashWithRsaAsync_ValidHash_ReturnsSignature()
    {
        var cert = TestCertificateUtils.CreateCertificate("RSATest");
        using var source = new TestRemoteCertificateSource(cert);
        var hash = SHA256.HashData(new byte[] { 1, 2, 3 });
        var signature = await source.SignHashWithRsaAsync(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public void RemoteCertificateSource_SignDataWithEcdsa_ValidData_ReturnsSignature()
    {
        var cert = TestCertificateUtils.CreateECDsaCertificate("ECDSATest");
        using var source = new TestRemoteCertificateSource(cert);
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var signature = source.SignDataWithEcdsa(data, HashAlgorithmName.SHA256);

        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public async Task RemoteCertificateSource_SignDataWithEcdsaAsync_ValidData_ReturnsSignature()
    {
        var cert = TestCertificateUtils.CreateECDsaCertificate("ECDSATest");
        using var source = new TestRemoteCertificateSource(cert);
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var signature = await source.SignDataWithEcdsaAsync(data, HashAlgorithmName.SHA256);

        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public void RemoteCertificateSource_SignHashWithEcdsa_ValidHash_ReturnsSignature()
    {
        var cert = TestCertificateUtils.CreateECDsaCertificate("ECDSATest");
        using var source = new TestRemoteCertificateSource(cert);
        var hash = SHA256.HashData(new byte[] { 1, 2, 3 });
        var signature = source.SignHashWithEcdsa(hash);

        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public async Task RemoteCertificateSource_SignHashWithEcdsaAsync_ValidHash_ReturnsSignature()
    {
        var cert = TestCertificateUtils.CreateECDsaCertificate("ECDSATest");
        using var source = new TestRemoteCertificateSource(cert);
        var hash = SHA256.HashData(new byte[] { 1, 2, 3 });
        var signature = await source.SignHashWithEcdsaAsync(hash);

        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public void RemoteCertificateSigningKey_Constructor_WithValidParameters_CreatesInstance()
    {
        var cert = TestCertificateUtils.CreateCertificate("RemoteKeyTest");
        using var source = new TestRemoteCertificateSource(cert);
        var mockSigningService = new MockSigningService();
        using var signingKey = new RemoteCertificateSigningKey(source, mockSigningService);

        Assert.That(signingKey, Is.Not.Null);
        Assert.That(signingKey.Metadata, Is.Not.Null);
        Assert.That(signingKey.SigningService, Is.EqualTo(mockSigningService));
    }

    [Test]
    public void RemoteCertificateSigningKey_GetCoseKey_ReturnsValidKey()
    {
        var cert = TestCertificateUtils.CreateCertificate("RemoteKeyTest");
        using var source = new TestRemoteCertificateSource(cert);
        var mockSigningService = new MockSigningService();
        using var signingKey = new RemoteCertificateSigningKey(source, mockSigningService);

        var coseKey = signingKey.GetCoseKey();

        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void RemoteCertificateSigningKey_GetCoseKey_CalledTwice_ReturnsSameInstance()
    {
        var cert = TestCertificateUtils.CreateCertificate("RemoteKeyTest");
        using var source = new TestRemoteCertificateSource(cert);
        var mockSigningService = new MockSigningService();
        using var signingKey = new RemoteCertificateSigningKey(source, mockSigningService);

        var coseKey1 = signingKey.GetCoseKey();
        var coseKey2 = signingKey.GetCoseKey();

        Assert.That(coseKey1, Is.SameAs(coseKey2));
    }

    [Test]
    public void RemoteCertificateSigningKey_Metadata_ContainsKeyInformation()
    {
        var cert = TestCertificateUtils.CreateCertificate("RemoteKeyTest");
        using var source = new TestRemoteCertificateSource(cert);
        var mockSigningService = new MockSigningService();
        using var signingKey = new RemoteCertificateSigningKey(source, mockSigningService);

        var metadata = signingKey.Metadata;

        Assert.That(metadata.IsRemote, Is.True);
        Assert.That(metadata.KeyType, Is.EqualTo(CryptographicKeyType.RSA));
    }

    [Test]
    public void RemoteCertificateSigningKey_Dispose_CanBeCalledMultipleTimes()
    {
        var cert = TestCertificateUtils.CreateCertificate("RemoteKeyTest");
        using var source = new TestRemoteCertificateSource(cert);
        var mockSigningService = new MockSigningService();
        var signingKey = new RemoteCertificateSigningKey(source, mockSigningService);

        signingKey.Dispose();
        Assert.DoesNotThrow(() => signingKey.Dispose());
    }

    [Test]
    public void RemoteCertificateSigningKey_GetSigningCertificate_ReturnsCertificate()
    {
        var cert = TestCertificateUtils.CreateCertificate("RemoteKeyTest");
        using var source = new TestRemoteCertificateSource(cert);
        var mockSigningService = new MockSigningService();
        using var signingKey = new RemoteCertificateSigningKey(source, mockSigningService);

        var signingCert = signingKey.GetSigningCertificate();

        Assert.That(signingCert, Is.Not.Null);
        Assert.That(signingCert.Subject, Does.Contain("RemoteKeyTest"));
    }

    [Test]
    public void RemoteCertificateSigningKey_GetCertificateChain_ReturnsChain()
    {
        var cert = TestCertificateUtils.CreateCertificate("RemoteKeyTest");
        using var source = new TestRemoteCertificateSource(cert);
        var mockSigningService = new MockSigningService();
        using var signingKey = new RemoteCertificateSigningKey(source, mockSigningService);

        var chain = signingKey.GetCertificateChain(X509ChainSortOrder.LeafFirst).ToList();

        Assert.That(chain, Is.Not.Null);
        Assert.That(chain.Count, Is.GreaterThan(0));
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
            throw new NotSupportedException("ML-DSA not supported in test implementation");
        }

        public override Task<byte[]> SignDataWithMLDsaAsync(byte[] data, HashAlgorithmName? hashAlgorithm = null, CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException("ML-DSA not supported in test implementation");
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

    // Mock signing service for testing
    private class MockSigningService : ISigningService<SigningOptions>
    {
        public SigningServiceMetadata ServiceMetadata => new SigningServiceMetadata("Mock");
        public bool IsRemote => true;

        public Task<ISigningKey> GetSigningKeyAsync(SigningOptions? options = null, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public System.Security.Cryptography.Cose.CoseSigner GetCoseSigner(SigningContext context)
        {
            throw new NotImplementedException();
        }

        public SigningOptions CreateSigningOptions()
        {
            return new SigningOptions();
        }

        public void Dispose()
        {
            // No resources to dispose
        }
    }
}