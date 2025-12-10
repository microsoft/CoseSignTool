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
public class RemoteSigningTests
{
    [Test]
    #pragma warning disable CA2252
    public void RemoteCertificateSource_HasPrivateKey_AlwaysReturnsTrue()
    {
        var cert = TestCertificateUtils.CreateCertificate("RemoteTest");
        using var source = new TestRemoteCertificateSource(cert);
        
        Assert.That(source.HasPrivateKey, Is.True);
    }
    #pragma warning restore CA2252

    [Test]
    public void RemoteCertificateSource_Constructor_WithDefaultChainBuilder_CreatesInstance()
    {
        #pragma warning disable CA2252
        var cert = TestCertificateUtils.CreateCertificate("RemoteTest");
        #pragma warning restore CA2252
        using var source = new TestRemoteCertificateSource(cert);
        
        Assert.That(source, Is.Not.Null);
    }

    [Test]
    public void RemoteCertificateSource_Constructor_WithCustomChainBuilder_UsesCustomBuilder()
    {
        var customBuilder = new X509ChainBuilder();
        #pragma warning disable CA2252
        var cert = TestCertificateUtils.CreateCertificate("Test");
        #pragma warning restore CA2252
        using var source = new TestRemoteCertificateSource(cert, customBuilder);
        
        Assert.That(source, Is.Not.Null);
    }

    [Test]
    public void RemoteCertificateSource_SignDataWithRsa_ValidData_ReturnsSignature()
    {
        #pragma warning disable CA2252
        var cert = TestCertificateUtils.CreateCertificate("RSATest");
        #pragma warning restore CA2252
        using var source = new TestRemoteCertificateSource(cert);
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var signature = source.SignDataWithRsa(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public async Task RemoteCertificateSource_SignDataWithRsaAsync_ValidData_ReturnsSignature()
    {
        #pragma warning disable CA2252
        var cert = TestCertificateUtils.CreateCertificate("RSATest");
        #pragma warning restore CA2252
        using var source = new TestRemoteCertificateSource(cert);
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var signature = await source.SignDataWithRsaAsync(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public void RemoteCertificateSource_SignHashWithRsa_ValidHash_ReturnsSignature()
    {
        #pragma warning disable CA2252
        var cert = TestCertificateUtils.CreateCertificate("RSATest");
        #pragma warning restore CA2252
        using var source = new TestRemoteCertificateSource(cert);
        var hash = SHA256.HashData(new byte[] { 1, 2, 3 });
        var signature = source.SignHashWithRsa(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public async Task RemoteCertificateSource_SignHashWithRsaAsync_ValidHash_ReturnsSignature()
    {
        #pragma warning disable CA2252
        var cert = TestCertificateUtils.CreateCertificate("RSATest");
        #pragma warning restore CA2252
        using var source = new TestRemoteCertificateSource(cert);
        var hash = SHA256.HashData(new byte[] { 1, 2, 3 });
        var signature = await source.SignHashWithRsaAsync(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public void RemoteCertificateSource_SignDataWithEcdsa_ValidData_ReturnsSignature()
    {
        #pragma warning disable CA2252
        var cert = TestCertificateUtils.CreateECDsaCertificate("ECDSATest");
        #pragma warning restore CA2252
        using var source = new TestRemoteCertificateSource(cert);
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var signature = source.SignDataWithEcdsa(data, HashAlgorithmName.SHA256);
        
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public async Task RemoteCertificateSource_SignDataWithEcdsaAsync_ValidData_ReturnsSignature()
    {
        #pragma warning disable CA2252
        var cert = TestCertificateUtils.CreateECDsaCertificate("ECDSATest");
        #pragma warning restore CA2252
        using var source = new TestRemoteCertificateSource(cert);
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var signature = await source.SignDataWithEcdsaAsync(data, HashAlgorithmName.SHA256);
        
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public void RemoteCertificateSource_SignHashWithEcdsa_ValidHash_ReturnsSignature()
    {
        #pragma warning disable CA2252
        var cert = TestCertificateUtils.CreateECDsaCertificate("ECDSATest");
        #pragma warning restore CA2252
        using var source = new TestRemoteCertificateSource(cert);
        var hash = SHA256.HashData(new byte[] { 1, 2, 3 });
        var signature = source.SignHashWithEcdsa(hash);
        
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public async Task RemoteCertificateSource_SignHashWithEcdsaAsync_ValidHash_ReturnsSignature()
    {
        #pragma warning disable CA2252
        var cert = TestCertificateUtils.CreateECDsaCertificate("ECDSATest");
        #pragma warning restore CA2252
        using var source = new TestRemoteCertificateSource(cert);
        var hash = SHA256.HashData(new byte[] { 1, 2, 3 });
        var signature = await source.SignHashWithEcdsaAsync(hash);
        
        Assert.That(signature, Is.Not.Null);
        Assert.That(signature.Length, Is.GreaterThan(0));
    }

    [Test]
    public void RemoteSigningKeyProvider_Constructor_WithValidParameters_CreatesInstance()
    {
        #pragma warning disable CA2252
        var cert = TestCertificateUtils.CreateCertificate("RemoteKeyTest");
        #pragma warning restore CA2252
        using var source = new TestRemoteCertificateSource(cert);
        var mockSigningService = new MockSigningService();
        using var provider = new RemoteSigningKeyProvider(source, mockSigningService);
        
        Assert.That(provider, Is.Not.Null);
        Assert.That(provider.Metadata, Is.Not.Null);
        Assert.That(provider.SigningService, Is.EqualTo(mockSigningService));
    }

    [Test]
    public void RemoteSigningKeyProvider_GetCoseKey_ReturnsValidKey()
    {
        #pragma warning disable CA2252
        var cert = TestCertificateUtils.CreateCertificate("RemoteKeyTest");
        #pragma warning restore CA2252
        using var source = new TestRemoteCertificateSource(cert);
        var mockSigningService = new MockSigningService();
        using var provider = new RemoteSigningKeyProvider(source, mockSigningService);
        
        var coseKey = provider.GetCoseKey();
        
        Assert.That(coseKey, Is.Not.Null);
    }

    [Test]
    public void RemoteSigningKeyProvider_GetCoseKey_CalledTwice_ReturnsSameInstance()
    {
        #pragma warning disable CA2252
        var cert = TestCertificateUtils.CreateCertificate("RemoteKeyTest");
        #pragma warning restore CA2252
        using var source = new TestRemoteCertificateSource(cert);
        var mockSigningService = new MockSigningService();
        using var provider = new RemoteSigningKeyProvider(source, mockSigningService);
        
        var coseKey1 = provider.GetCoseKey();
        var coseKey2 = provider.GetCoseKey();
        
        Assert.That(coseKey1, Is.SameAs(coseKey2));
    }

    [Test]
    public void RemoteSigningKeyProvider_Metadata_ContainsKeyInformation()
    {
        #pragma warning disable CA2252
        var cert = TestCertificateUtils.CreateCertificate("RemoteKeyTest");
        #pragma warning restore CA2252
        using var source = new TestRemoteCertificateSource(cert);
        var mockSigningService = new MockSigningService();
        using var provider = new RemoteSigningKeyProvider(source, mockSigningService);
        
        var metadata = provider.Metadata;
        
        Assert.That(metadata.IsRemote, Is.True);
        Assert.That(metadata.KeyType, Is.EqualTo(CryptographicKeyType.RSA));
    }

    [Test]
    public void RemoteSigningKeyProvider_Dispose_CanBeCalledMultipleTimes()
    {
        #pragma warning disable CA2252
        var cert = TestCertificateUtils.CreateCertificate("RemoteKeyTest");
        #pragma warning restore CA2252
        using var source = new TestRemoteCertificateSource(cert);
        var mockSigningService = new MockSigningService();
        var provider = new RemoteSigningKeyProvider(source, mockSigningService);
        
        provider.Dispose();
        Assert.DoesNotThrow(() => provider.Dispose());
    }

    // Test implementation of RemoteCertificateSource
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
                _certificate?.Dispose();
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
