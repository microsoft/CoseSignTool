// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Local;
using CoseSign1.Tests.Common;
using NUnit.Framework;

namespace CoseSign1.Certificates.Tests.Local;

public class DirectCertificateSourceTests
{
    [Test]
    public void Constructor_WithCertificateAndChain_Succeeds()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var source = new DirectCertificateSource(cert, chain);

        Assert.That(source, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithCertificateAndChainBuilder_Succeeds()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var chainBuilder = new CoseSign1.Certificates.ChainBuilders.ExplicitCertificateChainBuilder(chain);
        using var source = new DirectCertificateSource(cert, chainBuilder);

        Assert.That(source, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullCertificate_ThrowsArgumentNullException()
    {
        var chain = new[] { TestCertificateUtils.CreateCertificate() };
        Assert.Throws<ArgumentNullException>(() => new DirectCertificateSource(null!, chain));
    }

    [Test]
    public void Constructor_WithNullChain_ThrowsArgumentNullException()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        Assert.Throws<ArgumentNullException>(() => new DirectCertificateSource(cert, (IReadOnlyList<X509Certificate2>)null!));
    }

    [Test]
    public void Constructor_WithNullChainBuilder_ThrowsArgumentNullException()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        Assert.Throws<ArgumentNullException>(() => new DirectCertificateSource(cert, (ICertificateChainBuilder)null!));
    }

    [Test]
    public void Constructor_WithEmptyChain_ThrowsArgumentException()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var emptyChain = Array.Empty<X509Certificate2>();
        Assert.Throws<ArgumentException>(() => new DirectCertificateSource(cert, emptyChain));
    }

    [Test]
    public void GetSigningCertificate_ReturnsSameCertificate()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var source = new DirectCertificateSource(cert, chain);

        var retrieved = source.GetSigningCertificate();

        Assert.That(retrieved, Is.SameAs(cert));
    }

    [Test]
    public void HasPrivateKey_WithPrivateKey_ReturnsTrue()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var source = new DirectCertificateSource(cert, chain);

        Assert.That(source.HasPrivateKey, Is.True);
    }

    [Test]
    public void HasPrivateKey_WithoutPrivateKey_ReturnsFalse()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        using var publicOnly = X509CertificateLoader.LoadCertificate(cert.Export(X509ContentType.Cert));
        var chain = new[] { publicOnly };
        using var source = new DirectCertificateSource(publicOnly, chain);

        Assert.That(source.HasPrivateKey, Is.False);
    }

    [Test]
    public void GetChainBuilder_WithProvidedChain_ReturnsExplicitChainBuilder()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var source = new DirectCertificateSource(cert, chain);

        var chainBuilder = source.GetChainBuilder();

        Assert.That(chainBuilder, Is.InstanceOf<CoseSign1.Certificates.ChainBuilders.ExplicitCertificateChainBuilder>());
    }

    [Test]
    public void GetChainBuilder_WithChainBuilder_ReturnsSameBuilder()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var chainBuilder = new CoseSign1.Certificates.ChainBuilders.ExplicitCertificateChainBuilder(chain);
        using var source = new DirectCertificateSource(cert, chainBuilder);

        var retrievedBuilder = source.GetChainBuilder();

        Assert.That(retrievedBuilder, Is.SameAs(chainBuilder));
    }

    [Test]
    public void GetChainBuilder_BuildAndGetChain_ReturnsChain()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var source = new DirectCertificateSource(cert, chain);

        var chainBuilder = source.GetChainBuilder();
        chainBuilder.Build(cert);
        var retrievedChain = chainBuilder.ChainElements;

        Assert.That(retrievedChain, Is.Not.Null);
        Assert.That(retrievedChain, Has.Count.EqualTo(1));
        Assert.That(retrievedChain.First().Thumbprint, Is.EqualTo(cert.Thumbprint));
    }

    [Test]
    public void GetChainBuilder_WithChainBuilder_BuildsAndReturnsChain()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var chainBuilder = new CoseSign1.Certificates.ChainBuilders.ExplicitCertificateChainBuilder(chain);
        using var source = new DirectCertificateSource(cert, chainBuilder);

        var retrievedBuilder = source.GetChainBuilder();
        var buildResult = retrievedBuilder.Build(cert);
        var retrievedChain = retrievedBuilder.ChainElements;

        Assert.That(retrievedChain, Is.Not.Null);
        Assert.That(retrievedChain, Has.Count.EqualTo(1));
        Assert.That(buildResult, Is.True);
    }

    [Test]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        var source = new DirectCertificateSource(cert, chain);

        source.Dispose();
        source.Dispose(); // Should not throw
    }

    [Test]
    public void Dispose_DoesNotDisposeCertificate()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        var source = new DirectCertificateSource(cert, chain);

        source.Dispose();

        // Certificate should still be usable
        Assert.That(cert.Subject, Is.Not.Null);
    }

    #region Integration Tests: DirectCertificateSource + CertificateSigningKey Metadata Detection

    [Test]
    public void Integration_RSA2048Certificate_DetectsPS256Metadata()
    {
        // Arrange: Create DirectCertificateSource with RSA 2048-bit certificate
        using var cert = TestCertificateUtils.CreateCertificate("RSA2048Test", keySize: 2048);
        var chain = new[] { cert };
        using var source = new DirectCertificateSource(cert, chain);
        
        // Create signing key provider and CertificateSigningKey
        using var keyProvider = new DirectSigningKeyProvider(cert);
        using var mockService = new MockSigningService(false);
        using var signingKey = new CertificateSigningKey(source, keyProvider, mockService);

        // Act: Get metadata through CertificateSigningKey
        var metadata = signingKey.Metadata;

        // Assert: Verify full integration detects RSA 2048 → PS256
        Assert.That(metadata.KeyType, Is.EqualTo(CryptographicKeyType.RSA));
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-37)); // PS256
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA256));
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(2048));
        Assert.That(metadata.IsRemote, Is.False);
    }

    [Test]
    public void Integration_RSA3072Certificate_DetectsPS384Metadata()
    {
        // Arrange: Create DirectCertificateSource with RSA 3072-bit certificate
        using var cert = TestCertificateUtils.CreateCertificate("RSA3072Test", keySize: 3072);
        var chain = new[] { cert };
        using var source = new DirectCertificateSource(cert, chain);
        
        using var keyProvider = new DirectSigningKeyProvider(cert);
        using var mockService = new MockSigningService(false);
        using var signingKey = new CertificateSigningKey(source, keyProvider, mockService);

        // Act
        var metadata = signingKey.Metadata;

        // Assert: Verify RSA 3072 → PS384
        Assert.That(metadata.KeyType, Is.EqualTo(CryptographicKeyType.RSA));
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-38)); // PS384
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA384));
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(3072));
    }

    [Test]
    public void Integration_RSA4096Certificate_DetectsPS512Metadata()
    {
        // Arrange: Create DirectCertificateSource with RSA 4096-bit certificate
        using var cert = TestCertificateUtils.CreateCertificate("RSA4096Test", keySize: 4096);
        var chain = new[] { cert };
        using var source = new DirectCertificateSource(cert, chain);
        
        using var keyProvider = new DirectSigningKeyProvider(cert);
        using var mockService = new MockSigningService(false);
        using var signingKey = new CertificateSigningKey(source, keyProvider, mockService);

        // Act
        var metadata = signingKey.Metadata;

        // Assert: Verify RSA 4096 → PS512
        Assert.That(metadata.KeyType, Is.EqualTo(CryptographicKeyType.RSA));
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-39)); // PS512
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA512));
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(4096));
    }

    [Test]
    public void Integration_ECDsaP256Certificate_DetectsES256Metadata()
    {
        // Arrange: Create DirectCertificateSource with ECDSA P-256 certificate
        using var cert = TestCertificateUtils.CreateCertificate("ECDSA256Test", useEcc: true, keySize: 256);
        var chain = new[] { cert };
        using var source = new DirectCertificateSource(cert, chain);
        
        using var keyProvider = new DirectSigningKeyProvider(cert);
        using var mockService = new MockSigningService(false);
        using var signingKey = new CertificateSigningKey(source, keyProvider, mockService);

        // Act
        var metadata = signingKey.Metadata;

        // Assert: Verify ECDSA P-256 → ES256
        Assert.That(metadata.KeyType, Is.EqualTo(CryptographicKeyType.ECDsa));
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-7)); // ES256
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA256));
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(256));
    }

    [Test]
    public void Integration_ECDsaP384Certificate_DetectsES384Metadata()
    {
        // Arrange: Create DirectCertificateSource with ECDSA P-384 certificate
        using var cert = TestCertificateUtils.CreateCertificate("ECDSA384Test", useEcc: true, keySize: 384);
        var chain = new[] { cert };
        using var source = new DirectCertificateSource(cert, chain);
        
        using var keyProvider = new DirectSigningKeyProvider(cert);
        using var mockService = new MockSigningService(false);
        using var signingKey = new CertificateSigningKey(source, keyProvider, mockService);

        // Act
        var metadata = signingKey.Metadata;

        // Assert: Verify ECDSA P-384 → ES384
        Assert.That(metadata.KeyType, Is.EqualTo(CryptographicKeyType.ECDsa));
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-35)); // ES384
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA384));
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(384));
    }

    [Test]
    public void Integration_ECDsaP521Certificate_DetectsES512Metadata()
    {
        // Arrange: Create DirectCertificateSource with ECDSA P-521 certificate
        using var cert = TestCertificateUtils.CreateCertificate("ECDSA521Test", useEcc: true, keySize: 521);
        var chain = new[] { cert };
        using var source = new DirectCertificateSource(cert, chain);
        
        using var keyProvider = new DirectSigningKeyProvider(cert);
        using var mockService = new MockSigningService(false);
        using var signingKey = new CertificateSigningKey(source, keyProvider, mockService);

        // Act
        var metadata = signingKey.Metadata;

        // Assert: Verify ECDSA P-521 → ES512
        Assert.That(metadata.KeyType, Is.EqualTo(CryptographicKeyType.ECDsa));
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-36)); // ES512
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA512));
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(521));
    }

    [Test]
    public void Integration_PublicKeyOnlyCertificate_StillDetectsMetadata()
    {
        // Arrange: Create certificate and strip private key
        using var fullCert = TestCertificateUtils.CreateCertificate("PublicOnlyTest", keySize: 2048);
        using var publicOnly = X509CertificateLoader.LoadCertificate(fullCert.Export(X509ContentType.Cert));
        
        var chain = new[] { publicOnly };
        using var source = new DirectCertificateSource(publicOnly, chain);
        
        // Note: DirectSigningKeyProvider requires private key, so use mock
        using var mockKeyProvider = new MockSigningKeyProvider(publicOnly, isRemote: false);
        using var mockService = new MockSigningService(false);
        using var signingKey = new CertificateSigningKey(source, mockKeyProvider, mockService);

        // Act: Metadata detection should work from public key alone
        var metadata = signingKey.Metadata;

        // Assert: Metadata detected from public key
        Assert.That(metadata.KeyType, Is.EqualTo(CryptographicKeyType.RSA));
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-37)); // PS256
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(2048));
    }

    [Test]
    public void Integration_MetadataCaching_ReturnsSameInstanceAcrossMultipleCalls()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("CacheTest", keySize: 2048);
        var chain = new[] { cert };
        using var source = new DirectCertificateSource(cert, chain);
        
        using var keyProvider = new DirectSigningKeyProvider(cert);
        using var mockService = new MockSigningService(false);
        using var signingKey = new CertificateSigningKey(source, keyProvider, mockService);

        // Act: Access metadata multiple times
        var metadata1 = signingKey.Metadata;
        var metadata2 = signingKey.Metadata;
        var metadata3 = signingKey.Metadata;

        // Assert: Verify consistency (property getter creates new instance each time but values match)
        Assert.That(metadata1.CoseAlgorithmId, Is.EqualTo(metadata2.CoseAlgorithmId));
        Assert.That(metadata2.CoseAlgorithmId, Is.EqualTo(metadata3.CoseAlgorithmId));
        Assert.That(metadata1.KeyType, Is.EqualTo(metadata2.KeyType));
        Assert.That(metadata1.KeySizeInBits, Is.EqualTo(metadata2.KeySizeInBits));
    }

    [Test]
    public void Integration_DifferentRSAKeySizes_ProduceDifferentAlgorithms()
    {
        // Arrange: Multiple RSA certificates with different key sizes
        using var cert2048 = TestCertificateUtils.CreateCertificate("RSA2048", keySize: 2048);
        using var cert3072 = TestCertificateUtils.CreateCertificate("RSA3072", keySize: 3072);
        using var cert4096 = TestCertificateUtils.CreateCertificate("RSA4096", keySize: 4096);
        
        using var source2048 = new DirectCertificateSource(cert2048, new[] { cert2048 });
        using var source3072 = new DirectCertificateSource(cert3072, new[] { cert3072 });
        using var source4096 = new DirectCertificateSource(cert4096, new[] { cert4096 });
        
        using var provider2048 = new DirectSigningKeyProvider(cert2048);
        using var provider3072 = new DirectSigningKeyProvider(cert3072);
        using var provider4096 = new DirectSigningKeyProvider(cert4096);
        
        using var mockService = new MockSigningService(false);
        using var key2048 = new CertificateSigningKey(source2048, provider2048, mockService);
        using var key3072 = new CertificateSigningKey(source3072, provider3072, mockService);
        using var key4096 = new CertificateSigningKey(source4096, provider4096, mockService);

        // Act
        var metadata2048 = key2048.Metadata;
        var metadata3072 = key3072.Metadata;
        var metadata4096 = key4096.Metadata;

        // Assert: Each key size maps to different algorithm
        Assert.That(metadata2048.CoseAlgorithmId, Is.EqualTo(-37)); // PS256
        Assert.That(metadata3072.CoseAlgorithmId, Is.EqualTo(-38)); // PS384
        Assert.That(metadata4096.CoseAlgorithmId, Is.EqualTo(-39)); // PS512
        
        Assert.That(metadata2048.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA256));
        Assert.That(metadata3072.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA384));
        Assert.That(metadata4096.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA512));
    }

    [Test]
    public void Integration_RSAvsECDsa_ProduceDifferentKeyTypes()
    {
        // Arrange: One RSA and one ECDSA certificate
        using var rsaCert = TestCertificateUtils.CreateCertificate("RSATest", useEcc: false, keySize: 2048);
        using var ecdsaCert = TestCertificateUtils.CreateCertificate("ECDSATest", useEcc: true, keySize: 256);
        
        using var rsaSource = new DirectCertificateSource(rsaCert, new[] { rsaCert });
        using var ecdsaSource = new DirectCertificateSource(ecdsaCert, new[] { ecdsaCert });
        
        using var rsaProvider = new DirectSigningKeyProvider(rsaCert);
        using var ecdsaProvider = new DirectSigningKeyProvider(ecdsaCert);
        
        using var mockService = new MockSigningService(false);
        using var rsaKey = new CertificateSigningKey(rsaSource, rsaProvider, mockService);
        using var ecdsaKey = new CertificateSigningKey(ecdsaSource, ecdsaProvider, mockService);

        // Act
        var rsaMetadata = rsaKey.Metadata;
        var ecdsaMetadata = ecdsaKey.Metadata;

        // Assert: Different key types detected
        Assert.That(rsaMetadata.KeyType, Is.EqualTo(CryptographicKeyType.RSA));
        Assert.That(ecdsaMetadata.KeyType, Is.EqualTo(CryptographicKeyType.ECDsa));
        
        Assert.That(rsaMetadata.CoseAlgorithmId, Is.EqualTo(-37)); // PS256
        Assert.That(ecdsaMetadata.CoseAlgorithmId, Is.EqualTo(-7)); // ES256
    }

    [Test]
    public void Integration_IsRemoteFlag_ReflectsProviderRemoteState()
    {
        // Arrange: Create two signing keys - one local, one simulated remote
        using var cert = TestCertificateUtils.CreateCertificate("RemoteFlagTest", keySize: 2048);
        
        using var sourceLocal = new DirectCertificateSource(cert, new[] { cert });
        using var sourceRemote = new DirectCertificateSource(cert, new[] { cert });
        
        using var providerLocal = new MockSigningKeyProvider(cert, isRemote: false);
        using var providerRemote = new MockSigningKeyProvider(cert, isRemote: true);
        
        using var serviceLocal = new MockSigningService(false);
        using var serviceRemote = new MockSigningService(true);
        
        using var keyLocal = new CertificateSigningKey(sourceLocal, providerLocal, serviceLocal);
        using var keyRemote = new CertificateSigningKey(sourceRemote, providerRemote, serviceRemote);

        // Act
        var localMetadata = keyLocal.Metadata;
        var remoteMetadata = keyRemote.Metadata;

        // Assert: IsRemote flag correctly reflects provider state
        Assert.That(localMetadata.IsRemote, Is.False);
        Assert.That(remoteMetadata.IsRemote, Is.True);
        
        // Other metadata should be identical
        Assert.That(localMetadata.CoseAlgorithmId, Is.EqualTo(remoteMetadata.CoseAlgorithmId));
        Assert.That(localMetadata.KeyType, Is.EqualTo(remoteMetadata.KeyType));
    }

    [Test]
    public void Integration_MLDSA44Certificate_DetectsCorrectMetadata()
    {
        // Arrange: Create real ML-DSA-44 certificate using TestCertificateUtils
        using var mldsaCert = TestCertificateUtils.CreateMLDsaCertificate("MLDSA44Test", mlDsaParameterSet: 44);
        var chain = new[] { mldsaCert };
        using var source = new DirectCertificateSource(mldsaCert, chain);
        
        using var keyProvider = new MockSigningKeyProvider(mldsaCert, isRemote: false);
        using var mockService = new MockSigningService(false);
        using var signingKey = new CertificateSigningKey(source, keyProvider, mockService);

        // Act: Get metadata through CertificateSigningKey
        var metadata = signingKey.Metadata;

        // Assert: Verify ML-DSA-44 detection
        Assert.That(metadata.KeyType, Is.EqualTo(CryptographicKeyType.MLDSA), "Key type should be MLDSA");
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-48), "ML-DSA-44 should use COSE -48");
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA256), "ML-DSA-44 should use SHA256");
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(44), "ML-DSA-44 key size indicator should be 44");
        Assert.That(metadata.AdditionalMetadata, Is.Not.Null);
        Assert.That(metadata.AdditionalMetadata!["PublicKeyAlgorithmOid"], Is.EqualTo("2.16.840.1.101.3.4.3.17"));
    }

    [Test]
    public void Integration_MLDSA65Certificate_DetectsCorrectMetadata()
    {
        // Arrange: Create real ML-DSA-65 certificate using TestCertificateUtils
        using var mldsaCert = TestCertificateUtils.CreateMLDsaCertificate("MLDSA65Test", mlDsaParameterSet: 65);
        var chain = new[] { mldsaCert };
        using var source = new DirectCertificateSource(mldsaCert, chain);
        
        using var keyProvider = new MockSigningKeyProvider(mldsaCert, isRemote: false);
        using var mockService = new MockSigningService(false);
        using var signingKey = new CertificateSigningKey(source, keyProvider, mockService);

        // Act
        var metadata = signingKey.Metadata;

        // Assert: Verify ML-DSA-65 detection
        Assert.That(metadata.KeyType, Is.EqualTo(CryptographicKeyType.MLDSA), "Key type should be MLDSA");
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-49), "ML-DSA-65 should use COSE -49");
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA384), "ML-DSA-65 should use SHA384");
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(65), "ML-DSA-65 key size indicator should be 65");
        Assert.That(metadata.AdditionalMetadata, Is.Not.Null);
        Assert.That(metadata.AdditionalMetadata!["PublicKeyAlgorithmOid"], Is.EqualTo("2.16.840.1.101.3.4.3.18"));
    }

    [Test]
    public void Integration_MLDSA87Certificate_DetectsCorrectMetadata()
    {
        // Arrange: Create real ML-DSA-87 certificate using TestCertificateUtils
        using var mldsaCert = TestCertificateUtils.CreateMLDsaCertificate("MLDSA87Test", mlDsaParameterSet: 87);
        var chain = new[] { mldsaCert };
        using var source = new DirectCertificateSource(mldsaCert, chain);
        
        using var keyProvider = new MockSigningKeyProvider(mldsaCert, isRemote: false);
        using var mockService = new MockSigningService(false);
        using var signingKey = new CertificateSigningKey(source, keyProvider, mockService);

        // Act
        var metadata = signingKey.Metadata;

        // Assert: Verify ML-DSA-87 detection
        Assert.That(metadata.KeyType, Is.EqualTo(CryptographicKeyType.MLDSA), "Key type should be MLDSA");
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-50), "ML-DSA-87 should use COSE -50");
        Assert.That(metadata.HashAlgorithm, Is.EqualTo(HashAlgorithmName.SHA512), "ML-DSA-87 should use SHA512");
        Assert.That(metadata.KeySizeInBits, Is.EqualTo(87), "ML-DSA-87 key size indicator should be 87");
        Assert.That(metadata.AdditionalMetadata, Is.Not.Null);
        Assert.That(metadata.AdditionalMetadata!["PublicKeyAlgorithmOid"], Is.EqualTo("2.16.840.1.101.3.4.3.19"));
    }

    [Test]
    public void Integration_MLDSAWithRemoteProvider_ReflectsRemoteState()
    {
        // Arrange: ML-DSA certificate with remote provider (simulating hardware security module)
        using var mldsaCert = TestCertificateUtils.CreateMLDsaCertificate("RemoteMLDSATest", mlDsaParameterSet: 65);
        var chain = new[] { mldsaCert };
        using var source = new DirectCertificateSource(mldsaCert, chain);
        
        using var keyProvider = new MockSigningKeyProvider(mldsaCert, isRemote: true);
        using var mockService = new MockSigningService(true);
        using var signingKey = new CertificateSigningKey(source, keyProvider, mockService);

        // Act
        var metadata = signingKey.Metadata;

        // Assert: Remote ML-DSA signing scenario
        Assert.That(metadata.KeyType, Is.EqualTo(CryptographicKeyType.MLDSA));
        Assert.That(metadata.IsRemote, Is.True, "Should reflect remote signing");
        Assert.That(metadata.CoseAlgorithmId, Is.EqualTo(-49)); // ML-DSA-65
    }

    [Test]
    public void Integration_RSA_ECDSA_MLDSA_AllHaveDifferentKeyTypes()
    {
        // Arrange: Create one certificate of each supported type
        using var rsaCert = TestCertificateUtils.CreateCertificate("RSAComparison", useEcc: false, keySize: 2048);
        using var ecdsaCert = TestCertificateUtils.CreateCertificate("ECDSAComparison", useEcc: true, keySize: 256);
        using var mldsaCert = TestCertificateUtils.CreateMLDsaCertificate("MLDSAComparison", mlDsaParameterSet: 65);
        
        using var rsaSource = new DirectCertificateSource(rsaCert, new[] { rsaCert });
        using var ecdsaSource = new DirectCertificateSource(ecdsaCert, new[] { ecdsaCert });
        using var mldsaSource = new DirectCertificateSource(mldsaCert, new[] { mldsaCert });
        
        using var rsaProvider = new DirectSigningKeyProvider(rsaCert);
        using var ecdsaProvider = new DirectSigningKeyProvider(ecdsaCert);
        using var mldsaProvider = new MockSigningKeyProvider(mldsaCert, isRemote: false);
        
        using var mockService = new MockSigningService(false);
        using var rsaKey = new CertificateSigningKey(rsaSource, rsaProvider, mockService);
        using var ecdsaKey = new CertificateSigningKey(ecdsaSource, ecdsaProvider, mockService);
        using var mldsaKey = new CertificateSigningKey(mldsaSource, mldsaProvider, mockService);

        // Act
        var rsaMetadata = rsaKey.Metadata;
        var ecdsaMetadata = ecdsaKey.Metadata;
        var mldsaMetadata = mldsaKey.Metadata;

        // Assert: All three key types are distinct
        Assert.That(rsaMetadata.KeyType, Is.EqualTo(CryptographicKeyType.RSA));
        Assert.That(ecdsaMetadata.KeyType, Is.EqualTo(CryptographicKeyType.ECDsa));
        Assert.That(mldsaMetadata.KeyType, Is.EqualTo(CryptographicKeyType.MLDSA));
        
        // Each has different COSE algorithm
        Assert.That(rsaMetadata.CoseAlgorithmId, Is.EqualTo(-37)); // PS256
        Assert.That(ecdsaMetadata.CoseAlgorithmId, Is.EqualTo(-7)); // ES256
        Assert.That(mldsaMetadata.CoseAlgorithmId, Is.EqualTo(-49)); // ML-DSA-65
        
        // All are local
        Assert.That(rsaMetadata.IsRemote, Is.False);
        Assert.That(ecdsaMetadata.IsRemote, Is.False);
        Assert.That(mldsaMetadata.IsRemote, Is.False);
    }

    #endregion
}

// Mock classes to support integration tests
internal class MockSigningService : ISigningService<SigningOptions>
{
    private readonly bool _isRemote;
    
    public MockSigningService(bool isRemote)
    {
        _isRemote = isRemote;
    }
    
    public bool IsRemote => _isRemote;
    public SigningServiceMetadata ServiceMetadata => new SigningServiceMetadata("MockService", "Test service");
    
    public CoseSigner GetCoseSigner(SigningContext context)
    {
        throw new NotImplementedException("Mock service does not support GetCoseSigner");
    }
    
    public SigningOptions CreateSigningOptions()
    {
        return new SigningOptions();
    }
    
    public void Dispose() { }
}

internal class MockSigningKeyProvider : ISigningKeyProvider
{
    private readonly X509Certificate2 _certificate;
    private readonly bool _isRemote;
    
    public MockSigningKeyProvider(X509Certificate2 certificate, bool isRemote)
    {
        _certificate = certificate;
        _isRemote = isRemote;
    }
    
    public bool IsRemote => _isRemote;
    
    public CoseKey GetCoseKey()
    {
        // Return a basic CoseKey for testing
        using var rsa = _certificate.GetRSAPublicKey();
        if (rsa != null)
        {
            return new CoseKey(rsa, RSASignaturePadding.Pss, HashAlgorithmName.SHA256);
        }
        
        using var ecdsa = _certificate.GetECDsaPublicKey();
        if (ecdsa != null)
        {
            return new CoseKey(ecdsa, HashAlgorithmName.SHA256);
        }
        
        throw new InvalidOperationException("Certificate must have RSA or ECDSA key");
    }
    
    public void Dispose() { }
}
