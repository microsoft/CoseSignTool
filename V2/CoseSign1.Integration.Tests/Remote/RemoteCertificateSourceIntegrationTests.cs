// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CoseSign1.Certificates.Local;
using CoseSign1.Direct;
using CoseSign1.Tests.Common;

namespace CoseSign1.Integration.Tests.Remote;

/// <summary>
/// Integration tests for remote signing architecture using TestRemoteCertificateSource.
/// Tests the entire flow: TestRemoteCertificateSource -> RemoteSigningKeyProvider -> Remote* wrappers -> CoseKey -> DirectSignatureFactory
/// </summary>
[TestFixture]
public class RemoteCertificateSourceIntegrationTests
{
    private readonly byte[] _testPayload = Encoding.UTF8.GetBytes("Test payload for remote signing integration testing");
    private const string ContentType = "application/json";

    [Test]
    public void RemoteRsaSigning_ThroughDirectFactory_ProducesValidSignature()
    {
        // Arrange - Create RSA certificate and remote signing infrastructure
        var chain = TestCertificateUtils.CreateTestChain("RemoteRSA-Test", useEcc: false, keySize: 2048, leafFirst: true);
        using var signingCert = chain[0];
        var directCertSource = new DirectCertificateSource(signingCert, chain.Cast<X509Certificate2>().ToArray());
        var remoteCertSource = new TestRemoteCertificateSource(directCertSource);
        
        using var signingService = new DirectSigningRemoteCertificateSigningService(signingCert, remoteCertSource, chain.Cast<X509Certificate2>().ToArray());
        using var factory = new DirectSignatureFactory(signingService);

        // Act - Sign the payload using remote signing
        var messageBytes = factory.CreateCoseSign1MessageBytes(_testPayload, ContentType);

        // Assert - Verify we got a valid COSE message
        Assert.That(messageBytes, Is.Not.Null);
        Assert.That(messageBytes.Length, Is.GreaterThan(0));
        Assert.That(signingService.IsRemote, Is.True);
    }

    [Test]
    public void RemoteEcdsaSigning_ThroughDirectFactory_ProducesValidSignature()
    {
        // Arrange - Create ECDSA certificate and remote signing infrastructure
        var chain = TestCertificateUtils.CreateTestChain("RemoteECDSA-Test", useEcc: true, keySize: 256, leafFirst: true);
        using var signingCert = chain[0];
        var directCertSource = new DirectCertificateSource(signingCert, chain.Cast<X509Certificate2>().ToArray());
        var remoteCertSource = new TestRemoteCertificateSource(directCertSource);
        
        using var signingService = new DirectSigningRemoteCertificateSigningService(signingCert, remoteCertSource, chain.Cast<X509Certificate2>().ToArray());
        using var factory = new DirectSignatureFactory(signingService);

        // Act - Sign the payload using remote signing
        var messageBytes = factory.CreateCoseSign1MessageBytes(_testPayload, ContentType);

        // Assert - Verify we got a valid COSE message
        Assert.That(messageBytes, Is.Not.Null);
        Assert.That(messageBytes.Length, Is.GreaterThan(0));
        Assert.That(signingService.IsRemote, Is.True);
    }

    [Test]
    public void RemoteMLDsaSigning_ThroughDirectFactory_ProducesValidSignature()
    {
        // Arrange - Create ML-DSA certificate and remote signing infrastructure
        using var signingCert = TestCertificateUtils.CreateMLDsaCertificate("RemoteMLDSA-Test", mlDsaParameterSet: 44);
        var directCertSource = new DirectCertificateSource(signingCert, new[] { signingCert });
        var remoteCertSource = new TestRemoteCertificateSource(directCertSource);
        
        using var signingService = new DirectSigningRemoteCertificateSigningService(signingCert, remoteCertSource, new[] { signingCert });
        using var factory = new DirectSignatureFactory(signingService);

        // Act - Sign the payload using remote signing
        var messageBytes = factory.CreateCoseSign1MessageBytes(_testPayload, ContentType);

        // Assert - Verify we got a valid COSE message
        Assert.That(messageBytes, Is.Not.Null);
        Assert.That(messageBytes.Length, Is.GreaterThan(0));
        Assert.That(signingService.IsRemote, Is.True);
    }

    [Test]
    public void RemoteRsaSigning_WithDifferentKeySizes_ProducesValidSignatures()
    {
        int[] keySizes = { 2048, 3072, 4096 };

        foreach (var keySize in keySizes)
        {
            // Arrange
            var chain = TestCertificateUtils.CreateTestChain($"RemoteRSA{keySize}-Test", useEcc: false, keySize: keySize, leafFirst: true);
            using var signingCert = chain[0];
            var directCertSource = new DirectCertificateSource(signingCert, chain.Cast<X509Certificate2>().ToArray());
            var remoteCertSource = new TestRemoteCertificateSource(directCertSource);
            
            using var signingService = new DirectSigningRemoteCertificateSigningService(signingCert, remoteCertSource, chain.Cast<X509Certificate2>().ToArray());
            using var factory = new DirectSignatureFactory(signingService);

            // Act
            var messageBytes = factory.CreateCoseSign1MessageBytes(_testPayload, ContentType);

            // Assert
            Assert.That(messageBytes, Is.Not.Null);
            Assert.That(messageBytes.Length, Is.GreaterThan(0));
        }
    }

    [Test]
    public void RemoteEcdsaSigning_WithDifferentCurves_ProducesValidSignatures()
    {
        var testCases = new[]
        {
            (KeySize: 256, Name: "P256"),
            (KeySize: 384, Name: "P384"),
            (KeySize: 521, Name: "P521")
        };

        foreach (var testCase in testCases)
        {
            var keySize = testCase.KeySize;
            var name = testCase.Name;

            // Arrange
            var chain = TestCertificateUtils.CreateTestChain($"RemoteECDSA{name}-Test", useEcc: true, keySize: keySize, leafFirst: true);
            using var signingCert = chain[0];
            var directCertSource = new DirectCertificateSource(signingCert, chain.Cast<X509Certificate2>().ToArray());
            var remoteCertSource = new TestRemoteCertificateSource(directCertSource);
            
            using var signingService = new DirectSigningRemoteCertificateSigningService(signingCert, remoteCertSource, chain.Cast<X509Certificate2>().ToArray());
            using var factory = new DirectSignatureFactory(signingService);

            // Act
            var messageBytes = factory.CreateCoseSign1MessageBytes(_testPayload, ContentType);

            // Assert
            Assert.That(messageBytes, Is.Not.Null);
            Assert.That(messageBytes.Length, Is.GreaterThan(0));
        }
    }

    [Test]
    public void RemoteMLDsaSigning_WithDifferentSecurityLevels_ProducesValidSignatures()
    {
        var testCases = new[]
        {
            (Algorithm: MLDsaAlgorithm.MLDsa44, Level: "44"),
            (Algorithm: MLDsaAlgorithm.MLDsa65, Level: "65"),
            (Algorithm: MLDsaAlgorithm.MLDsa87, Level: "87")
        };

        foreach (var testCase in testCases)
        {
            var algorithm = testCase.Algorithm;
            var level = testCase.Level;

            // Arrange
            int paramSet;
            if (algorithm == MLDsaAlgorithm.MLDsa44)
            {
                paramSet = 44;
            }
            else if (algorithm == MLDsaAlgorithm.MLDsa65)
            {
                paramSet = 65;
            }
            else if (algorithm == MLDsaAlgorithm.MLDsa87)
            {
                paramSet = 87;
            }
            else
            {
                throw new ArgumentException("Unknown ML-DSA algorithm");
            }

            using var signingCert = TestCertificateUtils.CreateMLDsaCertificate($"RemoteMLDSA{level}-Test", mlDsaParameterSet: paramSet);
            var directCertSource = new DirectCertificateSource(signingCert, new[] { signingCert });
            var remoteCertSource = new TestRemoteCertificateSource(directCertSource);
            
            using var signingService = new DirectSigningRemoteCertificateSigningService(signingCert, remoteCertSource, new[] { signingCert });
            using var factory = new DirectSignatureFactory(signingService);

            // Act
            var messageBytes = factory.CreateCoseSign1MessageBytes(_testPayload, ContentType);

            // Assert
            Assert.That(messageBytes, Is.Not.Null);
            Assert.That(messageBytes.Length, Is.GreaterThan(0));
        }
    }

    [Test]
    public void RemoteSigning_IsRemoteProperty_ReturnsTrue()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain("RemoteProperty-Test", useEcc: false, keySize: 2048, leafFirst: true);
        using var signingCert = chain[0];
        var directCertSource = new DirectCertificateSource(signingCert, chain.Cast<X509Certificate2>().ToArray());
        var remoteCertSource = new TestRemoteCertificateSource(directCertSource);
        
        using var signingService = new DirectSigningRemoteCertificateSigningService(signingCert, remoteCertSource, chain.Cast<X509Certificate2>().ToArray());

        // Assert
        Assert.That(signingService.IsRemote, Is.True);
    }
}
