// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CoseSign1.Direct;
using CoseSign1.Indirect;

namespace CoseSign1.Integration.Tests;

/// <summary>
/// Integration tests verifying that RSA, ECDSA, and ML-DSA certificates can create valid
/// CoseSign1Messages through DirectSignatureFactory and IndirectSignatureFactory.
/// Tests the full signing pipeline: Certificate → LocalCertificateSigningService → Factory → CoseSign1Message
/// </summary>
[TestFixture]
public class CertificateSigningIntegrationTests
{
    private readonly byte[] TestPayload = Encoding.UTF8.GetBytes("Test payload for integration testing");
    private const string ContentType = "application/json";

    /// <summary>
    /// Helper to read int32 from CoseHeaderValue (handles EncodedValue properly)
    /// </summary>
    private static int ReadInt32FromCoseHeaderValue(CoseHeaderValue value)
    {
        var reader = new CborReader(value.EncodedValue);
        return reader.ReadInt32();
    }

    #region RSA Integration Tests

    [Test]
    public void DirectFactory_RSA2048_CreatesValidCoseSign1Message()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain("RSA2048-Test", useEcc: false, keySize: 2048, leafFirst: true);
        using var signingCert = chain[0];
        using var signingService = CertificateSigningService.Create(signingCert, chain.Cast<X509Certificate2>().ToArray());
        using var factory = new DirectSignatureFactory(signingService);

        // Act
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, ContentType);
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Assert
        Assert.That(message, Is.Not.Null);
        Assert.That(message.Content, Is.Not.Null);
        Assert.That(message.Content!.Value.ToArray(), Is.EqualTo(TestPayload));
        Assert.That(message.ProtectedHeaders.ContainsKey(CoseHeaderLabel.Algorithm), Is.True);

        var algValue = message.ProtectedHeaders[CoseHeaderLabel.Algorithm];
        Assert.That(ReadInt32FromCoseHeaderValue(algValue), Is.EqualTo(-37)); // PS256
    }

    [Test]
    public void DirectFactory_RSA3072_CreatesValidCoseSign1Message()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain("RSA3072-Test", useEcc: false, keySize: 3072, leafFirst: true);
        using var signingCert = chain[0];
        using var signingService = CertificateSigningService.Create(signingCert, chain.Cast<X509Certificate2>().ToArray());
        using var factory = new DirectSignatureFactory(signingService);

        // Act
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, ContentType);
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Assert
        Assert.That(message, Is.Not.Null);
        Assert.That(message.Content!.Value.ToArray(), Is.EqualTo(TestPayload));

        var algValue = message.ProtectedHeaders[CoseHeaderLabel.Algorithm];
        Assert.That(ReadInt32FromCoseHeaderValue(algValue), Is.EqualTo(-38)); // PS384
    }

    [Test]
    public void DirectFactory_RSA4096_CreatesValidCoseSign1Message()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain("RSA4096-Test", useEcc: false, keySize: 4096, leafFirst: true);
        using var signingCert = chain[0];
        using var signingService = CertificateSigningService.Create(signingCert, chain.Cast<X509Certificate2>().ToArray());
        using var factory = new DirectSignatureFactory(signingService);

        // Act
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, ContentType);
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Assert
        Assert.That(message, Is.Not.Null);
        Assert.That(message.Content!.Value.ToArray(), Is.EqualTo(TestPayload));

        var algValue = message.ProtectedHeaders[CoseHeaderLabel.Algorithm];
        Assert.That(ReadInt32FromCoseHeaderValue(algValue), Is.EqualTo(-39)); // PS512
    }

    [Test]
    public void IndirectFactory_RSA2048_CreatesValidCoseSign1Message()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain("RSA2048-Indirect", useEcc: false, keySize: 2048, leafFirst: true);
        using var signingCert = chain[0];
        using var signingService = CertificateSigningService.Create(signingCert, chain.Cast<X509Certificate2>().ToArray());
        using var factory = new IndirectSignatureFactory(signingService);

        // Act - Uses default SHA256 for payload hash (RSA2048 standard)
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, ContentType);
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Assert
        Assert.That(message, Is.Not.Null);
        Assert.That(message.Content, Is.Not.Null, "Indirect signature should embed the hash");
        Assert.That(message.Content!.Value.Length, Is.EqualTo(32), "Should contain SHA256 hash (32 bytes)");

        var algValue = message.ProtectedHeaders[CoseHeaderLabel.Algorithm];
        Assert.That(ReadInt32FromCoseHeaderValue(algValue), Is.EqualTo(-37)); // PS256

        var payloadHashAlgLabel = new CoseHeaderLabel(258);
        Assert.That(message.ProtectedHeaders.ContainsKey(payloadHashAlgLabel), Is.True);
    }

    [Test]
    public void IndirectFactory_RSA3072_CreatesValidCoseSign1Message()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain("RSA3072-Indirect", useEcc: false, keySize: 3072, leafFirst: true);
        using var signingCert = chain[0];
        using var signingService = CertificateSigningService.Create(signingCert, chain.Cast<X509Certificate2>().ToArray());
        using var factory = new IndirectSignatureFactory(signingService);

        // Act - Use SHA384 for payload hash to match key size
        var options = new IndirectSignatureOptions { HashAlgorithm = HashAlgorithmName.SHA384 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, ContentType, options);
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Assert
        Assert.That(message, Is.Not.Null);
        Assert.That(message.Content!.Value.Length, Is.EqualTo(48), "Should contain SHA384 hash (48 bytes)");

        var algValue = message.ProtectedHeaders[CoseHeaderLabel.Algorithm];
        Assert.That(ReadInt32FromCoseHeaderValue(algValue), Is.EqualTo(-38)); // PS384
    }

    [Test]
    public void IndirectFactory_RSA4096_CreatesValidCoseSign1Message()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain("RSA4096-Indirect", useEcc: false, keySize: 4096, leafFirst: true);
        using var signingCert = chain[0];
        using var signingService = CertificateSigningService.Create(signingCert, chain.Cast<X509Certificate2>().ToArray());
        using var factory = new IndirectSignatureFactory(signingService);

        // Act - Use SHA512 for payload hash to match key size
        var options = new IndirectSignatureOptions { HashAlgorithm = HashAlgorithmName.SHA512 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, ContentType, options);
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Assert
        Assert.That(message, Is.Not.Null);
        Assert.That(message.Content!.Value.Length, Is.EqualTo(64), "Should contain SHA512 hash (64 bytes)");

        var algValue = message.ProtectedHeaders[CoseHeaderLabel.Algorithm];
        Assert.That(ReadInt32FromCoseHeaderValue(algValue), Is.EqualTo(-39)); // PS512
    }

    #endregion

    #region ECDSA Integration Tests

    [Test]
    public void DirectFactory_ECDSA_P256_CreatesValidCoseSign1Message()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain("ECDSA-P256-Test", useEcc: true, keySize: 256, leafFirst: true);
        using var signingCert = chain[0];
        using var signingService = CertificateSigningService.Create(signingCert, chain.Cast<X509Certificate2>().ToArray());
        using var factory = new DirectSignatureFactory(signingService);

        // Act
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, ContentType);
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Assert
        Assert.That(message, Is.Not.Null);
        Assert.That(message.Content!.Value.ToArray(), Is.EqualTo(TestPayload));

        var algValue = message.ProtectedHeaders[CoseHeaderLabel.Algorithm];
        Assert.That(ReadInt32FromCoseHeaderValue(algValue), Is.EqualTo(-7)); // ES256
    }

    [Test]
    public void DirectFactory_ECDSA_P384_CreatesValidCoseSign1Message()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain("ECDSA-P384-Test", useEcc: true, keySize: 384, leafFirst: true);
        using var signingCert = chain[0];
        using var signingService = CertificateSigningService.Create(signingCert, chain.Cast<X509Certificate2>().ToArray());
        using var factory = new DirectSignatureFactory(signingService);

        // Act
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, ContentType);
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Assert
        Assert.That(message, Is.Not.Null);
        Assert.That(message.Content!.Value.ToArray(), Is.EqualTo(TestPayload));

        var algValue = message.ProtectedHeaders[CoseHeaderLabel.Algorithm];
        Assert.That(ReadInt32FromCoseHeaderValue(algValue), Is.EqualTo(-35)); // ES384
    }

    [Test]
    public void DirectFactory_ECDSA_P521_CreatesValidCoseSign1Message()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain("ECDSA-P521-Test", useEcc: true, keySize: 521, leafFirst: true);
        using var signingCert = chain[0];
        using var signingService = CertificateSigningService.Create(signingCert, chain.Cast<X509Certificate2>().ToArray());
        using var factory = new DirectSignatureFactory(signingService);

        // Act
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, ContentType);
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Assert
        Assert.That(message, Is.Not.Null);
        Assert.That(message.Content!.Value.ToArray(), Is.EqualTo(TestPayload));

        var algValue = message.ProtectedHeaders[CoseHeaderLabel.Algorithm];
        Assert.That(ReadInt32FromCoseHeaderValue(algValue), Is.EqualTo(-36)); // ES512
    }

    [Test]
    public void IndirectFactory_ECDSA_P256_CreatesValidCoseSign1Message()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain("ECDSA-P256-Indirect", useEcc: true, keySize: 256, leafFirst: true);
        using var signingCert = chain[0];
        using var signingService = CertificateSigningService.Create(signingCert, chain.Cast<X509Certificate2>().ToArray());
        using var factory = new IndirectSignatureFactory(signingService);

        // Act
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, ContentType);
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Assert
        Assert.That(message, Is.Not.Null);
        Assert.That(message.Content!.Value.Length, Is.EqualTo(32), "Should contain SHA256 hash");

        var algValue = message.ProtectedHeaders[CoseHeaderLabel.Algorithm];
        Assert.That(ReadInt32FromCoseHeaderValue(algValue), Is.EqualTo(-7)); // ES256

        var payloadHashAlgLabel = new CoseHeaderLabel(258);
        Assert.That(message.ProtectedHeaders.ContainsKey(payloadHashAlgLabel), Is.True);
    }

    [Test]
    public void IndirectFactory_ECDSA_P384_CreatesValidCoseSign1Message()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain("ECDSA-P384-Indirect", useEcc: true, keySize: 384, leafFirst: true);
        using var signingCert = chain[0];
        using var signingService = CertificateSigningService.Create(signingCert, chain.Cast<X509Certificate2>().ToArray());
        using var factory = new IndirectSignatureFactory(signingService);

        // Act - Use SHA384 for payload hash to match curve
        var options = new IndirectSignatureOptions { HashAlgorithm = HashAlgorithmName.SHA384 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, ContentType, options);
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Assert
        Assert.That(message, Is.Not.Null);
        Assert.That(message.Content!.Value.Length, Is.EqualTo(48), "Should contain SHA384 hash");

        var algValue = message.ProtectedHeaders[CoseHeaderLabel.Algorithm];
        Assert.That(ReadInt32FromCoseHeaderValue(algValue), Is.EqualTo(-35)); // ES384
    }

    [Test]
    public void IndirectFactory_ECDSA_P521_CreatesValidCoseSign1Message()
    {
        // Arrange
        var chain = TestCertificateUtils.CreateTestChain("ECDSA-P521-Indirect", useEcc: true, keySize: 521, leafFirst: true);
        using var signingCert = chain[0];
        using var signingService = CertificateSigningService.Create(signingCert, chain.Cast<X509Certificate2>().ToArray());
        using var factory = new IndirectSignatureFactory(signingService);

        // Act - Use SHA512 for payload hash to match curve
        var options = new IndirectSignatureOptions { HashAlgorithm = HashAlgorithmName.SHA512 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, ContentType, options);
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Assert
        Assert.That(message, Is.Not.Null);
        Assert.That(message.Content!.Value.Length, Is.EqualTo(64), "Should contain SHA512 hash");

        var algValue = message.ProtectedHeaders[CoseHeaderLabel.Algorithm];
        Assert.That(ReadInt32FromCoseHeaderValue(algValue), Is.EqualTo(-36)); // ES512
    }

    #endregion

    #region ML-DSA Integration Tests

    [Test]
    public void DirectFactory_MLDSA44_CreatesValidCoseSign1Message()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var mldsaCert = TestCertificateUtils.CreateMLDsaCertificate("MLDSA44-Test", mlDsaParameterSet: 44);
        var rsaChain = TestCertificateUtils.CreateTestChain("MLDSA44-Chain", useEcc: false, leafFirst: true);
        var chain = new List<X509Certificate2> { mldsaCert, rsaChain[1], rsaChain[2] };
        using var signingService = CertificateSigningService.Create(mldsaCert, chain);
        using var factory = new DirectSignatureFactory(signingService);

        // Act
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, ContentType);
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Assert
        Assert.That(message, Is.Not.Null);
        Assert.That(message.Content!.Value.ToArray(), Is.EqualTo(TestPayload));

        var algValue = message.ProtectedHeaders[CoseHeaderLabel.Algorithm];
        Assert.That(ReadInt32FromCoseHeaderValue(algValue), Is.EqualTo(-48)); // ML-DSA-44
    }

    [Test]
    public void DirectFactory_MLDSA65_CreatesValidCoseSign1Message()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var mldsaCert = TestCertificateUtils.CreateMLDsaCertificate("MLDSA65-Test", mlDsaParameterSet: 65);
        var rsaChain = TestCertificateUtils.CreateTestChain("MLDSA65-Chain", useEcc: false, leafFirst: true);
        var chain = new List<X509Certificate2> { mldsaCert, rsaChain[1], rsaChain[2] };
        using var signingService = CertificateSigningService.Create(mldsaCert, chain);
        using var factory = new DirectSignatureFactory(signingService);

        // Act
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, ContentType);
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Assert
        Assert.That(message, Is.Not.Null);
        Assert.That(message.Content!.Value.ToArray(), Is.EqualTo(TestPayload));

        var algValue = message.ProtectedHeaders[CoseHeaderLabel.Algorithm];
        Assert.That(ReadInt32FromCoseHeaderValue(algValue), Is.EqualTo(-49)); // ML-DSA-65
    }

    [Test]
    public void DirectFactory_MLDSA87_CreatesValidCoseSign1Message()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var mldsaCert = TestCertificateUtils.CreateMLDsaCertificate("MLDSA87-Test", mlDsaParameterSet: 87);
        var rsaChain = TestCertificateUtils.CreateTestChain("MLDSA87-Chain", useEcc: false, leafFirst: true);
        var chain = new List<X509Certificate2> { mldsaCert, rsaChain[1], rsaChain[2] };
        using var signingService = CertificateSigningService.Create(mldsaCert, chain);
        using var factory = new DirectSignatureFactory(signingService);

        // Act
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, ContentType);
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Assert
        Assert.That(message, Is.Not.Null);
        Assert.That(message.Content!.Value.ToArray(), Is.EqualTo(TestPayload));

        var algValue = message.ProtectedHeaders[CoseHeaderLabel.Algorithm];
        Assert.That(ReadInt32FromCoseHeaderValue(algValue), Is.EqualTo(-50)); // ML-DSA-87
    }

    [Test]
    public void IndirectFactory_MLDSA44_CreatesValidCoseSign1Message()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var mldsaCert = TestCertificateUtils.CreateMLDsaCertificate("MLDSA44-Indirect", mlDsaParameterSet: 44);
        var rsaChain = TestCertificateUtils.CreateTestChain("MLDSA44-Indirect-Chain", useEcc: false, leafFirst: true);
        var chain = new List<X509Certificate2> { mldsaCert, rsaChain[1], rsaChain[2] };
        using var signingService = CertificateSigningService.Create(mldsaCert, chain);
        using var factory = new IndirectSignatureFactory(signingService);

        // Act
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, ContentType);
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Assert
        Assert.That(message, Is.Not.Null);
        Assert.That(message.Content!.Value.Length, Is.EqualTo(32), "ML-DSA-44 uses SHA256, should contain 32-byte hash");

        var algValue = message.ProtectedHeaders[CoseHeaderLabel.Algorithm];
        Assert.That(ReadInt32FromCoseHeaderValue(algValue), Is.EqualTo(-48)); // ML-DSA-44

        var payloadHashAlgLabel = new CoseHeaderLabel(258);
        Assert.That(message.ProtectedHeaders.ContainsKey(payloadHashAlgLabel), Is.True);
    }

    [Test]
    public void IndirectFactory_MLDSA65_CreatesValidCoseSign1Message()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var mldsaCert = TestCertificateUtils.CreateMLDsaCertificate("MLDSA65-Indirect", mlDsaParameterSet: 65);
        var rsaChain = TestCertificateUtils.CreateTestChain("MLDSA65-Indirect-Chain", useEcc: false, leafFirst: true);
        var chain = new List<X509Certificate2> { mldsaCert, rsaChain[1], rsaChain[2] };
        using var signingService = CertificateSigningService.Create(mldsaCert, chain);
        using var factory = new IndirectSignatureFactory(signingService);

        // Act - Use SHA384 for payload hash (ML-DSA-65 standard)
        var options = new IndirectSignatureOptions { HashAlgorithm = HashAlgorithmName.SHA384 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, ContentType, options);
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Assert
        Assert.That(message, Is.Not.Null);
        Assert.That(message.Content!.Value.Length, Is.EqualTo(48), "ML-DSA-65 uses SHA384, should contain 48-byte hash");

        var algValue = message.ProtectedHeaders[CoseHeaderLabel.Algorithm];
        Assert.That(ReadInt32FromCoseHeaderValue(algValue), Is.EqualTo(-49)); // ML-DSA-65

        var payloadHashAlgLabel = new CoseHeaderLabel(258);
        Assert.That(message.ProtectedHeaders.ContainsKey(payloadHashAlgLabel), Is.True);
    }

    [Test]
    public void IndirectFactory_MLDSA87_CreatesValidCoseSign1Message()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange
        using var mldsaCert = TestCertificateUtils.CreateMLDsaCertificate("MLDSA87-Indirect", mlDsaParameterSet: 87);
        var rsaChain = TestCertificateUtils.CreateTestChain("MLDSA87-Indirect-Chain", useEcc: false, leafFirst: true);
        var chain = new List<X509Certificate2> { mldsaCert, rsaChain[1], rsaChain[2] };
        using var signingService = CertificateSigningService.Create(mldsaCert, chain);
        using var factory = new IndirectSignatureFactory(signingService);

        // Act - Use SHA512 for payload hash (ML-DSA-87 standard)
        var options = new IndirectSignatureOptions { HashAlgorithm = HashAlgorithmName.SHA512 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, ContentType, options);
        var message = CoseMessage.DecodeSign1(messageBytes);

        // Assert
        Assert.That(message, Is.Not.Null);
        Assert.That(message.Content!.Value.Length, Is.EqualTo(64), "ML-DSA-87 uses SHA512, should contain 64-byte hash");

        var algValue = message.ProtectedHeaders[CoseHeaderLabel.Algorithm];
        Assert.That(ReadInt32FromCoseHeaderValue(algValue), Is.EqualTo(-50)); // ML-DSA-87

        var payloadHashAlgLabel = new CoseHeaderLabel(258);
        Assert.That(message.ProtectedHeaders.ContainsKey(payloadHashAlgLabel), Is.True);
    }

    #endregion

    #region Cross-Algorithm Verification Tests

    [Test]
    public void DirectFactory_AllAlgorithms_ProduceDistinctCoseAlgorithmIds()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange & Act
        var results = new Dictionary<string, int>();

        // RSA2048
        {
            var rsaChain = TestCertificateUtils.CreateTestChain("RSA-CrossAlgo", useEcc: false, keySize: 2048, leafFirst: true);
            using var rsaCert = rsaChain[0];
            using var service = CertificateSigningService.Create(rsaCert, rsaChain.Cast<X509Certificate2>().ToArray());
            using var factory = new DirectSignatureFactory(service);
            var msg = CoseMessage.DecodeSign1(factory.CreateCoseSign1MessageBytes(TestPayload, ContentType));
            results["RSA2048"] = ReadInt32FromCoseHeaderValue(msg.ProtectedHeaders[CoseHeaderLabel.Algorithm]);
        }

        // ECDSA-P256
        {
            var ecdsaChain = TestCertificateUtils.CreateTestChain("ECDSA-CrossAlgo", useEcc: true, keySize: 256, leafFirst: true);
            using var ecdsaCert = ecdsaChain[0];
            using var service = CertificateSigningService.Create(ecdsaCert, ecdsaChain.Cast<X509Certificate2>().ToArray());
            using var factory = new DirectSignatureFactory(service);
            var msg = CoseMessage.DecodeSign1(factory.CreateCoseSign1MessageBytes(TestPayload, ContentType));
            results["ECDSA-P256"] = ReadInt32FromCoseHeaderValue(msg.ProtectedHeaders[CoseHeaderLabel.Algorithm]);
        }

        // MLDSA44
        {
            using var mldsaCert = TestCertificateUtils.CreateMLDsaCertificate("MLDSA-CrossAlgo", mlDsaParameterSet: 44);
            var tempChain = TestCertificateUtils.CreateTestChain("MLDSA-CrossAlgo-Chain", useEcc: false, leafFirst: true);
            var mldsaChain = new List<X509Certificate2> { mldsaCert, tempChain[1], tempChain[2] };
            using var service = CertificateSigningService.Create(mldsaCert, mldsaChain);
            using var factory = new DirectSignatureFactory(service);
            var msg = CoseMessage.DecodeSign1(factory.CreateCoseSign1MessageBytes(TestPayload, ContentType));
            results["MLDSA44"] = ReadInt32FromCoseHeaderValue(msg.ProtectedHeaders[CoseHeaderLabel.Algorithm]);
        }

        // Assert
        Assert.That(results["RSA2048"], Is.EqualTo(-37)); // PS256
        Assert.That(results["ECDSA-P256"], Is.EqualTo(-7)); // ES256
        Assert.That(results["MLDSA44"], Is.EqualTo(-48)); // ML-DSA-44

        // Verify all distinct
        Assert.That(results.Values.Distinct().Count(), Is.EqualTo(3));
    }

    [Test]
    public void IndirectFactory_AllAlgorithms_ProduceValidHashEnvelopes()
    {
        PlatformHelper.SkipIfMLDsaNotSupported();

        // Arrange & Act - Verify all algorithms work with indirect signatures
        var algorithms = new[] { "RSA2048", "ECDSA-P256", "MLDSA44" };
        var payloadHashAlgLabel = new CoseHeaderLabel(258);

        foreach (var algorithm in algorithms)
        {
            X509Certificate2? cert = null;
            List<X509Certificate2>? chain = null;

            try
            {
                if (algorithm == "RSA2048")
                {
                    var rsaChain = TestCertificateUtils.CreateTestChain("RSA-Indirect-CrossAlgo", useEcc: false, keySize: 2048, leafFirst: true);
                    cert = rsaChain[0];
                    chain = new List<X509Certificate2> { rsaChain[0], rsaChain[1], rsaChain[2] };
                }
                else if (algorithm == "ECDSA-P256")
                {
                    var ecdsaChain = TestCertificateUtils.CreateTestChain("ECDSA-Indirect-CrossAlgo", useEcc: true, keySize: 256, leafFirst: true);
                    cert = ecdsaChain[0];
                    chain = new List<X509Certificate2> { ecdsaChain[0], ecdsaChain[1], ecdsaChain[2] };
                }
                else // MLDSA44
                {
                    cert = TestCertificateUtils.CreateMLDsaCertificate("MLDSA-Indirect-CrossAlgo", mlDsaParameterSet: 44);
                    var tempChain = TestCertificateUtils.CreateTestChain("MLDSA-Indirect-CrossAlgo-Chain", useEcc: false, leafFirst: true);
                    chain = new List<X509Certificate2> { cert, tempChain[1], tempChain[2] };
                }

                using var service = CertificateSigningService.Create(cert, chain);
                using var factory = new IndirectSignatureFactory(service);

                var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, ContentType);
                var message = CoseMessage.DecodeSign1(messageBytes);

                // Assert
                Assert.That(message, Is.Not.Null, $"{algorithm} should produce valid message");
                Assert.That(message.ProtectedHeaders.ContainsKey(payloadHashAlgLabel),
                    Is.True, $"{algorithm} should include PayloadHashAlg header (258)");
                Assert.That(message.Content!.Value.Length, Is.EqualTo(32),
                    $"{algorithm} should embed SHA256 hash (all use SHA256 for 2048/P-256/44)");
            }
            finally
            {
                if (algorithm == "MLDSA44" && cert != null)
                {
                    cert.Dispose();
                }
            }
        }
    }

    #endregion
}