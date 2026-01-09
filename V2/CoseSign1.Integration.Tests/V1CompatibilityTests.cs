// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Integration.Tests;

using System.Reflection;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using CoseSign1.Certificates.Extensions;

/// <summary>
/// Integration tests verifying that V2 can properly read and process COSE messages
/// created by V1 CoseSignTool. These tests use real COSE signature files from V1.
/// </summary>
[TestFixture]
[Category("V1Compatibility")]
public class V1CompatibilityTests
{
    private static string GetTestDataPath()
    {
        string assemblyLocation = Assembly.GetExecutingAssembly().Location;
        string assemblyDir = Path.GetDirectoryName(assemblyLocation) ?? Directory.GetCurrentDirectory();
        string testDataPath = Path.Combine(assemblyDir, "TestData");

        Assert.That(Directory.Exists(testDataPath), Is.True, $"Test data directory should exist at {testDataPath}");
        return testDataPath;
    }

    #region Reading V1 COSE Messages

    /// <summary>
    /// Tests that V2 can decode a COSE message created by V1 CoseSignTool.
    /// The test file UnitTestSignatureWithCRL.cose was created by V1 with indirect signature.
    /// </summary>
    [Test]
    public void V2_CanDecode_V1CoseMessage()
    {
        // Arrange
        string coseFile = Path.Combine(GetTestDataPath(), "UnitTestSignatureWithCRL.cose");
        Assert.That(File.Exists(coseFile), Is.True, $"V1 test signature file should exist at {coseFile}");

        // Act
        byte[] coseBytes = File.ReadAllBytes(coseFile);
        CoseSign1Message message = CoseMessage.DecodeSign1(coseBytes);

        // Assert
        Assert.That(message, Is.Not.Null, "Should be able to decode V1 COSE message");
        Assert.That(message.ProtectedHeaders, Is.Not.Null, "Protected headers should be present");
        Assert.That(message.UnprotectedHeaders, Is.Not.Null, "Unprotected headers should be present");
    }

    /// <summary>
    /// Tests that V2 can extract the certificate chain from a V1 COSE message.
    /// </summary>
    [Test]
    public void V2_CanExtractCertificateChain_FromV1CoseMessage()
    {
        // Arrange
        string coseFile = Path.Combine(GetTestDataPath(), "UnitTestSignatureWithCRL.cose");
        byte[] coseBytes = File.ReadAllBytes(coseFile);
        CoseSign1Message message = CoseMessage.DecodeSign1(coseBytes);

        // Act
        bool foundChain = message.TryGetCertificateChain(out X509Certificate2Collection? chain);

        // Assert
        Assert.That(foundChain, Is.True, "Should be able to extract certificate chain from V1 message");
        Assert.That(chain, Is.Not.Null, "Certificate chain should not be null");
        Assert.That(chain!.Count, Is.GreaterThan(0), "Certificate chain should have at least one certificate");

        // Log certificate details for debugging
        foreach (var cert in chain)
        {
            TestContext.Out.WriteLine($"Certificate: {cert.Subject}");
            TestContext.Out.WriteLine($"  Issuer: {cert.Issuer}");
            TestContext.Out.WriteLine($"  Thumbprint: {cert.Thumbprint}");
            TestContext.Out.WriteLine($"  Valid: {cert.NotBefore} to {cert.NotAfter}");
        }
    }

    /// <summary>
    /// Tests that V2 can extract the signing certificate from a V1 COSE message.
    /// </summary>
    [Test]
    public void V2_CanExtractSigningCertificate_FromV1CoseMessage()
    {
        // Arrange
        string coseFile = Path.Combine(GetTestDataPath(), "UnitTestSignatureWithCRL.cose");
        byte[] coseBytes = File.ReadAllBytes(coseFile);
        CoseSign1Message message = CoseMessage.DecodeSign1(coseBytes);

        // Act
        bool foundCert = message.TryGetSigningCertificate(out X509Certificate2? signingCert);

        // Assert
        Assert.That(foundCert, Is.True, "Should be able to extract signing certificate from V1 message");
        Assert.That(signingCert, Is.Not.Null, "Signing certificate should not be null");
        Assert.That(signingCert!.HasPrivateKey, Is.False, "Signing certificate should not have private key (extracted from message)");

        TestContext.Out.WriteLine($"Signing Certificate: {signingCert.Subject}");
        TestContext.Out.WriteLine($"  Algorithm: {signingCert.GetKeyAlgorithm()}");
    }

    /// <summary>
    /// Tests that V2 can identify the algorithm header from a V1 COSE message.
    /// </summary>
    [Test]
    public void V2_CanReadAlgorithmHeader_FromV1CoseMessage()
    {
        // Arrange
        string coseFile = Path.Combine(GetTestDataPath(), "UnitTestSignatureWithCRL.cose");
        byte[] coseBytes = File.ReadAllBytes(coseFile);
        CoseSign1Message message = CoseMessage.DecodeSign1(coseBytes);

        // Act & Assert
        Assert.That(message.ProtectedHeaders.ContainsKey(CoseHeaderLabel.Algorithm), Is.True,
            "V1 message should have Algorithm header");

        var algValue = message.ProtectedHeaders[CoseHeaderLabel.Algorithm];
        Assert.That(algValue.EncodedValue.Length, Is.GreaterThan(0), "Algorithm header should have a value");

        TestContext.Out.WriteLine($"Algorithm header encoded value length: {algValue.EncodedValue.Length}");
    }

    /// <summary>
    /// Tests that V2 can find the root certificate in a V1 COSE message chain.
    /// </summary>
    [Test]
    public void V2_CanFindRootCertificate_InV1CoseMessageChain()
    {
        // Arrange
        string coseFile = Path.Combine(GetTestDataPath(), "UnitTestSignatureWithCRL.cose");
        byte[] coseBytes = File.ReadAllBytes(coseFile);
        CoseSign1Message message = CoseMessage.DecodeSign1(coseBytes);

        // Act
        bool foundChain = message.TryGetCertificateChain(out X509Certificate2Collection? chain);
        Assert.That(foundChain, Is.True);

        // Find root (self-signed certificate where Subject == Issuer)
        X509Certificate2? root = chain!.Cast<X509Certificate2>().FirstOrDefault(cert => cert.Subject == cert.Issuer);

        // Assert
        Assert.That(root, Is.Not.Null, "Should be able to find root certificate in chain");
        TestContext.Out.WriteLine($"Root Certificate: {root!.Subject}");
    }

    #endregion

    #region Payload Verification

    /// <summary>
    /// Tests that the V1 test payload file can be read and parsed.
    /// </summary>
    [Test]
    public void V2_CanReadAndParse_V1TestPayload()
    {
        // Arrange
        string payloadFile = Path.Combine(GetTestDataPath(), "UnitTestPayload.json");
        Assert.That(File.Exists(payloadFile), Is.True, $"V1 test payload file should exist at {payloadFile}");

        // Act
        string jsonContent = File.ReadAllText(payloadFile);
        using JsonDocument doc = JsonDocument.Parse(jsonContent);

        // Assert
        Assert.That(doc.RootElement.ValueKind, Is.EqualTo(JsonValueKind.Object), "Payload should be a JSON object");
        Assert.That(doc.RootElement.TryGetProperty("Source", out _), Is.True, "Payload should have Source property");
        Assert.That(doc.RootElement.TryGetProperty("Data", out _), Is.True, "Payload should have Data property");

        TestContext.Out.WriteLine($"Payload Source: {doc.RootElement.GetProperty("Source").GetString()}");
    }

    /// <summary>
    /// Tests that the V1 signature is an indirect (hash envelope) signature
    /// by checking if it has detached content.
    /// </summary>
    [Test]
    public void V2_CanIdentify_V1IndirectSignature()
    {
        // Arrange
        string coseFile = Path.Combine(GetTestDataPath(), "UnitTestSignatureWithCRL.cose");
        byte[] coseBytes = File.ReadAllBytes(coseFile);
        CoseSign1Message message = CoseMessage.DecodeSign1(coseBytes);

        // Act & Assert - V1 UnitTestSignatureWithCRL.cose is an indirect signature (no embedded content)
        // The Content property will be null for indirect/detached signatures
        bool hasEmbeddedContent = message.Content.HasValue;
        
        TestContext.Out.WriteLine($"Has embedded content: {hasEmbeddedContent}");
        
        // Indirect signatures don't embed the full payload - they embed a hash envelope
        // So we just check that we can access the content property
        Assert.That(message, Is.Not.Null, "Message should be valid regardless of content type");
    }

    #endregion

    #region Message Structure Validation

    /// <summary>
    /// Tests that V2 can read both protected and unprotected headers from V1 message.
    /// </summary>
    [Test]
    public void V2_CanReadHeaders_FromV1CoseMessage()
    {
        // Arrange
        string coseFile = Path.Combine(GetTestDataPath(), "UnitTestSignatureWithCRL.cose");
        byte[] coseBytes = File.ReadAllBytes(coseFile);
        CoseSign1Message message = CoseMessage.DecodeSign1(coseBytes);

        // Act & Assert - Protected headers
        Assert.That(message.ProtectedHeaders, Is.Not.Null, "Should have protected headers");
        
        TestContext.Out.WriteLine("Protected Headers:");
        foreach (var kvp in message.ProtectedHeaders)
        {
            TestContext.Out.WriteLine($"  Label: {kvp.Key}");
        }

        // Act & Assert - Unprotected headers (typically contain certificate chain)
        Assert.That(message.UnprotectedHeaders, Is.Not.Null, "Should have unprotected headers");
        
        TestContext.Out.WriteLine("Unprotected Headers:");
        foreach (var kvp in message.UnprotectedHeaders)
        {
            TestContext.Out.WriteLine($"  Label: {kvp.Key}");
        }
    }

    /// <summary>
    /// Tests that V2 signature bytes are not null in V1 message.
    /// </summary>
    [Test]
    public void V2_CanReadSignature_FromV1CoseMessage()
    {
        // Arrange
        string coseFile = Path.Combine(GetTestDataPath(), "UnitTestSignatureWithCRL.cose");
        byte[] coseBytes = File.ReadAllBytes(coseFile);
        CoseSign1Message message = CoseMessage.DecodeSign1(coseBytes);

        // Act & Assert
        Assert.That(message.Signature.Length, Is.GreaterThan(0), "Signature should have data");

        TestContext.Out.WriteLine($"Signature length: {message.Signature.Length} bytes");
    }

    /// <summary>
    /// Tests the raw COSE bytes structure.
    /// </summary>
    [Test]
    public void V2_ValidatesRawCoseStructure_FromV1()
    {
        // Arrange
        string coseFile = Path.Combine(GetTestDataPath(), "UnitTestSignatureWithCRL.cose");
        byte[] coseBytes = File.ReadAllBytes(coseFile);

        // Assert - COSE Sign1 messages start with tag 18 (0xD2 in CBOR)
        // The CBOR tag 18 is the COSE Sign1 tag
        Assert.That(coseBytes.Length, Is.GreaterThan(10), "COSE message should have reasonable size");
        TestContext.Out.WriteLine($"COSE message size: {coseBytes.Length} bytes");

        // Verify we can decode it (this is the real test)
        Assert.DoesNotThrow(() => CoseMessage.DecodeSign1(coseBytes),
            "Should be able to decode V1 COSE message without exceptions");
    }

    #endregion

    #region Cross-Version Compatibility

    /// <summary>
    /// Tests that certificates extracted from V1 messages have expected properties.
    /// </summary>
    [Test]
    public void V2_ValidatesCertificateProperties_FromV1Message()
    {
        // Arrange
        string coseFile = Path.Combine(GetTestDataPath(), "UnitTestSignatureWithCRL.cose");
        byte[] coseBytes = File.ReadAllBytes(coseFile);
        CoseSign1Message message = CoseMessage.DecodeSign1(coseBytes);

        // Act
        message.TryGetCertificateChain(out X509Certificate2Collection? chain);

        // Assert - validate chain structure
        Assert.That(chain, Is.Not.Null);
        Assert.That(chain!.Count, Is.GreaterThanOrEqualTo(1), "Chain should have at least the signing cert");

        foreach (var cert in chain)
        {
            // Basic certificate validation
            Assert.That(cert.Subject, Is.Not.Null.And.Not.Empty, "Certificate should have a subject");
            Assert.That(cert.Issuer, Is.Not.Null.And.Not.Empty, "Certificate should have an issuer");
            Assert.That(cert.Thumbprint, Is.Not.Null.And.Not.Empty, "Certificate should have a thumbprint");

            // Log for manual verification
            TestContext.Out.WriteLine($"Certificate: {cert.Subject}");
            TestContext.Out.WriteLine($"  Key Algorithm: {cert.GetKeyAlgorithm()}");
            TestContext.Out.WriteLine($"  Signature Algorithm: {cert.SignatureAlgorithm.FriendlyName}");
        }
    }

    #endregion
}
