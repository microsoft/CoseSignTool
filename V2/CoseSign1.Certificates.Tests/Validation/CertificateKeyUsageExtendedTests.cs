// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Validation;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;

/// <summary>
/// Extended tests for CertificateKeyUsageAssertionProvider covering more scenarios.
/// </summary>
[TestFixture]
[Category("Validation")]
public class CertificateKeyUsageExtendedTests
{
    private X509Certificate2? _certWithDigitalSignature;
    private X509Certificate2? _certWithCodeSigningEku;
    private X509Certificate2? _certWithClientAuthEku;
    private X509Certificate2? _certWithNoKeyUsage;
    private CoseSign1Message? _dummyMessage;

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        // Create certificate with DigitalSignature key usage
        using var rsa1 = RSA.Create(2048);
        var req1 = new CertificateRequest(
            "CN=Digital Signature Test",
            rsa1,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        req1.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        _certWithDigitalSignature = req1.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(365));

        // Create certificate with Code Signing EKU
        using var rsa2 = RSA.Create(2048);
        var req2 = new CertificateRequest(
            "CN=Code Signing Test",
            rsa2,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var codeSigningOid = new OidCollection { new Oid("1.3.6.1.5.5.7.3.3", "Code Signing") };
        req2.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(codeSigningOid, critical: true));
        _certWithCodeSigningEku = req2.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(365));

        // Create certificate with Client Authentication EKU
        using var rsa3 = RSA.Create(2048);
        var req3 = new CertificateRequest(
            "CN=Client Auth Test",
            rsa3,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var clientAuthOid = new OidCollection { new Oid("1.3.6.1.5.5.7.3.2", "Client Authentication") };
        req3.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(clientAuthOid, critical: true));
        _certWithClientAuthEku = req3.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(365));

        // Create certificate without any key usage extension
        using var rsa4 = RSA.Create(2048);
        var req4 = new CertificateRequest(
            "CN=No Key Usage Test",
            rsa4,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        _certWithNoKeyUsage = req4.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(365));

        _dummyMessage = CreateDummyMessage();
    }

    [OneTimeTearDown]
    public void OneTimeTearDown()
    {
        _certWithDigitalSignature?.Dispose();
        _certWithCodeSigningEku?.Dispose();
        _certWithClientAuthEku?.Dispose();
        _certWithNoKeyUsage?.Dispose();
    }

    #region Key Usage Validation Tests

    [Test]
    public void ExtractAssertions_WithMatchingKeyUsage_ReturnsValid()
    {
        // Arrange
        var provider = new CertificateKeyUsageAssertionProvider(X509KeyUsageFlags.DigitalSignature);
        var signingKey = new X509CertificateSigningKey(_certWithDigitalSignature!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509KeyUsageAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.IsValid, Is.True);
    }

    [Test]
    public void ExtractAssertions_WithMissingKeyUsage_ReturnsInvalid()
    {
        // Arrange - asking for KeyEncipherment but cert only has DigitalSignature
        var provider = new CertificateKeyUsageAssertionProvider(X509KeyUsageFlags.KeyEncipherment);
        var signingKey = new X509CertificateSigningKey(_certWithDigitalSignature!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509KeyUsageAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.IsValid, Is.False);
    }

    [Test]
    public void ExtractAssertions_WithNoKeyUsageExtension_ReturnsInvalid()
    {
        // Arrange
        var provider = new CertificateKeyUsageAssertionProvider(X509KeyUsageFlags.DigitalSignature);
        var signingKey = new X509CertificateSigningKey(_certWithNoKeyUsage!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509KeyUsageAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.IsValid, Is.False);
    }

    #endregion

    #region EKU Validation Tests

    [Test]
    public void ExtractAssertions_WithMatchingEku_ReturnsValid()
    {
        // Arrange
        var provider = new CertificateKeyUsageAssertionProvider("1.3.6.1.5.5.7.3.3"); // Code Signing
        var signingKey = new X509CertificateSigningKey(_certWithCodeSigningEku!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509KeyUsageAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.IsValid, Is.True);
    }

    [Test]
    public void ExtractAssertions_WithNonMatchingEku_ReturnsInvalid()
    {
        // Arrange - asking for Code Signing but cert has Client Auth
        var provider = new CertificateKeyUsageAssertionProvider("1.3.6.1.5.5.7.3.3"); // Code Signing
        var signingKey = new X509CertificateSigningKey(_certWithClientAuthEku!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509KeyUsageAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.IsValid, Is.False);
    }

    [Test]
    public void ExtractAssertions_WithNoEkuExtension_ReturnsInvalid()
    {
        // Arrange
        var provider = new CertificateKeyUsageAssertionProvider("1.3.6.1.5.5.7.3.3"); // Code Signing
        var signingKey = new X509CertificateSigningKey(_certWithNoKeyUsage!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509KeyUsageAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.IsValid, Is.False);
    }

    [Test]
    public void ExtractAssertions_WithOidObject_MatchingEku_ReturnsValid()
    {
        // Arrange
        var eku = new Oid("1.3.6.1.5.5.7.3.3", "Code Signing");
        var provider = new CertificateKeyUsageAssertionProvider(eku);
        var signingKey = new X509CertificateSigningKey(_certWithCodeSigningEku!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509KeyUsageAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.IsValid, Is.True);
    }

    #endregion

    #region Constructor Tests

    [Test]
    public void Constructor_WithNullOid_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new CertificateKeyUsageAssertionProvider((Oid)null!));
    }

    [Test]
    public void Constructor_WithNullOrWhitespaceOidString_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            new CertificateKeyUsageAssertionProvider(string.Empty));
        Assert.Throws<ArgumentException>(() =>
            new CertificateKeyUsageAssertionProvider("  "));
    }

    [Test]
    public void Constructor_WithLogger_CreatesProvider()
    {
        // Arrange
        var mockLogger = new Mock<ILogger<CertificateKeyUsageAssertionProvider>>().Object;

        // Act
        var provider = new CertificateKeyUsageAssertionProvider(
            X509KeyUsageFlags.DigitalSignature,
            mockLogger);

        // Assert
        Assert.That(provider, Is.Not.Null);
    }

    #endregion

    #region ExtractAssertionsAsync Tests

    [Test]
    public async Task ExtractAssertionsAsync_ReturnsAssertions()
    {
        // Arrange
        var provider = new CertificateKeyUsageAssertionProvider(X509KeyUsageFlags.DigitalSignature);
        var signingKey = new X509CertificateSigningKey(_certWithDigitalSignature!);

        // Act
        var assertions = await provider.ExtractAssertionsAsync(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
    }

    #endregion

    #region Helper Methods

    private static CoseSign1Message CreateDummyMessage()
    {
        var writer = new CborWriter();
        writer.WriteStartArray(4); // COSE_Sign1 structure
        writer.WriteByteString(Array.Empty<byte>()); // Protected
        writer.WriteStartMap(0); // Unprotected
        writer.WriteEndMap();
        writer.WriteByteString(Array.Empty<byte>()); // Payload
        writer.WriteByteString(Array.Empty<byte>()); // Signature
        writer.WriteEndArray();
        return CoseMessage.DecodeSign1(writer.Encode());
    }

    #endregion
}
