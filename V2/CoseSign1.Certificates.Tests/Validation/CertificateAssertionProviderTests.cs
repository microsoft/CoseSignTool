// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.Validation;
using Moq;
using NUnit.Framework;

/// <summary>
/// Tests for certificate assertion providers.
/// </summary>
[TestFixture]
[Category("Validation")]
public class CertificateAssertionProviderTests
{
    private X509Certificate2? _validCert;
    private X509Certificate2? _expiredCert;
    private X509Certificate2? _futureCert;
    private CoseSign1Message? _dummyMessage;

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        // Create a valid certificate
        using var rsaValid = RSA.Create(2048);
        var validReq = new CertificateRequest(
            "CN=Valid Test Certificate",
            rsaValid,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        _validCert = validReq.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-30),
            DateTimeOffset.UtcNow.AddDays(365));

        // Create an expired certificate
        using var rsaExpired = RSA.Create(2048);
        var expiredReq = new CertificateRequest(
            "CN=Expired Test Certificate",
            rsaExpired,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        _expiredCert = expiredReq.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-365),
            DateTimeOffset.UtcNow.AddDays(-1));

        // Create a not-yet-valid certificate
        using var rsaFuture = RSA.Create(2048);
        var futureReq = new CertificateRequest(
            "CN=Future Test Certificate",
            rsaFuture,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        _futureCert = futureReq.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(1),
            DateTimeOffset.UtcNow.AddDays(365));

        // Create a minimal dummy message
        var writer = new CborWriter();
        writer.WriteStartArray(4); // COSE_Sign1 structure
        writer.WriteByteString(Array.Empty<byte>()); // Protected
        writer.WriteStartMap(0); // Unprotected
        writer.WriteEndMap();
        writer.WriteByteString(Array.Empty<byte>()); // Payload
        writer.WriteByteString(Array.Empty<byte>()); // Signature
        writer.WriteEndArray();
        var messageBytes = writer.Encode();
        _dummyMessage = CoseMessage.DecodeSign1(messageBytes);
    }

    [OneTimeTearDown]
    public void OneTimeTearDown()
    {
        _validCert?.Dispose();
        _expiredCert?.Dispose();
        _futureCert?.Dispose();
    }

    #region CertificateExpirationAssertionProvider Tests

    [Test]
    public void CertificateExpirationAssertionProvider_ComponentName_IsCorrect()
    {
        // Arrange
        var provider = new CertificateExpirationAssertionProvider();

        // Assert
        Assert.That(provider.ComponentName, Is.EqualTo(nameof(CertificateExpirationAssertionProvider)));
    }

    [Test]
    public void CertificateExpirationAssertionProvider_WithValidCert_ReturnsValidAssertion()
    {
        // Arrange
        var provider = new CertificateExpirationAssertionProvider();
        var signingKey = new X509CertificateSigningKey(_validCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509ValidityAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.IsValid, Is.True);
        Assert.That(assertion.SigningKey, Is.SameAs(signingKey));
    }

    [Test]
    public void CertificateExpirationAssertionProvider_WithExpiredCert_ReturnsExpiredAssertion()
    {
        // Arrange
        var provider = new CertificateExpirationAssertionProvider();
        var signingKey = new X509CertificateSigningKey(_expiredCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509ValidityAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.IsValid, Is.False);
        Assert.That(assertion.IsExpired, Is.True);
    }

    [Test]
    public void CertificateExpirationAssertionProvider_WithFutureCert_ReturnsNotYetValidAssertion()
    {
        // Arrange
        var provider = new CertificateExpirationAssertionProvider();
        var signingKey = new X509CertificateSigningKey(_futureCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509ValidityAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.IsValid, Is.False);
        Assert.That(assertion.IsExpired, Is.False);
    }

    [Test]
    public void CertificateExpirationAssertionProvider_WithSpecificTime_ValidatesAtThatTime()
    {
        // Arrange - use a time when the "expired" cert was valid
        var validationTime = DateTime.UtcNow.AddDays(-100);
        var provider = new CertificateExpirationAssertionProvider(validationTime);
        var signingKey = new X509CertificateSigningKey(_expiredCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509ValidityAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.IsValid, Is.True); // Was valid 100 days ago
    }

    [Test]
    public void CertificateExpirationAssertionProvider_WithNonX509Key_ReturnsEmpty()
    {
        // Arrange
        var provider = new CertificateExpirationAssertionProvider();
        var mockSigningKey = new Mock<ISigningKey>().Object;

        // Act
        var assertions = provider.ExtractAssertions(mockSigningKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Is.Empty);
    }

    [Test]
    public async Task CertificateExpirationAssertionProvider_ExtractAssertionsAsync_Works()
    {
        // Arrange
        var provider = new CertificateExpirationAssertionProvider();
        var signingKey = new X509CertificateSigningKey(_validCert!);

        // Act
        var assertions = await provider.ExtractAssertionsAsync(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
    }

    #endregion

    #region CertificateCommonNameAssertionProvider Tests

    [Test]
    public void CertificateCommonNameAssertionProvider_ComponentName_IsCorrect()
    {
        // Arrange
        var provider = new CertificateCommonNameAssertionProvider("CN=Test");

        // Assert
        Assert.That(provider.ComponentName, Is.EqualTo(nameof(CertificateCommonNameAssertionProvider)));
    }

    [Test]
    public void CertificateCommonNameAssertionProvider_WithMatchingCN_ReturnsMatchingAssertion()
    {
        // Arrange
        var provider = new CertificateCommonNameAssertionProvider("Valid Test Certificate");
        var signingKey = new X509CertificateSigningKey(_validCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509CommonNameAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.Matches, Is.True);
    }

    [Test]
    public void CertificateCommonNameAssertionProvider_WithNonMatchingCN_ReturnsNonMatchingAssertion()
    {
        // Arrange
        var provider = new CertificateCommonNameAssertionProvider("Wrong Name");
        var signingKey = new X509CertificateSigningKey(_validCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509CommonNameAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.Matches, Is.False);
    }

    [Test]
    public void CertificateCommonNameAssertionProvider_WithNonX509Key_ReturnsEmpty()
    {
        // Arrange
        var provider = new CertificateCommonNameAssertionProvider("Test");
        var mockSigningKey = new Mock<ISigningKey>().Object;

        // Act
        var assertions = provider.ExtractAssertions(mockSigningKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Is.Empty);
    }

    #endregion

    #region CertificateIssuerAssertionProvider Tests

    [Test]
    public void CertificateIssuerAssertionProvider_ComponentName_IsCorrect()
    {
        // Arrange
        var provider = new CertificateIssuerAssertionProvider("CN=Test Issuer");

        // Assert
        Assert.That(provider.ComponentName, Is.EqualTo(nameof(CertificateIssuerAssertionProvider)));
    }

    [Test]
    public void CertificateIssuerAssertionProvider_WithSelfSignedCert_IssuerMatchesSubject()
    {
        // Arrange - self-signed cert has Issuer = Subject
        var provider = new CertificateIssuerAssertionProvider("Valid Test Certificate");
        var signingKey = new X509CertificateSigningKey(_validCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509IssuerAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.Matches, Is.True);
    }

    [Test]
    public void CertificateIssuerAssertionProvider_WithNonMatchingIssuer_ReturnsNonMatchingAssertion()
    {
        // Arrange
        var provider = new CertificateIssuerAssertionProvider("Wrong Issuer");
        var signingKey = new X509CertificateSigningKey(_validCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509IssuerAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.Matches, Is.False);
    }

    [Test]
    public void CertificateIssuerAssertionProvider_WithNonX509Key_ReturnsEmpty()
    {
        // Arrange
        var provider = new CertificateIssuerAssertionProvider("Test");
        var mockSigningKey = new Mock<ISigningKey>().Object;

        // Act
        var assertions = provider.ExtractAssertions(mockSigningKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Is.Empty);
    }

    #endregion

    #region CertificateKeyUsageAssertionProvider Tests

    [Test]
    public void CertificateKeyUsageAssertionProvider_ComponentName_IsCorrect()
    {
        // Arrange
        var provider = new CertificateKeyUsageAssertionProvider(X509KeyUsageFlags.DigitalSignature);

        // Assert
        Assert.That(provider.ComponentName, Is.EqualTo(nameof(CertificateKeyUsageAssertionProvider)));
    }

    [Test]
    public void CertificateKeyUsageAssertionProvider_WithOidString_CreatesProvider()
    {
        // Arrange & Act
        var provider = new CertificateKeyUsageAssertionProvider("1.3.6.1.5.5.7.3.3"); // Code Signing

        // Assert - just verify it doesn't throw
        Assert.That(provider, Is.Not.Null);
        Assert.That(provider.ComponentName, Is.EqualTo(nameof(CertificateKeyUsageAssertionProvider)));
    }

    [Test]
    public void CertificateKeyUsageAssertionProvider_WithOid_CreatesProvider()
    {
        // Arrange & Act
        var eku = new Oid("1.3.6.1.5.5.7.3.3", "Code Signing");
        var provider = new CertificateKeyUsageAssertionProvider(eku);

        // Assert - just verify it doesn't throw
        Assert.That(provider, Is.Not.Null);
    }

    [Test]
    public void CertificateKeyUsageAssertionProvider_WithNonX509Key_ReturnsEmpty()
    {
        // Arrange
        var provider = new CertificateKeyUsageAssertionProvider(X509KeyUsageFlags.DigitalSignature);
        var mockSigningKey = new Mock<ISigningKey>().Object;

        // Act
        var assertions = provider.ExtractAssertions(mockSigningKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Is.Empty);
    }

    #endregion
}
