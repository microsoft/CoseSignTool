// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using System.Formats.Cbor;
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.Validation;
using CoseSign1.Tests.Common;
using CoseSign1.Validation;
using Microsoft.Extensions.Logging;
using Moq;

/// <summary>
/// Extended tests for CertificateIssuerAssertionProvider to improve code coverage.
/// </summary>
[TestFixture]
[Category("Validation")]
public class CertificateIssuerAssertionProviderExtendedTests
{
    private X509Certificate2? _validCert;
    private CoseSign1Message? _dummyMessage;

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        // Create a self-signed certificate (issuer = subject)
        _validCert = TestCertificateUtils.CreateCertificate("Valid Test Certificate");
        _dummyMessage = CreateDummyMessage();
    }

    [OneTimeTearDown]
    public void OneTimeTearDown()
    {
        _validCert?.Dispose();
    }

    #region Constructor Tests

    [Test]
    public void Constructor_WithNullIssuerName_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new CertificateIssuerAssertionProvider(null!));
    }

    [Test]
    public void Constructor_WithEmptyIssuerName_CreatesProvider()
    {
        // Empty string is allowed (though unusual)
        var provider = new CertificateIssuerAssertionProvider(string.Empty);

        // Assert
        Assert.That(provider, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithValidIssuerNameAndLogger_CreatesProvider()
    {
        // Arrange
        var mockLogger = new Mock<ILogger<CertificateIssuerAssertionProvider>>().Object;

        // Act
        var provider = new CertificateIssuerAssertionProvider("TestIssuer", mockLogger);

        // Assert
        Assert.That(provider, Is.Not.Null);
        Assert.That(provider.ComponentName, Is.EqualTo(nameof(CertificateIssuerAssertionProvider)));
    }

    #endregion

    #region ExtractAssertions Tests

    [Test]
    public void ExtractAssertions_WithSelfSignedCert_MatchesIssuerEqualsSubject()
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
    public void ExtractAssertions_WithCaseInsensitiveMatch_ReturnsMatch()
    {
        // Arrange - use different case
        var provider = new CertificateIssuerAssertionProvider("VALID TEST CERTIFICATE");
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
    public void ExtractAssertions_WithLowercaseMatch_ReturnsMatch()
    {
        // Arrange
        var provider = new CertificateIssuerAssertionProvider("valid test certificate");
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
    public void ExtractAssertions_WithMismatch_ReturnsFalse()
    {
        // Arrange
        var provider = new CertificateIssuerAssertionProvider("Different Issuer");
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
    public void ExtractAssertions_ReturnsActualIssuerNameInAssertion()
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
        Assert.That(assertion!.ActualIssuer, Is.EqualTo("Valid Test Certificate"));
    }

    [Test]
    public void ExtractAssertions_WithNonX509SigningKey_ReturnsEmpty()
    {
        // Arrange
        var provider = new CertificateIssuerAssertionProvider("Test Issuer");
        var mockSigningKey = new Mock<ISigningKey>().Object;

        // Act
        var assertions = provider.ExtractAssertions(mockSigningKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Is.Empty);
    }

    [Test]
    public void ExtractAssertions_WithOptions_PassesThroughOptions()
    {
        // Arrange
        var provider = new CertificateIssuerAssertionProvider("Valid Test Certificate");
        var signingKey = new X509CertificateSigningKey(_validCert!);
        var options = new CoseSign1ValidationOptions
        {
            CertificateHeaderLocation = CoseHeaderLocation.Protected
        };

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!, options);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
    }

    #endregion

    #region ExtractAssertionsAsync Tests

    [Test]
    public async Task ExtractAssertionsAsync_WithMatchingIssuer_ReturnsMatch()
    {
        // Arrange
        var provider = new CertificateIssuerAssertionProvider("Valid Test Certificate");
        var signingKey = new X509CertificateSigningKey(_validCert!);

        // Act
        var assertions = await provider.ExtractAssertionsAsync(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509IssuerAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.Matches, Is.True);
    }

    [Test]
    public async Task ExtractAssertionsAsync_WithCancellationToken_Completes()
    {
        // Arrange
        var provider = new CertificateIssuerAssertionProvider("Valid Test Certificate");
        var signingKey = new X509CertificateSigningKey(_validCert!);
        using var cts = new CancellationTokenSource();

        // Act
        var assertions = await provider.ExtractAssertionsAsync(signingKey, _dummyMessage!, null, cts.Token);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
    }

    [Test]
    public async Task ExtractAssertionsAsync_WithOptions_PassesOptionsCorrectly()
    {
        // Arrange
        var provider = new CertificateIssuerAssertionProvider("Valid Test Certificate");
        var signingKey = new X509CertificateSigningKey(_validCert!);
        var options = new CoseSign1ValidationOptions();

        // Act
        var assertions = await provider.ExtractAssertionsAsync(signingKey, _dummyMessage!, options);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
    }

    #endregion

    #region Logging Tests

    [Test]
    public void ExtractAssertions_WithLogger_LogsValidation()
    {
        // Arrange
        var mockLogger = new Mock<ILogger<CertificateIssuerAssertionProvider>>();
        mockLogger.Setup(l => l.IsEnabled(It.IsAny<LogLevel>())).Returns(true);

        var provider = new CertificateIssuerAssertionProvider("Valid Test Certificate", mockLogger.Object);
        var signingKey = new X509CertificateSigningKey(_validCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
    }

    [Test]
    public void ExtractAssertions_WithLoggerAndMismatch_LogsMismatch()
    {
        // Arrange
        var mockLogger = new Mock<ILogger<CertificateIssuerAssertionProvider>>();
        mockLogger.Setup(l => l.IsEnabled(It.IsAny<LogLevel>())).Returns(true);

        var provider = new CertificateIssuerAssertionProvider("Wrong Issuer", mockLogger.Object);
        var signingKey = new X509CertificateSigningKey(_validCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509IssuerAssertion;
        Assert.That(assertion!.Matches, Is.False);
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
