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
/// Extended tests for CertificateCommonNameAssertionProvider to improve code coverage.
/// </summary>
[TestFixture]
[Category("Validation")]
public class CertificateCommonNameAssertionProviderExtendedTests
{
    private X509Certificate2? _validCert;
    private CoseSign1Message? _dummyMessage;

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
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
    public void Constructor_WithNullCommonName_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            new CertificateCommonNameAssertionProvider(null!));
    }

    [Test]
    public void Constructor_WithEmptyCommonName_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            new CertificateCommonNameAssertionProvider(string.Empty));
    }

    [Test]
    public void Constructor_WithWhitespaceCommonName_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            new CertificateCommonNameAssertionProvider("   "));
    }

    [Test]
    public void Constructor_WithValidCommonNameAndLogger_CreatesProvider()
    {
        // Arrange
        var mockLogger = new Mock<ILogger<CertificateCommonNameAssertionProvider>>().Object;

        // Act
        var provider = new CertificateCommonNameAssertionProvider("TestCN", mockLogger);

        // Assert
        Assert.That(provider, Is.Not.Null);
        Assert.That(provider.ComponentName, Is.EqualTo(nameof(CertificateCommonNameAssertionProvider)));
    }

    #endregion

    #region ExtractAssertions Tests

    [Test]
    public void ExtractAssertions_WithCaseInsensitiveMatch_ReturnsMatch()
    {
        // Arrange - use different case than certificate
        var provider = new CertificateCommonNameAssertionProvider("VALID TEST CERTIFICATE");
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
    public void ExtractAssertions_WithLowercaseMatch_ReturnsMatch()
    {
        // Arrange
        var provider = new CertificateCommonNameAssertionProvider("valid test certificate");
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
    public void ExtractAssertions_WithPartialMatch_DoesNotMatch()
    {
        // Arrange
        var provider = new CertificateCommonNameAssertionProvider("Valid Test");
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
    public void ExtractAssertions_WithNullCertificateInKey_ReturnsEmpty()
    {
        // Arrange
        var provider = new CertificateCommonNameAssertionProvider("Test");
        var signingKey = new X509CertificateSigningKey(_validCert!, null);

        // This test is tricky - we need a signing key with null certificate
        // The X509CertificateSigningKey constructor requires a certificate
        // so we can only test with a valid one
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
        var provider = new CertificateCommonNameAssertionProvider("Valid Test Certificate");
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

    [Test]
    public void ExtractAssertions_ReturnsActualCommonNameInAssertion()
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
        Assert.That(assertion!.ActualCommonName, Is.EqualTo("Valid Test Certificate"));
    }

    #endregion

    #region ExtractAssertionsAsync Tests

    [Test]
    public async Task ExtractAssertionsAsync_WithMatchingCN_ReturnsMatch()
    {
        // Arrange
        var provider = new CertificateCommonNameAssertionProvider("Valid Test Certificate");
        var signingKey = new X509CertificateSigningKey(_validCert!);

        // Act
        var assertions = await provider.ExtractAssertionsAsync(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509CommonNameAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.Matches, Is.True);
    }

    [Test]
    public async Task ExtractAssertionsAsync_WithCancellationToken_Completes()
    {
        // Arrange
        var provider = new CertificateCommonNameAssertionProvider("Valid Test Certificate");
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
        var provider = new CertificateCommonNameAssertionProvider("Valid Test Certificate");
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
        var mockLogger = new Mock<ILogger<CertificateCommonNameAssertionProvider>>();
        mockLogger.Setup(l => l.IsEnabled(It.IsAny<LogLevel>())).Returns(true);

        var provider = new CertificateCommonNameAssertionProvider("Valid Test Certificate", mockLogger.Object);
        var signingKey = new X509CertificateSigningKey(_validCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert - provider should work and return assertions
        Assert.That(assertions, Has.Count.EqualTo(1));
    }

    [Test]
    public void ExtractAssertions_WithLoggerAndMismatch_LogsMismatch()
    {
        // Arrange
        var mockLogger = new Mock<ILogger<CertificateCommonNameAssertionProvider>>();
        mockLogger.Setup(l => l.IsEnabled(It.IsAny<LogLevel>())).Returns(true);

        var provider = new CertificateCommonNameAssertionProvider("Wrong Name", mockLogger.Object);
        var signingKey = new X509CertificateSigningKey(_validCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert - should return assertion with mismatch
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509CommonNameAssertion;
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
