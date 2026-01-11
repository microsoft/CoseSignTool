// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using System.Formats.Cbor;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.Validation;
using CoseSign1.Tests.Common;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;

/// <summary>
/// Tests for CertificatePredicateAssertionProvider.
/// </summary>
[TestFixture]
[Category("Validation")]
public class CertificatePredicateAssertionProviderTests
{
    private X509Certificate2? _testCert;
    private CoseSign1Message? _dummyMessage;

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        _testCert = TestCertificateUtils.CreateCertificate(nameof(CertificatePredicateAssertionProviderTests));
        _dummyMessage = CreateDummyMessage();
    }

    [OneTimeTearDown]
    public void OneTimeTearDown()
    {
        _testCert?.Dispose();
    }

    #region Constructor Tests

    [Test]
    public void Constructor_WithValidPredicate_CreatesProvider()
    {
        // Act
        var provider = new CertificatePredicateAssertionProvider(cert => true);

        // Assert
        Assert.That(provider, Is.Not.Null);
        Assert.That(provider.ComponentName, Is.EqualTo(nameof(CertificatePredicateAssertionProvider)));
    }

    [Test]
    public void Constructor_WithNullPredicate_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new CertificatePredicateAssertionProvider(null!));
    }

    [Test]
    public void Constructor_WithFailureMessage_CreatesProvider()
    {
        // Act
        var provider = new CertificatePredicateAssertionProvider(
            cert => false,
            "Custom failure message");

        // Assert
        Assert.That(provider, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithLogger_CreatesProvider()
    {
        // Arrange
        var mockLogger = new Mock<ILogger<CertificatePredicateAssertionProvider>>().Object;

        // Act
        var provider = new CertificatePredicateAssertionProvider(
            cert => true,
            "message",
            mockLogger);

        // Assert
        Assert.That(provider, Is.Not.Null);
    }

    #endregion

    #region ComponentName Tests

    [Test]
    public void ComponentName_ReturnsCorrectName()
    {
        // Arrange
        var provider = new CertificatePredicateAssertionProvider(cert => true);

        // Assert
        Assert.That(provider.ComponentName, Is.EqualTo(nameof(CertificatePredicateAssertionProvider)));
    }

    #endregion

    #region ExtractAssertions Tests

    [Test]
    public void ExtractAssertions_WithPassingPredicate_ReturnsPassedAssertion()
    {
        // Arrange
        var provider = new CertificatePredicateAssertionProvider(
            cert => cert.Subject.Contains("CertificatePredicateAssertionProviderTests"));
        var signingKey = new X509CertificateSigningKey(_testCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509PredicateAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.IsSatisfied, Is.True);
    }

    [Test]
    public void ExtractAssertions_WithFailingPredicate_ReturnsFailedAssertion()
    {
        // Arrange
        var provider = new CertificatePredicateAssertionProvider(
            cert => cert.Subject.Contains("NonExistentName"));
        var signingKey = new X509CertificateSigningKey(_testCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509PredicateAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.IsSatisfied, Is.False);
    }

    [Test]
    public void ExtractAssertions_WithFailingPredicateAndCustomMessage_IncludesMessage()
    {
        // Arrange
        const string customMessage = "Custom validation failed!";
        var provider = new CertificatePredicateAssertionProvider(
            cert => false,
            customMessage);
        var signingKey = new X509CertificateSigningKey(_testCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509PredicateAssertion;
        Assert.That(assertion, Is.Not.Null);
        Assert.That(assertion!.IsSatisfied, Is.False);
        Assert.That(assertion.Details, Is.EqualTo(customMessage));
    }

    [Test]
    public void ExtractAssertions_WithNonX509Key_ReturnsEmpty()
    {
        // Arrange
        var provider = new CertificatePredicateAssertionProvider(cert => true);
        var mockSigningKey = new Mock<ISigningKey>().Object;

        // Act
        var assertions = provider.ExtractAssertions(mockSigningKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Is.Empty);
    }

    [Test]
    public void ExtractAssertions_PredicateReceivesCertificate()
    {
        // Arrange
        X509Certificate2? receivedCert = null;
        var provider = new CertificatePredicateAssertionProvider(
            cert =>
            {
                receivedCert = cert;
                return true;
            });
        var signingKey = new X509CertificateSigningKey(_testCert!);

        // Act
        provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(receivedCert, Is.SameAs(_testCert));
    }

    [Test]
    public void ExtractAssertions_WithComplexPredicate_Works()
    {
        // Arrange - predicate checks thumbprint, validity, and subject
        var expectedThumbprint = _testCert!.Thumbprint;
        var provider = new CertificatePredicateAssertionProvider(
            cert => cert.Thumbprint == expectedThumbprint
                    && cert.NotAfter > DateTime.UtcNow
                    && !string.IsNullOrEmpty(cert.Subject));
        var signingKey = new X509CertificateSigningKey(_testCert!);

        // Act
        var assertions = provider.ExtractAssertions(signingKey, _dummyMessage!);

        // Assert
        Assert.That(assertions, Has.Count.EqualTo(1));
        var assertion = assertions[0] as X509PredicateAssertion;
        Assert.That(assertion!.IsSatisfied, Is.True);
    }

    #endregion

    #region ExtractAssertionsAsync Tests

    [Test]
    public async Task ExtractAssertionsAsync_ReturnsAssertions()
    {
        // Arrange
        var provider = new CertificatePredicateAssertionProvider(cert => true);
        var signingKey = new X509CertificateSigningKey(_testCert!);

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
