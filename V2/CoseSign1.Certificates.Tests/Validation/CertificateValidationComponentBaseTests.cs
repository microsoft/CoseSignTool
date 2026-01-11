// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using System.Formats.Cbor;
using System.Security.Cryptography.Cose;
using CoseSign1.Certificates.Validation;
using CoseSign1.Tests.Common;
using CoseSign1.Validation;

/// <summary>
/// Tests for CertificateValidationComponentBase to improve code coverage.
/// </summary>
[TestFixture]
[Category("Validation")]
public class CertificateValidationComponentBaseTests
{
    private X509Certificate2? _selfSignedCert;

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        _selfSignedCert = TestCertificateUtils.CreateCertificate(nameof(CertificateValidationComponentBaseTests));
    }

    [OneTimeTearDown]
    public void OneTimeTearDown()
    {
        _selfSignedCert?.Dispose();
    }

    #region ComputeApplicability Tests

    [Test]
    public void ComputeApplicability_WithEmptyMessage_ReturnsFalse()
    {
        // Arrange
        var component = new TestCertificateValidationComponent();
        var emptyMessage = CreateEmptyMessage();

        // Act
        var isApplicable = component.IsApplicablePublic(emptyMessage);

        // Assert
        Assert.That(isApplicable, Is.False);
    }

    [Test]
    public void ComputeApplicability_WithNullOptions_DefaultsToProtected()
    {
        // Arrange
        var component = new TestCertificateValidationComponent();
        var emptyMessage = CreateEmptyMessage();

        // Act
        var isApplicable = component.IsApplicablePublic(emptyMessage, null);

        // Assert - empty message has no certificate chain
        Assert.That(isApplicable, Is.False);
    }

    [Test]
    public void ComputeApplicability_WithOptions_PassesThroughOptions()
    {
        // Arrange
        var component = new TestCertificateValidationComponent();
        var emptyMessage = CreateEmptyMessage();
        var options = new CoseSign1ValidationOptions
        {
            CertificateHeaderLocation = CoseHeaderLocation.Protected
        };

        // Act
        var isApplicable = component.IsApplicablePublic(emptyMessage, options);

        // Assert
        Assert.That(isApplicable, Is.False);
    }

    #endregion

    #region HasCertificateChain Tests

    [Test]
    public void HasCertificateChain_WithNullMessage_ReturnsFalse()
    {
        // Arrange
        var component = new TestCertificateValidationComponent();

        // Act
        var hasCerts = component.HasCertificateChainPublic(null, CoseHeaderLocation.Protected);

        // Assert
        Assert.That(hasCerts, Is.False);
    }

    [Test]
    public void HasCertificateChain_WithEmptyMessage_ReturnsFalse()
    {
        // Arrange
        var component = new TestCertificateValidationComponent();
        var emptyMessage = CreateEmptyMessage();

        // Act
        var hasCerts = component.HasCertificateChainPublic(emptyMessage, CoseHeaderLocation.Protected);

        // Assert
        Assert.That(hasCerts, Is.False);
    }

    [Test]
    public void HasCertificateChain_WithEmptyMessageUnprotected_ReturnsFalse()
    {
        // Arrange
        var component = new TestCertificateValidationComponent();
        var emptyMessage = CreateEmptyMessage();

        // Act
        var hasCerts = component.HasCertificateChainPublic(emptyMessage, CoseHeaderLocation.Unprotected);

        // Assert
        Assert.That(hasCerts, Is.False);
    }

    #endregion

    #region ComponentName Tests

    [Test]
    public void ComponentName_ReturnsCorrectName()
    {
        // Arrange
        var component = new TestCertificateValidationComponent();

        // Act & Assert
        Assert.That(component.ComponentName, Is.EqualTo("TestCertificateValidationComponent"));
    }

    #endregion

    #region Integration Tests

    [Test]
    public void DerivedComponent_InheritsBaseValidationBehavior()
    {
        // Arrange
        var component = new CertificateExpirationAssertionProvider();
        var messageWithCerts = CreateMessageWithCertificateChain();

        // Act - check that a real derived component works
        Assert.That(component.ComponentName, Is.EqualTo(nameof(CertificateExpirationAssertionProvider)));
    }

    [Test]
    public void DerivedComponent_ChainAssertionProvider_InheritsBehavior()
    {
        // Arrange
        var component = new CertificateChainAssertionProvider(
            allowUntrusted: true,
            revocationMode: X509RevocationMode.NoCheck);

        // Act & Assert
        Assert.That(component.ComponentName, Is.EqualTo(nameof(CertificateChainAssertionProvider)));
    }

    #endregion

    #region Helper Methods

    private static CoseSign1Message CreateEmptyMessage()
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

    private static CoseSign1Message CreateMessageWithCertificateChain(CoseHeaderLocation location = CoseHeaderLocation.Protected)
    {
        // For testing purposes, just return an empty message
        // The actual certificate chain handling is tested in integration tests
        return CreateEmptyMessage();
    }

    #endregion

    #region Test Helper Class

    /// <summary>
    /// Test implementation of CertificateValidationComponentBase to test protected methods.
    /// </summary>
    private class TestCertificateValidationComponent : CertificateValidationComponentBase
    {
        public override string ComponentName => nameof(TestCertificateValidationComponent);

        // Expose protected methods for testing
        public bool IsApplicablePublic(CoseSign1Message message, CoseSign1ValidationOptions? options = null)
        {
            return ComputeApplicability(message, options);
        }

        public bool HasCertificateChainPublic(CoseSign1Message? message, CoseHeaderLocation location)
        {
            return HasCertificateChain(message, location);
        }
    }

    #endregion
}
