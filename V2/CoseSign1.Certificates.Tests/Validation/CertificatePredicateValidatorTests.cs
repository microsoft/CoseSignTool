// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Local;
using CoseSign1.Certificates.Validation;
using CoseSign1.Direct;
using CoseSign1.Tests.Common;
using CoseSign1.Validation;
using NUnit.Framework;

namespace CoseSign1.Certificates.Tests.Validation;

[TestFixture]
public class CertificatePredicateValidatorTests
{
    [Test]
    public void Constructor_WithValidPredicate_CreatesInstance()
    {
        // Act
        var validator = new CertificatePredicateValidator(cert => true);

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullPredicate_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new CertificatePredicateValidator(null!));
    }

    [Test]
    public void Constructor_WithPredicateAndMessage_CreatesInstance()
    {
        // Act
        var validator = new CertificatePredicateValidator(
            cert => true,
            "Custom failure message");

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithAllParameters_CreatesInstance()
    {
        // Act
        var validator = new CertificatePredicateValidator(
            cert => true,
            "Custom message",
            allowUnprotectedHeaders: true);

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Validate_WithNullInput_ReturnsFailure()
    {
        // Arrange
        var validator = new CertificatePredicateValidator(cert => true);

        // Act
        var result = validator.Validate(null!);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "NULL_INPUT"), Is.True);
    }

    [Test]
    public void Validate_WithPredicateTrue_ReturnsSuccess()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateValidator(cert => true);

        // Act
        var result = validator.Validate(message);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificatePredicateValidator)));
    }

    [Test]
    public void Validate_WithPredicateFalse_ReturnsFailure()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateValidator(cert => false);

        // Act
        var result = validator.Validate(message);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "CERTIFICATE_PREDICATE_FAILED"), Is.True);
    }

    [Test]
    public void Validate_WithPredicateFalse_UsesDefaultMessage()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateValidator(cert => false);

        // Act
        var result = validator.Validate(message);

        // Assert
        Assert.That(result.Failures[0].Message, Does.Contain("does not match the specified predicate"));
    }

    [Test]
    public void Validate_WithPredicateFalse_UsesCustomMessage()
    {
        // Arrange
        var message = CreateSignedMessage();
        var customMessage = "Certificate failed custom validation";
        var validator = new CertificatePredicateValidator(cert => false, customMessage);

        // Act
        var result = validator.Validate(message);

        // Assert
        Assert.That(result.Failures[0].Message, Is.EqualTo(customMessage));
    }

    [Test]
    public void Validate_WithPredicateCheckingSubject_Works()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateValidator(
            cert => cert.Subject.Contains("PredicateTest"));

        // Act
        var result = validator.Validate(message);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithPredicateCheckingIssuer_Works()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateValidator(
            cert => !string.IsNullOrEmpty(cert.Issuer));

        // Act
        var result = validator.Validate(message);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithPredicateCheckingThumbprint_Works()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateValidator(
            cert => cert.Thumbprint.Length > 0);

        // Act
        var result = validator.Validate(message);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_SuccessIncludesThumbprintInMetadata()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateValidator(cert => true);

        // Act
        var result = validator.Validate(message);

        // Assert
        Assert.That(result.Metadata.ContainsKey("CertificateThumbprint"), Is.True);
        Assert.That(result.Metadata["CertificateThumbprint"], Is.InstanceOf<string>());
    }

    [Test]
    public async Task ValidateAsync_WithPredicateTrue_ReturnsSuccess()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateValidator(cert => true);

        // Act
        var result = await validator.ValidateAsync(message);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithPredicateFalse_ReturnsFailure()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateValidator(cert => false);

        // Act
        var result = await validator.ValidateAsync(message);

        // Assert
        Assert.That(result.IsValid, Is.False);
    }

    [Test]
    public async Task ValidateAsync_WithCancellationToken_CompletesSuccessfully()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateValidator(cert => true);
        using var cts = new CancellationTokenSource();

        // Act
        var result = await validator.ValidateAsync(message, cts.Token);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithComplexPredicate_Works()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateValidator(cert =>
        {
            // Complex multi-condition check
            return cert != null &&
                   !string.IsNullOrEmpty(cert.Subject) &&
                   cert.NotBefore < DateTime.UtcNow &&
                   cert.NotAfter > DateTime.UtcNow;
        },
        "Certificate must be valid and have a subject");

        // Act
        var result = validator.Validate(message);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithNullFailureMessage_UsesDefault()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateValidator(cert => false, null);

        // Act
        var result = validator.Validate(message);

        // Assert
        Assert.That(result.Failures[0].Message, Does.Contain("does not match"));
    }

    [Test]
    public void Validate_WithEmptyFailureMessage_UsesProvidedEmpty()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateValidator(cert => false, "");

        // Act
        var result = validator.Validate(message);

        // Assert
        Assert.That(result.Failures[0].Message, Is.EqualTo(""));
    }

#pragma warning disable CA2252
    private CoseSign1Message CreateSignedMessage()
    {
        using var cert = TestCertificateUtils.CreateCertificate("PredicateTest");
        using var signingService = new LocalCertificateSigningService(cert, new[] { cert });
        using var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        return CoseMessage.DecodeSign1(messageBytes);
    }
#pragma warning restore CA2252
}