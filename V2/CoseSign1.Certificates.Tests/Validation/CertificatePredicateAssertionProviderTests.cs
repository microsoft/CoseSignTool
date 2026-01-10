// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using CoseSign1.Certificates.Validation;
using CoseSign1.Direct;
using CoseSign1.Validation;

[TestFixture]
public class CertificatePredicateAssertionProviderTests
{
    [Test]
    public void Constructor_WithValidPredicate_CreatesInstance()
    {
        // Act
        var validator = new CertificatePredicateAssertionProvider(cert => true);

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullPredicate_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new CertificatePredicateAssertionProvider(null!));
    }

    [Test]
    public void Constructor_WithPredicateAndMessage_CreatesInstance()
    {
        // Act
        var validator = new CertificatePredicateAssertionProvider(
            cert => true,
            "Custom failure message");

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithAllParameters_CreatesInstance()
    {
        // Act
        var validator = new CertificatePredicateAssertionProvider(
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
        var validator = new CertificatePredicateAssertionProvider(cert => true);

        // Act
        var result = validator.Validate(null!, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "NULL_INPUT"), Is.True);
    }

    [Test]
    public void Validate_WithPredicateTrue_ReturnsSuccess()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateAssertionProvider(cert => true);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificatePredicateAssertionProvider)));
    }

    [Test]
    public void Validate_WithPredicateFalse_ReturnsFailure()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateAssertionProvider(cert => false);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "CERTIFICATE_PREDICATE_FAILED"), Is.True);
    }

    [Test]
    public void Validate_WithPredicateFalse_UsesDefaultMessage()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateAssertionProvider(cert => false);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.Failures[0].Message, Does.Contain("does not match the specified predicate"));
    }

    [Test]
    public void Validate_WithPredicateFalse_UsesCustomMessage()
    {
        // Arrange
        var message = CreateSignedMessage();
        var customMessage = "Certificate failed custom validation";
        var validator = new CertificatePredicateAssertionProvider(cert => false, customMessage);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.Failures[0].Message, Is.EqualTo(customMessage));
    }

    [Test]
    public void Validate_WithPredicateCheckingSubject_Works()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateAssertionProvider(
            cert => cert.Subject.Contains("PredicateTest"));

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithPredicateCheckingIssuer_Works()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateAssertionProvider(
            cert => !string.IsNullOrEmpty(cert.Issuer));

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithPredicateCheckingThumbprint_Works()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateAssertionProvider(
            cert => cert.Thumbprint.Length > 0);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_SuccessIncludesThumbprintInMetadata()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateAssertionProvider(cert => true);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.Metadata.ContainsKey("CertificateThumbprint"), Is.True);
        Assert.That(result.Metadata["CertificateThumbprint"], Is.InstanceOf<string>());
    }

    [Test]
    public async Task ValidateAsync_WithPredicateTrue_ReturnsSuccess()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateAssertionProvider(cert => true);

        // Act
        var result = await validator.ValidateAsync(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithPredicateFalse_ReturnsFailure()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateAssertionProvider(cert => false);

        // Act
        var result = await validator.ValidateAsync(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.False);
    }

    [Test]
    public async Task ValidateAsync_WithCancellationToken_CompletesSuccessfully()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateAssertionProvider(cert => true);
        using var cts = new CancellationTokenSource();

        // Act
        var result = await validator.ValidateAsync(message, ValidationStage.KeyMaterialTrust, cts.Token);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithComplexPredicate_Works()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateAssertionProvider(cert =>
        {
            // Complex multi-condition check
            return cert != null &&
                   !string.IsNullOrEmpty(cert.Subject) &&
                   cert.NotBefore < DateTime.UtcNow &&
                   cert.NotAfter > DateTime.UtcNow;
        },
        "Certificate must be valid and have a subject");

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithNullFailureMessage_UsesDefault()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateAssertionProvider(cert => false, null);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.Failures[0].Message, Does.Contain("does not match"));
    }

    [Test]
    public void Validate_WithEmptyFailureMessage_UsesProvidedEmpty()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificatePredicateAssertionProvider(cert => false, "");

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.Failures[0].Message, Is.EqualTo(""));
    }

    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    private CoseSign1Message CreateSignedMessage()
    {
        using var cert = TestCertificateUtils.CreateCertificate("PredicateTest");
        using var signingService = CertificateSigningService.Create(cert, new X509Certificate2[] { cert });
        using var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        return CoseMessage.DecodeSign1(messageBytes);
    }
}