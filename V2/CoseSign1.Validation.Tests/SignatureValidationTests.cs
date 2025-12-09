// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.Local;
using CoseSign1.Certificates.Validation;
using CoseSign1.Direct;
using CoseSign1.Tests.Common;
using CoseSign1.Validation;

namespace CoseSign1.Validation.Tests;

[TestFixture]
public class SignatureValidationTests
{
    private static readonly byte[] TestPayload = Encoding.UTF8.GetBytes("test payload for validation");

    [Test]
    public void SignatureValidator_WithValidEmbeddedSignature_Succeeds()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate(nameof(SignatureValidator_WithValidEmbeddedSignature_Succeeds), useEcc: true);
        using var signingService = new LocalCertificateSigningService(cert, new[] { cert });
        using var factory = new DirectSignatureFactory(signingService);

        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/json");
        var message = CoseMessage.DecodeSign1(messageBytes);

        var validator = CoseValidatorBuilder
            .ForMessage()
            .ValidateCertificateSignature()
            .Build();

        // Act
        var result = validator.Validate(message);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Failures, Is.Empty);
    }

    [Test]
    public void SignatureValidator_WithNullMessage_Fails()
    {
        // Arrange
        var validator = CoseValidatorBuilder
            .ForMessage()
            .ValidateCertificateSignature()
            .Build();

        // Act
        var result = validator.Validate(null!);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("NULL_INPUT"));
    }

    [Test]
    public async Task SignatureValidator_WithValidEmbeddedSignature_SucceedsAsync()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate(nameof(SignatureValidator_WithValidEmbeddedSignature_SucceedsAsync), useEcc: true);
        using var signingService = new LocalCertificateSigningService(cert, new[] { cert });
        using var factory = new DirectSignatureFactory(signingService);

        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/json");
        var message = CoseMessage.DecodeSign1(messageBytes);

        var validator = CoseValidatorBuilder
            .ForMessage()
            .ValidateCertificateSignature()
            .Build();

        // Act
        var result = await validator.ValidateAsync(message);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Failures, Is.Empty);
    }

    [Test]
    public void DetachedSignatureValidator_WithValidDetachedSignature_Succeeds()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate(nameof(DetachedSignatureValidator_WithValidDetachedSignature_Succeeds), useEcc: true);
        using var signingService = new LocalCertificateSigningService(cert, new[] { cert });
        using var factory = new DirectSignatureFactory(signingService);

        var options = new DirectSignatureOptions { EmbedPayload = false };
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/json", options);
        var message = CoseMessage.DecodeSign1(messageBytes);

        var validator = CoseValidatorBuilder
            .ForMessage()
            .ValidateCertificateSignature(TestPayload)
            .Build();

        // Act
        var result = validator.Validate(message);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Failures, Is.Empty);
        Assert.That(message.Content, Is.Null, "Expected detached content");
    }

    [Test]
    public void DetachedSignatureValidator_WithWrongPayload_Fails()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate(nameof(DetachedSignatureValidator_WithWrongPayload_Fails), useEcc: true);
        using var signingService = new LocalCertificateSigningService(cert, new[] { cert });
        using var factory = new DirectSignatureFactory(signingService);

        var options = new DirectSignatureOptions { EmbedPayload = false };
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/json", options);
        var message = CoseMessage.DecodeSign1(messageBytes);

        byte[] wrongPayload = Encoding.UTF8.GetBytes("wrong payload");
        var validator = CoseValidatorBuilder
            .ForMessage()
            .ValidateCertificateSignature(wrongPayload)
            .Build();

        // Act
        var result = validator.Validate(message);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("SIGNATURE_INVALID"));
    }

    [Test]
    public void DetachedSignatureValidator_WithEmbeddedContent_Fails()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate(nameof(DetachedSignatureValidator_WithEmbeddedContent_Fails), useEcc: true);
        using var signingService = new LocalCertificateSigningService(cert, new[] { cert });
        using var factory = new DirectSignatureFactory(signingService);

        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/json");
        var message = CoseMessage.DecodeSign1(messageBytes);

        var validator = CoseValidatorBuilder
            .ForMessage()
            .ValidateCertificateSignature(TestPayload)  // Using detached validator with embedded content
            .Build();

        // Act
        var result = validator.Validate(message);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("UNEXPECTED_EMBEDDED_CONTENT"));
    }

    [Test]
    public void MultipleValidators_AllPass_Succeeds()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate(nameof(MultipleValidators_AllPass_Succeeds), useEcc: true);
        using var signingService = new LocalCertificateSigningService(cert, new[] { cert });
        using var factory = new DirectSignatureFactory(signingService);

        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/json");
        var message = CoseMessage.DecodeSign1(messageBytes);

        var validator = CoseValidatorBuilder
            .ForMessage()
            .ValidateCertificateSignature()
            .AddValidator(msg => ValidationResult.Success("CustomValidator"))
            .Build();

        // Act
        var result = validator.Validate(message);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Failures, Is.Empty);
    }

    [Test]
    public void MultipleValidators_OneFails_ReturnsAllFailures()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate(nameof(MultipleValidators_OneFails_ReturnsAllFailures), useEcc: true);
        using var signingService = new LocalCertificateSigningService(cert, new[] { cert });
        using var factory = new DirectSignatureFactory(signingService);

        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/json");
        var message = CoseMessage.DecodeSign1(messageBytes);

        var validator = CoseValidatorBuilder
            .ForMessage()
            .ValidateCertificateSignature()  // This will pass
            .AddValidator(msg => ValidationResult.Failure("CustomValidator1", "Custom failure"))  // This will fail
            .AddValidator(msg => ValidationResult.Failure("CustomValidator2", "Another failure"))  // This will also fail
            .Build();

        // Act
        var result = validator.Validate(message);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(2));
        Assert.That(result.Failures[0].Message, Is.EqualTo("Custom failure"));
        Assert.That(result.Failures[1].Message, Is.EqualTo("Another failure"));
    }

    [Test]
    public void StopOnFirstFailure_StopsAfterFirstError()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate(nameof(StopOnFirstFailure_StopsAfterFirstError), useEcc: true);
        using var signingService = new LocalCertificateSigningService(cert, new[] { cert });
        using var factory = new DirectSignatureFactory(signingService);

        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/json");
        var message = CoseMessage.DecodeSign1(messageBytes);

        int secondValidatorCalled = 0;

        var validator = CoseValidatorBuilder
            .ForMessage()
            .AddValidator(msg => ValidationResult.Failure("FirstValidator", "First failure"))
            .AddValidator(msg =>
            {
                secondValidatorCalled++;
                return ValidationResult.Failure("SecondValidator", "Second failure");
            })
            .StopOnFirstFailure()
            .Build();

        // Act
        var result = validator.Validate(message);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].Message, Is.EqualTo("First failure"));
        Assert.That(secondValidatorCalled, Is.EqualTo(0), "Second validator should not have been called");
    }

    [Test]
    public void CertificateSignatureValidator_WithDetachedSignature_Fails()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate(nameof(CertificateSignatureValidator_WithDetachedSignature_Fails), useEcc: true);
        using var signingService = new LocalCertificateSigningService(cert, new[] { cert });
        using var factory = new DirectSignatureFactory(signingService);

        var options = new DirectSignatureOptions { EmbedPayload = false };
        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/json", options);
        var message = CoseMessage.DecodeSign1(messageBytes);

        var validator = CoseValidatorBuilder
            .ForMessage()
            .ValidateCertificateSignature()
            .Build();

        // Act
        var result = validator.Validate(message);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("DETACHED_CONTENT_NOT_SUPPORTED"));
        Assert.That(message.Content, Is.Null, "Expected detached content");
    }
}
