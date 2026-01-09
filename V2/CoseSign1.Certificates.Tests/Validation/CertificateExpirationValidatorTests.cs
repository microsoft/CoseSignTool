// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using CoseSign1.Certificates.Validation;
using CoseSign1.Direct;
using CoseSign1.Validation;

[TestFixture]
public class CertificateExpirationValidatorTests
{
    [Test]
    public void Constructor_Default_CreatesInstance()
    {
        // Act
        var validator = new CertificateExpirationValidator();

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithAllowUnprotectedHeaders_CreatesInstance()
    {
        // Act
        var validator = new CertificateExpirationValidator(allowUnprotectedHeaders: true);

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithValidationTime_CreatesInstance()
    {
        // Arrange
        var validationTime = DateTime.UtcNow;

        // Act
        var validator = new CertificateExpirationValidator(validationTime);

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithValidationTimeAndAllowUnprotected_CreatesInstance()
    {
        // Arrange
        var validationTime = DateTime.UtcNow;

        // Act
        var validator = new CertificateExpirationValidator(validationTime, allowUnprotectedHeaders: true);

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Validate_WithNullInput_ReturnsFailure()
    {
        // Arrange
        var validator = new CertificateExpirationValidator();

        // Act
        var result = validator.Validate(null!, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateExpirationValidator)));
        Assert.That(result.Failures.Any(f => f.ErrorCode == "NULL_INPUT"), Is.True);
    }

    [Test]
    public void Validate_WithValidCertificate_ReturnsSuccess()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificateExpirationValidator();

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateExpirationValidator)));
        Assert.That(result.Metadata.ContainsKey("NotBefore"), Is.True);
        Assert.That(result.Metadata.ContainsKey("NotAfter"), Is.True);
        Assert.That(result.Metadata.ContainsKey("ValidationTime"), Is.True);
        Assert.That(result.Metadata.ContainsKey("CertificateThumbprint"), Is.True);
    }

    [Test]
    public void Validate_WithExpiredCertificate_ReturnsFailure()
    {
        // Arrange
        var message = CreateSignedMessage();
        var futureTime = DateTime.UtcNow.AddYears(100); // Far in the future
        var validator = new CertificateExpirationValidator(futureTime);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "CERTIFICATE_EXPIRED"), Is.True);
        Assert.That(result.Failures[0].Message, Does.Contain("has expired"));
        Assert.That(result.Failures[0].Message, Does.Contain("NotAfter"));
    }

    [Test]
    public void Validate_WithNotYetValidCertificate_ReturnsFailure()
    {
        // Arrange
        var message = CreateSignedMessage();
        var pastTime = DateTime.UtcNow.AddYears(-100); // Far in the past
        var validator = new CertificateExpirationValidator(pastTime);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "CERTIFICATE_NOT_YET_VALID"), Is.True);
        Assert.That(result.Failures[0].Message, Does.Contain("not yet valid"));
        Assert.That(result.Failures[0].Message, Does.Contain("NotBefore"));
    }

    [Test]
    public void Validate_WithSpecificValidationTime_UsesProvidedTime()
    {
        // Arrange
        var message = CreateSignedMessage();
        var specificTime = DateTime.UtcNow.AddDays(-1);
        var validator = new CertificateExpirationValidator(specificTime);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata["ValidationTime"], Is.EqualTo(specificTime));
    }

    [Test]
    public async Task ValidateAsync_WithValidCertificate_ReturnsSuccess()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificateExpirationValidator();

        // Act
        var result = await validator.ValidateAsync(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithExpiredCertificate_ReturnsFailure()
    {
        // Arrange
        var message = CreateSignedMessage();
        var futureTime = DateTime.UtcNow.AddYears(100);
        var validator = new CertificateExpirationValidator(futureTime);

        // Act
        var result = await validator.ValidateAsync(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "CERTIFICATE_EXPIRED"), Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithCancellationToken_CompletesSuccessfully()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificateExpirationValidator();
        using var cts = new CancellationTokenSource();

        // Act
        var result = await validator.ValidateAsync(message, ValidationStage.KeyMaterialTrust, cts.Token);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_IncludesNotBeforeInMetadata()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificateExpirationValidator();

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.Metadata["NotBefore"], Is.InstanceOf<DateTime>());
    }

    [Test]
    public void Validate_IncludesNotAfterInMetadata()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificateExpirationValidator();

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.Metadata["NotAfter"], Is.InstanceOf<DateTime>());
    }

    [Test]
    public void Validate_IncludesThumbprintInMetadata()
    {
        // Arrange
        var message = CreateSignedMessage();
        var validator = new CertificateExpirationValidator();

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.Metadata["CertificateThumbprint"], Is.InstanceOf<string>());
        Assert.That(result.Metadata["CertificateThumbprint"].ToString(), Is.Not.Empty);
    }

    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    private CoseSign1Message CreateSignedMessage()
    {
        using var cert = TestCertificateUtils.CreateCertificate("ExpirationTest");
        using var signingService = CertificateSigningService.Create(cert, new X509Certificate2[] { cert });
        using var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        return CoseMessage.DecodeSign1(messageBytes);
    }
}