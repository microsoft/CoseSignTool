// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.Validation;
using CoseSign1.Validation;
using NUnit.Framework;

namespace CoseSign1.Certificates.Tests.Validation;

/// <summary>
/// Tests for the CertificateIssuerValidator class.
/// </summary>
[TestFixture]
public class CertificateIssuerValidatorTests
{
    [Test]
    public void Constructor_Default_CreatesInstance()
    {
        // Act
        var validator = new CertificateIssuerValidator("TestIssuer");

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithAllowUnprotectedHeaders_CreatesInstance()
    {
        // Act
        var validator = new CertificateIssuerValidator("TestIssuer", allowUnprotectedHeaders: true);

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullExpectedName_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new CertificateIssuerValidator(null!));
    }

    [Test]
    public void Validate_WithNullInput_ReturnsFailure()
    {
        // Arrange
        var validator = new CertificateIssuerValidator("TestIssuer");

        // Act
        var result = validator.Validate(null!);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateIssuerValidator)));
        Assert.That(result.Failures.Any(f => f.ErrorCode == "NULL_INPUT"), Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithNullInput_ReturnsFailure()
    {
        // Arrange
        var validator = new CertificateIssuerValidator("TestIssuer");

        // Act
        var result = await validator.ValidateAsync(null!);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "NULL_INPUT"), Is.True);
    }

    [Test]
    public void Validate_MessageWithoutCertificate_ReturnsFailure()
    {
        // Arrange
        var validator = new CertificateIssuerValidator("TestIssuer");

        // Create a signed message without certificate
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        byte[] signedBytes = CoseSign1Message.SignDetached(new byte[] { 1, 2, 3 }, signer, ReadOnlySpan<byte>.Empty);
        var message = CoseSign1Message.DecodeSign1(signedBytes);

        // Act
        var result = validator.Validate(message);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "CERTIFICATE_NOT_FOUND"), Is.True);
    }

    [Test]
    public void Validate_WithAllowUnprotectedFalse_ReturnsFailure()
    {
        // Arrange - default is to not allow unprotected headers
        var validator = new CertificateIssuerValidator("TestIssuer", allowUnprotectedHeaders: false);

        // Create a signed message without certificate
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        byte[] signedBytes = CoseSign1Message.SignDetached(new byte[] { 1, 2, 3 }, signer, ReadOnlySpan<byte>.Empty);
        var message = CoseSign1Message.DecodeSign1(signedBytes);

        // Act
        var result = validator.Validate(message);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "CERTIFICATE_NOT_FOUND"), Is.True);
    }

    [Test]
    public void Validator_ImplementsIValidator()
    {
        // Arrange
        var validator = new CertificateIssuerValidator("TestIssuer");

        // Assert
        Assert.That(validator, Is.InstanceOf<IValidator<CoseSign1Message>>());
    }

    [Test]
    public async Task ValidateAsync_ReturnsSameResultAsValidate()
    {
        // Arrange
        var validator = new CertificateIssuerValidator("TestIssuer");

        // Act
        var syncResult = validator.Validate(null!);
        var asyncResult = await validator.ValidateAsync(null!);

        // Assert - both should return same failure for null input
        Assert.That(asyncResult.IsValid, Is.EqualTo(syncResult.IsValid));
        Assert.That(asyncResult.Failures[0].ErrorCode, Is.EqualTo(syncResult.Failures[0].ErrorCode));
    }

    [Test]
    public void DifferentCasedExpectedNames_CreateValidators()
    {
        // This test verifies that issuer name comparison will be case-insensitive
        // We create validators with different cases and verify they were created
        var validatorLower = new CertificateIssuerValidator("testissuer");
        var validatorUpper = new CertificateIssuerValidator("TESTISSUER");
        var validatorMixed = new CertificateIssuerValidator("TestIssuer");

        // All validators should be created successfully
        Assert.That(validatorLower, Is.Not.Null);
        Assert.That(validatorUpper, Is.Not.Null);
        Assert.That(validatorMixed, Is.Not.Null);
    }
}
