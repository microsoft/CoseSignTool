// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Local;
using CoseSign1.Certificates.Validation;
using CoseSign1.Direct;
using CoseSign1.Tests.Common;
using NUnit.Framework;

namespace CoseSign1.Certificates.Tests.Validation;

[TestFixture]
public class AdditionalValidatorTests
{
    private System.Security.Cryptography.X509Certificates.X509Certificate2? TestCert;
    private CoseSign1Message? ValidMessage;

    [SetUp]
#pragma warning disable CA2252 // Preview features
    public void SetUp()
    {
        TestCert = TestCertificateUtils.CreateCertificate("ValidatorTest");

        var chainBuilder = new X509ChainBuilder();
        var signingService = new LocalCertificateSigningService(TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        ValidMessage = CoseSign1Message.DecodeSign1(messageBytes);
    }
#pragma warning restore CA2252

    [TearDown]
    public void TearDown()
    {
        TestCert?.Dispose();
    }

    [Test]
    public void CertificateCommonNameValidator_Constructor_WithRequiredName_CreatesValidator()
    {
        var validator = new CertificateCommonNameValidator("Test");
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void CertificateCommonNameValidator_Constructor_WithNullName_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => new CertificateCommonNameValidator(null!));
    }

    [Test]
    public void CertificateCommonNameValidator_Constructor_WithEmptyName_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => new CertificateCommonNameValidator(""));
    }

    [Test]
    public void CertificateCommonNameValidator_Validate_WithMatchingName_ReturnsSuccess()
    {
        var validator = new CertificateCommonNameValidator("ValidatorTest");
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void CertificateCommonNameValidator_Validate_WithNonMatchingName_ReturnsFailure()
    {
        var validator = new CertificateCommonNameValidator("WrongName");
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.False);
    }

    [Test]
    public void CertificateCommonNameValidator_Validate_WithNullInput_ReturnsFailure()
    {
        var validator = new CertificateCommonNameValidator("Test");
        var result = validator.Validate(null!);

        Assert.That(result.IsValid, Is.False);
    }

    [Test]
    public async Task CertificateCommonNameValidator_ValidateAsync_CompletesSuccessfully()
    {
        var validator = new CertificateCommonNameValidator("ValidatorTest");
        var result = await validator.ValidateAsync(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void CertificateExpirationValidator_Constructor_CreatesValidator()
    {
        var validator = new CertificateExpirationValidator();
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void CertificateExpirationValidator_Validate_WithValidCertificate_ReturnsSuccess()
    {
        var validator = new CertificateExpirationValidator();
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void CertificateExpirationValidator_Validate_WithNullInput_ReturnsFailure()
    {
        var validator = new CertificateExpirationValidator();
        var result = validator.Validate(null!);

        Assert.That(result.IsValid, Is.False);
    }

    [Test]
    public async Task CertificateExpirationValidator_ValidateAsync_CompletesSuccessfully()
    {
        var validator = new CertificateExpirationValidator();
        var result = await validator.ValidateAsync(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void CertificateDetachedSignatureValidator_Constructor_CreatesValidator()
    {
        var validator = new CertificateDetachedSignatureValidator(new byte[] { 1, 2, 3 });
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void CertificateDetachedSignatureValidator_Constructor_WithNullPayload_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new CertificateDetachedSignatureValidator(null!));
    }

    [Test]
    public void CertificateDetachedSignatureValidator_Validate_WithValidSignature_ReturnsSuccess()
    {
        // For detached signatures, the message doesn't contain the payload
        // So we need to create a detached message
#pragma warning disable CA2252
        var cert = TestCertificateUtils.CreateCertificate("DetachedTest");
#pragma warning restore CA2252
        var chainBuilder = new X509ChainBuilder();
        var signingService = new LocalCertificateSigningService(cert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };

        // Create detached signature (payload not embedded)
        var options = new DirectSignatureOptions { EmbedPayload = false };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test", options);
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var validator = new CertificateDetachedSignatureValidator(payload);
        var result = validator.Validate(message);

        Assert.That(result.IsValid, Is.True);
        cert.Dispose();
    }

    [Test]
    public void CertificateDetachedSignatureValidator_Validate_WithNullInput_ReturnsFailure()
    {
        var validator = new CertificateDetachedSignatureValidator(new byte[] { 1, 2, 3 });
        var result = validator.Validate(null!);

        Assert.That(result.IsValid, Is.False);
    }

    [Test]
    public async Task CertificateDetachedSignatureValidator_ValidateAsync_CompletesSuccessfully()
    {
        // Create detached signature
#pragma warning disable CA2252
        var cert = TestCertificateUtils.CreateCertificate("DetachedAsyncTest");
#pragma warning restore CA2252
        var chainBuilder = new X509ChainBuilder();
        var signingService = new LocalCertificateSigningService(cert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };

        var options = new DirectSignatureOptions { EmbedPayload = false };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test", options);
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var validator = new CertificateDetachedSignatureValidator(payload);
        var result = await validator.ValidateAsync(message);

        Assert.That(result.IsValid, Is.True);
        cert.Dispose();
    }
}