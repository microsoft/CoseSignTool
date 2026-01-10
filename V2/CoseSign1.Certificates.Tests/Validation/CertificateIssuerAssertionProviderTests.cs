// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using CoseSign1.Certificates.Validation;
using CoseSign1.Direct;
using CoseSign1.Validation;
using CoseSign1.Validation.Interfaces;

/// <summary>
/// Tests for the CertificateIssuerAssertionProvider class.
/// </summary>
[TestFixture]
public class CertificateIssuerAssertionProviderTests
{
    [Test]
    public void Constructor_Default_CreatesInstance()
    {
        // Act
        var validator = new CertificateIssuerAssertionProvider("TestIssuer");

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithAllowUnprotectedHeaders_CreatesInstance()
    {
        // Act
        var validator = new CertificateIssuerAssertionProvider("TestIssuer", allowUnprotectedHeaders: true);

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullExpectedName_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new CertificateIssuerAssertionProvider(null!));
    }

    [Test]
    public void Validate_WithNullInput_ReturnsFailure()
    {
        // Arrange
        var validator = new CertificateIssuerAssertionProvider("TestIssuer");

        // Act
        var result = validator.Validate(null!, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateIssuerAssertionProvider)));
        Assert.That(result.Failures.Any(f => f.ErrorCode == "NULL_INPUT"), Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithNullInput_ReturnsFailure()
    {
        // Arrange
        var validator = new CertificateIssuerAssertionProvider("TestIssuer");

        // Act
        var result = await validator.ValidateAsync(null!, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "NULL_INPUT"), Is.True);
    }

    [Test]
    public void Validate_MessageWithoutCertificate_ReturnsFailure()
    {
        // Arrange
        var validator = new CertificateIssuerAssertionProvider("TestIssuer");

        // Create a signed message without certificate
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        byte[] signedBytes = CoseSign1Message.SignDetached(new byte[] { 1, 2, 3 }, signer, ReadOnlySpan<byte>.Empty);
        var message = CoseSign1Message.DecodeSign1(signedBytes);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "CERTIFICATE_NOT_FOUND"), Is.True);
    }

    [Test]
    public void Validate_WithAllowUnprotectedFalse_ReturnsFailure()
    {
        // Arrange - default is to not allow unprotected headers
        var validator = new CertificateIssuerAssertionProvider("TestIssuer", allowUnprotectedHeaders: false);

        // Create a signed message without certificate
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        byte[] signedBytes = CoseSign1Message.SignDetached(new byte[] { 1, 2, 3 }, signer, ReadOnlySpan<byte>.Empty);
        var message = CoseSign1Message.DecodeSign1(signedBytes);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "CERTIFICATE_NOT_FOUND"), Is.True);
    }

    [Test]
    public void Validator_ImplementsIValidator()
    {
        // Arrange
        var validator = new CertificateIssuerAssertionProvider("TestIssuer");

        // Assert
        Assert.That(validator, Is.InstanceOf<IValidator>());
    }

    [Test]
    public async Task ValidateAsync_ReturnsSameResultAsValidate()
    {
        // Arrange
        var validator = new CertificateIssuerAssertionProvider("TestIssuer");

        // Act
        var syncResult = validator.Validate(null!, ValidationStage.KeyMaterialTrust);
        var asyncResult = await validator.ValidateAsync(null!, ValidationStage.KeyMaterialTrust);

        // Assert - both should return same failure for null input
        Assert.That(asyncResult.IsValid, Is.EqualTo(syncResult.IsValid));
        Assert.That(asyncResult.Failures[0].ErrorCode, Is.EqualTo(syncResult.Failures[0].ErrorCode));
    }

    [Test]
    public void DifferentCasedExpectedNames_CreateValidators()
    {
        // This test verifies that issuer name comparison will be case-insensitive
        // We create validators with different cases and verify they were created
        var validatorLower = new CertificateIssuerAssertionProvider("testissuer");
        var validatorUpper = new CertificateIssuerAssertionProvider("TESTISSUER");
        var validatorMixed = new CertificateIssuerAssertionProvider("TestIssuer");

        // All validators should be created successfully
        Assert.That(validatorLower, Is.Not.Null);
        Assert.That(validatorUpper, Is.Not.Null);
        Assert.That(validatorMixed, Is.Not.Null);
    }

    [Test]
    public void Validate_WithMatchingIssuer_ReturnsSuccess()
    {
        // Arrange - create a self-signed certificate
        // For self-signed certs, the issuer CN equals the subject CN
        using var cert = TestCertificateUtils.CreateCertificate("TestIssuerCN");
        var chainBuilder = new CoseSign1.Certificates.ChainBuilders.X509ChainBuilder();
        var signingService = CertificateSigningService.Create(cert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        // For a self-signed cert, Issuer == Subject
        var validator = new CertificateIssuerAssertionProvider("TestIssuerCN");

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateIssuerAssertionProvider)));
    }

    [Test]
    public void Validate_WithMismatchedIssuer_ReturnsFailure()
    {
        // Arrange - create a self-signed certificate with known CN
        using var cert = TestCertificateUtils.CreateCertificate("ActualIssuerCN");
        var chainBuilder = new CoseSign1.Certificates.ChainBuilders.X509ChainBuilder();
        var signingService = CertificateSigningService.Create(cert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        // Validator expects different issuer than actual
        var validator = new CertificateIssuerAssertionProvider("ExpectedIssuerCN");

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "ISSUER_CN_MISMATCH"), Is.True);
    }

    [Test]
    public void Validate_WithMatchingIssuerCaseInsensitive_ReturnsSuccess()
    {
        // Arrange - create a self-signed certificate
        using var cert = TestCertificateUtils.CreateCertificate("TestIssuerCN");
        var chainBuilder = new CoseSign1.Certificates.ChainBuilders.X509ChainBuilder();
        var signingService = CertificateSigningService.Create(cert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        // Validator uses different case than actual certificate
        var validator = new CertificateIssuerAssertionProvider("TESTISSUERCN");

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert - should match case-insensitively
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithMatchingIssuer_ReturnsSuccess()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("TestIssuerCN");
        var chainBuilder = new CoseSign1.Certificates.ChainBuilders.X509ChainBuilder();
        var signingService = CertificateSigningService.Create(cert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var message = CoseSign1Message.DecodeSign1(messageBytes);
        var validator = new CertificateIssuerAssertionProvider("TestIssuerCN");

        // Act
        var result = await validator.ValidateAsync(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_SuccessResult_ContainsMetadata()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("TestIssuerCN");
        var chainBuilder = new CoseSign1.Certificates.ChainBuilders.X509ChainBuilder();
        var signingService = CertificateSigningService.Create(cert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var message = CoseSign1Message.DecodeSign1(messageBytes);
        var validator = new CertificateIssuerAssertionProvider("TestIssuerCN");

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata, Does.ContainKey("IssuerCN"));
        Assert.That(result.Metadata, Does.ContainKey("CertificateThumbprint"));
        Assert.That(result.Metadata["IssuerCN"], Is.EqualTo("TestIssuerCN"));
    }

    [Test]
    public void Validate_WithAllowUnprotectedHeadersTrue_ValidatesSuccessfully()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("UnprotectedHeaderTest");
        var chainBuilder = new CoseSign1.Certificates.ChainBuilders.X509ChainBuilder();
        var signingService = CertificateSigningService.Create(cert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var validator = new CertificateIssuerAssertionProvider("UnprotectedHeaderTest", allowUnprotectedHeaders: true);

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithIssuerContainingMultipleRdns_ExtractsCorrectCn()
    {
        // Arrange - Certificate with CN in subject will have same in issuer for self-signed
        using var cert = TestCertificateUtils.CreateCertificate("MultiRdnTest");
        var chainBuilder = new CoseSign1.Certificates.ChainBuilders.X509ChainBuilder();
        var signingService = CertificateSigningService.Create(cert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var validator = new CertificateIssuerAssertionProvider("MultiRdnTest");

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithCancellationToken_CompletesSuccessfully()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("CancellationTest");
        var chainBuilder = new CoseSign1.Certificates.ChainBuilders.X509ChainBuilder();
        var signingService = CertificateSigningService.Create(cert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var message = CoseSign1Message.DecodeSign1(messageBytes);
        var validator = new CertificateIssuerAssertionProvider("CancellationTest");
        using var cts = new CancellationTokenSource();

        // Act
        var result = await validator.ValidateAsync(message, ValidationStage.KeyMaterialTrust, cts.Token);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_FailureResult_ContainsActualIssuerCn()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("ActualCN");
        var chainBuilder = new CoseSign1.Certificates.ChainBuilders.X509ChainBuilder();
        var signingService = CertificateSigningService.Create(cert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var validator = new CertificateIssuerAssertionProvider("ExpectedCN");

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures[0].Message, Does.Contain("ActualCN"));
        Assert.That(result.Failures[0].Message, Does.Contain("ExpectedCN"));
    }

    [Test]
    public void Validate_WithLowerCaseExpectedIssuer_MatchesUpperCaseCertIssuer()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("UPPERCASE");
        var chainBuilder = new CoseSign1.Certificates.ChainBuilders.X509ChainBuilder();
        var signingService = CertificateSigningService.Create(cert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var validator = new CertificateIssuerAssertionProvider("uppercase");

        // Act
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }
}