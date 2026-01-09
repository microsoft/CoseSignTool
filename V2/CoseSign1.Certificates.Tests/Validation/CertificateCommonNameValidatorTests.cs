// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Validation;
using CoseSign1.Direct;
using CoseSign1.Validation;

/// <summary>
/// Tests for CertificateCommonNameValidator.
/// </summary>
[TestFixture]
[System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
public class CertificateCommonNameValidatorTests
{
    private const string TestCertCN = "CommonNameTest";

    private sealed record TestContext(
        X509Certificate2 TestCert,
        CoseSign1Message ValidMessage) : IDisposable
    {
        public void Dispose() => TestCert.Dispose();
    }

    private static TestContext CreateTestContext()
    {
        var testCert = TestCertificateUtils.CreateCertificate(TestCertCN);

        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(testCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var validMessage = CoseSign1Message.DecodeSign1(messageBytes);

        return new TestContext(testCert, validMessage);
    }

    [Test]
    public void Constructor_WithValidCommonName_CreatesValidator()
    {
        var validator = new CertificateCommonNameValidator("TestCN");
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullCommonName_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
            new CertificateCommonNameValidator(null!));
    }

    [Test]
    public void Constructor_WithEmptyCommonName_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
            new CertificateCommonNameValidator(""));
    }

    [Test]
    public void Constructor_WithWhitespaceCommonName_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
            new CertificateCommonNameValidator("   "));
    }

    [Test]
    public void Constructor_WithAllowUnprotectedHeaders_CreatesValidator()
    {
        var validator = new CertificateCommonNameValidator("TestCN", allowUnprotectedHeaders: true);
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Validate_WithNullInput_ReturnsFailure()
    {
        var validator = new CertificateCommonNameValidator(TestCertCN);
        var result = validator.Validate(null!, ValidationStage.KeyMaterialTrust);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateCommonNameValidator)));
            Assert.That(result.Failures.Any(f => f.ErrorCode == "NULL_INPUT"), Is.True);
        });
    }

    [Test]
    public void Validate_WithMatchingCommonName_ReturnsSuccess()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateCommonNameValidator(TestCertCN);
        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsValid, Is.True);
            Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateCommonNameValidator)));
            Assert.That(result.Metadata.ContainsKey("CommonName"), Is.True);
            Assert.That(result.Metadata.ContainsKey("CertificateThumbprint"), Is.True);
            Assert.That(result.Metadata["CommonName"], Is.EqualTo(TestCertCN));
        });
    }

    [Test]
    public void Validate_WithMatchingCommonNameCaseInsensitive_ReturnsSuccess()
    {
        using var ctx = CreateTestContext();
        // Test case-insensitive matching
        var validator = new CertificateCommonNameValidator(TestCertCN.ToUpperInvariant());
        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithNonMatchingCommonName_ReturnsFailure()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateCommonNameValidator("WrongCN");
        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.Failures.Any(f => f.ErrorCode == "CN_MISMATCH"), Is.True);
            Assert.That(result.Failures.Any(f => f.Message.Contains("WrongCN")), Is.True);
        });
    }

    [Test]
    public async Task ValidateAsync_WithMatchingCommonName_ReturnsSuccess()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateCommonNameValidator(TestCertCN);
        var result = await validator.ValidateAsync(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithCancellationToken_CompletesSuccessfully()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateCommonNameValidator(TestCertCN);
        using var cts = new CancellationTokenSource();
        var result = await validator.ValidateAsync(ctx.ValidMessage, ValidationStage.KeyMaterialTrust, cts.Token);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithAllowUnprotectedHeadersTrue_ValidatesSuccessfully()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateCommonNameValidator(TestCertCN, allowUnprotectedHeaders: true);
        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_MessageWithoutCertificate_ReturnsFailure()
    {
        // Create a message without certificate headers
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var signer = new CoseSigner(rsa, System.Security.Cryptography.RSASignaturePadding.Pss, System.Security.Cryptography.HashAlgorithmName.SHA256);
        var payload = new byte[] { 1, 2, 3 };
        var messageBytes = CoseSign1Message.SignEmbedded(payload, signer);
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var validator = new CertificateCommonNameValidator("TestCN");
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.Failures.Any(f => f.ErrorCode == "CERTIFICATE_NOT_FOUND"), Is.True);
        });
    }

    [Test]
    public void Validate_WithPartialCnMatch_ReturnsFailure()
    {
        using var ctx = CreateTestContext();
        // Partial matches should not succeed
        var validator = new CertificateCommonNameValidator("CommonName");
        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsValid, Is.False);
    }

    [Test]
    public void Validate_WithCnHavingSpecialCharacters_MatchesCorrectly()
    {
        // Create cert with special characters in CN
        using var specialCert = TestCertificateUtils.CreateCertificate("Test.User@example.com");
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(specialCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var validator = new CertificateCommonNameValidator("Test.User@example.com");
        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithDifferentCase_MatchesCaseInsensitively()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateCommonNameValidator("commonnametest");
        var result = validator.Validate(ctx.ValidMessage, ValidationStage.KeyMaterialTrust);

        Assert.That(result.IsValid, Is.True);
    }
}
