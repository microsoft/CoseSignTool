// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Local;
using CoseSign1.Certificates.Validation;
using CoseSign1.Direct;
using CoseSign1.Tests.Common;
using CoseSign1.Validation;
using NUnit.Framework;

namespace CoseSign1.Certificates.Tests.Validation;

[TestFixture]
public class SignatureValidatorTests
{
    private System.Security.Cryptography.X509Certificates.X509Certificate2? _testCert;
    private CoseSign1Message? _validMessage;

    [SetUp]
#pragma warning disable CA2252 // Preview features
    public void SetUp()
    {
        _testCert = TestCertificateUtils.CreateCertificate("SignatureValidatorTest");

        var chainBuilder = new X509ChainBuilder();
        var signingService = new LocalCertificateSigningService(_testCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        _validMessage = CoseSign1Message.DecodeSign1(messageBytes);
    }
#pragma warning restore CA2252

    [TearDown]
    public void TearDown()
    {
        _testCert?.Dispose();
    }

    [Test]
    public void Constructor_WithDefaultParameters_CreatesValidator()
    {
        var validator = new SignatureValidator();
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithAllowUnprotectedHeaders_CreatesValidator()
    {
        var validator = new SignatureValidator(allowUnprotectedHeaders: true);
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Validate_WithNullInput_ReturnsFailure()
    {
        var validator = new SignatureValidator();
        var result = validator.Validate(null!);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(SignatureValidator)));
        Assert.That(result.Failures.Any(e => e.ErrorCode == "NULL_INPUT"), Is.True);
    }

    [Test]
    public void Validate_WithValidSignature_ReturnsSuccess()
    {
        var validator = new SignatureValidator();
        var result = validator.Validate(_validMessage!);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(SignatureValidator)));
    }

    [Test]
    public void Validate_WithAllowUnprotectedHeaders_ValidatesSuccessfully()
    {
        var validator = new SignatureValidator(allowUnprotectedHeaders: true);
        var result = validator.Validate(_validMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithValidSignature_ReturnsSuccess()
    {
        var validator = new SignatureValidator();
        var result = await validator.ValidateAsync(_validMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithCancellationToken_CompletesSuccessfully()
    {
        var validator = new SignatureValidator();
        using var cts = new CancellationTokenSource();
        var result = await validator.ValidateAsync(_validMessage!, cts.Token);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithECDsaCertificate_ValidatesSuccessfully()
    {
#pragma warning disable CA2252
        var ecdsaCert = TestCertificateUtils.CreateECDsaCertificate("ECDSATest");
#pragma warning restore CA2252
        var chainBuilder = new X509ChainBuilder();
        var signingService = new LocalCertificateSigningService(ecdsaCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var validator = new SignatureValidator();
        var result = validator.Validate(message);

        Assert.That(result.IsValid, Is.True);
        ecdsaCert.Dispose();
    }
}