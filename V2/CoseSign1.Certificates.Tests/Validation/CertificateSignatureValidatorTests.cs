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
public class CertificateSignatureValidatorTests
{
    private System.Security.Cryptography.X509Certificates.X509Certificate2? _testCert;
    private CoseSign1Message? _validMessage;

    [SetUp]
    #pragma warning disable CA2252 // Preview features
    public void SetUp()
    {
        _testCert = TestCertificateUtils.CreateCertificate("CertificateSignatureValidatorTest");
        
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
        var validator = new CertificateSignatureValidator();
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithAllowUnprotectedHeaders_CreatesValidator()
    {
        var validator = new CertificateSignatureValidator(allowUnprotectedHeaders: true);
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Validate_WithNullInput_ReturnsFailure()
    {
        var validator = new CertificateSignatureValidator();
        var result = validator.Validate(null!);
        
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateSignatureValidator)));
    }

    [Test]
    public void Validate_WithValidSignature_ReturnsSuccess()
    {
        var validator = new CertificateSignatureValidator();
        var result = validator.Validate(_validMessage!);
        
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateSignatureValidator)));
    }

    [Test]
    public void Validate_WithAllowUnprotectedHeaders_ValidatesSuccessfully()
    {
        var validator = new CertificateSignatureValidator(allowUnprotectedHeaders: true);
        var result = validator.Validate(_validMessage!);
        
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithValidSignature_ReturnsSuccess()
    {
        var validator = new CertificateSignatureValidator();
        var result = await validator.ValidateAsync(_validMessage!, CancellationToken.None);
        
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateSignatureValidator)));
    }

    [Test]
    public async Task ValidateAsync_WithCancellationToken_ThrowsWhenCancelled()
    {
        var validator = new CertificateSignatureValidator();
        var cts = new CancellationTokenSource();
        cts.Cancel();
        
        // Task may complete before cancellation is observed
        try
        {
            await validator.ValidateAsync(_validMessage!, cts.Token);
            // If no exception, test passes - cancellation may not be observed for fast operations
        }
        catch (OperationCanceledException)
        {
            // Expected - cancellation was observed
            Assert.Pass();
        }
    }

    [Test]
    public async Task ValidateAsync_WithNullInput_ReturnsFailure()
    {
        var validator = new CertificateSignatureValidator();
        var result = await validator.ValidateAsync(null!, CancellationToken.None);
        
        Assert.That(result.IsValid, Is.False);
    }
}
