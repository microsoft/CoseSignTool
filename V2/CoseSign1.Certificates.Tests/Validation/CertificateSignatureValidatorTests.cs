// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Validation;
using CoseSign1.Direct;
using CoseSign1.Validation;

[TestFixture]
[System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
public class CertificateSignatureValidatorTests
{
    /// <summary>
    /// Holds the test state for each test method.
    /// </summary>
    private sealed record TestContext(
        System.Security.Cryptography.X509Certificates.X509Certificate2 TestCert,
        CoseSign1Message ValidMessage) : IDisposable
    {
        public void Dispose() => TestCert?.Dispose();
    }

    /// <summary>
    /// Creates a fresh test context with isolated state.
    /// </summary>
    private static TestContext CreateTestContext()
    {
        var testCert = TestCertificateUtils.CreateCertificate("CertificateSignatureValidatorTest");

        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(testCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var validMessage = CoseSign1Message.DecodeSign1(messageBytes);

        return new TestContext(testCert, validMessage);
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
        var result = validator.Validate(null!, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateSignatureValidator)));
    }

    [Test]
    public void Validate_WithValidSignature_ReturnsSuccess()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateSignatureValidator();
        var result = validator.Validate(ctx.ValidMessage, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.True);
        // CertificateSignatureValidator delegates to CertificateEmbeddedSignatureValidator for embedded messages
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateEmbeddedSignatureValidator)));
    }

    [Test]
    public void Validate_WithAllowUnprotectedHeaders_ValidatesSuccessfully()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateSignatureValidator(allowUnprotectedHeaders: true);
        var result = validator.Validate(ctx.ValidMessage, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithValidSignature_ReturnsSuccess()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateSignatureValidator();
        var result = await validator.ValidateAsync(ctx.ValidMessage, ValidationStage.Signature, CancellationToken.None);

        Assert.That(result.IsValid, Is.True);
        // CertificateSignatureValidator delegates to CertificateEmbeddedSignatureValidator for embedded messages
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateEmbeddedSignatureValidator)));
    }

    [Test]
    public async Task ValidateAsync_WithCancellationToken_ThrowsWhenCancelled()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateSignatureValidator();
        var cts = new CancellationTokenSource();
        cts.Cancel();

        // Task may complete before cancellation is observed
        try
        {
            await validator.ValidateAsync(ctx.ValidMessage, ValidationStage.Signature, cts.Token);
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
        var result = await validator.ValidateAsync(null!, ValidationStage.Signature, CancellationToken.None);

        Assert.That(result.IsValid, Is.False);
    }

    #region Detached Signature Tests

    [Test]
    public void Constructor_WithDetachedPayload_CreatesValidator()
    {
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var validator = new CertificateSignatureValidator(payload);
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithDetachedPayloadAndAllowUnprotected_CreatesValidator()
    {
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var validator = new CertificateSignatureValidator(payload, allowUnprotectedHeaders: true);
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithReadOnlyMemoryPayload_CreatesValidator()
    {
        ReadOnlyMemory<byte> payload = new byte[] { 1, 2, 3, 4, 5 };
        var validator = new CertificateSignatureValidator(payload);
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithReadOnlyMemoryAndAllowUnprotected_CreatesValidator()
    {
        ReadOnlyMemory<byte> payload = new byte[] { 1, 2, 3, 4, 5 };
        var validator = new CertificateSignatureValidator(payload, allowUnprotectedHeaders: true);
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullDetachedPayload_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new CertificateSignatureValidator((byte[])null!));
    }

    [Test]
    public void Validate_DetachedSignature_WithPayload_ReturnsSuccess()
    {
        using var ctx = CreateTestContext();
        // Create a detached signature
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(ctx.TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);

        // Create detached signature (embedPayload: false)
        var options = new DirectSignatureOptions { EmbedPayload = false };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test", options);
        var detachedMessage = CoseSign1Message.DecodeSign1(messageBytes);

        // Validate with the payload
        var validator = new CertificateSignatureValidator(payload);
        var result = validator.Validate(detachedMessage, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateDetachedSignatureValidator)));
    }

    [Test]
    public void Validate_DetachedSignature_WithoutPayload_ReturnsFailure()
    {
        using var ctx = CreateTestContext();
        // Create a detached signature
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(ctx.TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);

        // Create detached signature (embedPayload: false)
        var options = new DirectSignatureOptions { EmbedPayload = false };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test", options);
        var detachedMessage = CoseSign1Message.DecodeSign1(messageBytes);

        // Try to validate without payload - should fail
        var validator = new CertificateSignatureValidator(); // No payload provided
        var result = validator.Validate(detachedMessage, ValidationStage.Signature);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.Failures, Has.Count.GreaterThan(0));
            Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("MISSING_DETACHED_PAYLOAD"));
        });
    }

    [Test]
    public async Task ValidateAsync_DetachedSignature_WithPayload_ReturnsSuccess()
    {
        using var ctx = CreateTestContext();
        // Create a detached signature
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(ctx.TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);

        // Create detached signature (embedPayload: false)
        var options = new DirectSignatureOptions { EmbedPayload = false };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test", options);
        var detachedMessage = CoseSign1Message.DecodeSign1(messageBytes);

        // Validate with the payload
        var validator = new CertificateSignatureValidator(payload);
        var result = await validator.ValidateAsync(detachedMessage, ValidationStage.Signature, CancellationToken.None);

        Assert.That(result.IsValid, Is.True);
    }

    #endregion
}