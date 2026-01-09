// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Validation;
using CoseSign1.Direct;
using CoseSign1.Validation;
using CoseSign1.Validation.Interfaces;

/// <summary>
/// Tests for CertificateEmbeddedSignatureValidator.
/// Note: This is an internal class, so we test it via CertificateSignatureValidator.
/// </summary>
[TestFixture]
[System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
public class CertificateEmbeddedSignatureValidatorTests
{
    private sealed record TestContext(
        System.Security.Cryptography.X509Certificates.X509Certificate2 TestCert,
        CoseSign1Message ValidEmbeddedMessage,
        CoseSign1Message DetachedMessage) : IDisposable
    {
        public void Dispose() => TestCert.Dispose();
    }

    private static TestContext CreateTestContext()
    {
        var testCert = TestCertificateUtils.CreateCertificate("EmbeddedValidatorTest");

        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(testCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };

        // Create embedded message
        var embeddedOptions = new DirectSignatureOptions { EmbedPayload = true };
        var embeddedBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test", embeddedOptions);
        var validEmbeddedMessage = CoseSign1Message.DecodeSign1(embeddedBytes);

        // Create detached message
        var detachedOptions = new DirectSignatureOptions { EmbedPayload = false };
        var detachedBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test", detachedOptions);
        var detachedMessage = CoseSign1Message.DecodeSign1(detachedBytes);

        return new TestContext(testCert, validEmbeddedMessage, detachedMessage);
    }

    [Test]
    public void Validate_WithNullInput_ReturnsNullInputFailure()
    {
        // Use CertificateSignatureValidator to trigger embedded validator
        var validator = new CertificateSignatureValidator();
        var result = validator.Validate(null!, ValidationStage.Signature);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateSignatureValidator)));
            Assert.That(result.Failures, Has.Count.GreaterThan(0));
            Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("NULL_INPUT"));
        });
    }

    [Test]
    public void EmbeddedValidator_Validate_WithNullInput_ReturnsNullInputFailure()
    {
        var validator = CreateEmbeddedValidator();
        var result = validator.Validate(null!, ValidationStage.Signature);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateEmbeddedSignatureValidator)));
            Assert.That(result.Failures, Has.Count.EqualTo(1));
            Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("NULL_INPUT"));
        });
    }

    [Test]
    public void EmbeddedValidator_Validate_WithDetachedMessage_ReturnsDetachedNotSupported()
    {
        using var ctx = CreateTestContext();
        var validator = CreateEmbeddedValidator();
        var result = validator.Validate(ctx.DetachedMessage, ValidationStage.Signature);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateEmbeddedSignatureValidator)));
            Assert.That(result.Failures, Has.Count.EqualTo(1));
            Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("DETACHED_CONTENT_NOT_SUPPORTED"));
        });
    }

    [Test]
    public void EmbeddedValidator_Validate_WithTamperedSignature_ReturnsSignatureInvalid()
    {
        using var ctx = CreateTestContext();
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(ctx.TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };

        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test").ToArray();
        if (messageBytes.Length > 10)
        {
            messageBytes[messageBytes.Length - 1] ^= 0xFF;
            messageBytes[messageBytes.Length - 2] ^= 0xFF;
        }

        var tamperedMessage = CoseSign1Message.DecodeSign1(messageBytes);
        var validator = CreateEmbeddedValidator();
        var result = validator.Validate(tamperedMessage, ValidationStage.Signature);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateEmbeddedSignatureValidator)));
            Assert.That(result.Failures, Has.Count.EqualTo(1));
            Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("SIGNATURE_INVALID"));
        });
    }

    [Test]
    public async Task EmbeddedValidator_ValidateAsync_ForwardsToValidate()
    {
        using var ctx = CreateTestContext();
        var validator = CreateEmbeddedValidator();
        var result = await validator.ValidateAsync(ctx.ValidEmbeddedMessage, ValidationStage.Signature, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsValid, Is.True);
            Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateEmbeddedSignatureValidator)));
        });
    }

    [Test]
    public void Validate_WithValidEmbeddedSignature_ReturnsSuccess()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateSignatureValidator();
        var result = validator.Validate(ctx.ValidEmbeddedMessage, ValidationStage.Signature);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsValid, Is.True);
            Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateEmbeddedSignatureValidator)));
            Assert.That(result.Failures, Has.Count.EqualTo(0));
        });
    }

    [Test]
    public void Validate_WithAllowUnprotectedHeaders_ValidatesSuccessfully()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateSignatureValidator(allowUnprotectedHeaders: true);
        var result = validator.Validate(ctx.ValidEmbeddedMessage, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithValidEmbeddedSignature_ReturnsSuccess()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateSignatureValidator();
        var result = await validator.ValidateAsync(ctx.ValidEmbeddedMessage, ValidationStage.Signature, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsValid, Is.True);
            Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateEmbeddedSignatureValidator)));
        });
    }

    [Test]
    public async Task ValidateAsync_WithCancellation_CompletesOrThrows()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateSignatureValidator();
        var cts = new CancellationTokenSource();
        cts.Cancel();

        try
        {
            var result = await validator.ValidateAsync(ctx.ValidEmbeddedMessage, ValidationStage.Signature, cts.Token);
            // If we get here, the validation completed before cancellation was observed
            Assert.That(result, Is.Not.Null);
        }
        catch (OperationCanceledException)
        {
            // Expected - cancellation was observed
            Assert.Pass();
        }
    }

    [Test]
    public void Validate_DetachedMessageAsEmbedded_ReturnsDetachedNotSupported()
    {
        using var ctx = CreateTestContext();
        // Create a validator without detached payload - trying to validate detached as embedded
        var validator = new CertificateSignatureValidator();
        var result = validator.Validate(ctx.DetachedMessage, ValidationStage.Signature);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.Failures, Has.Count.GreaterThan(0));
            // Should indicate that detached content is not supported or missing
            Assert.That(result.Failures[0].ErrorCode, Is.AnyOf("DETACHED_CONTENT_NOT_SUPPORTED", "MISSING_DETACHED_PAYLOAD"));
        });
    }

    [Test]
    public void Validate_WithTamperedSignature_ReturnsSignatureInvalid()
    {
        using var ctx = CreateTestContext();
        // Create a valid message then tamper with it
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(ctx.TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };

        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test").ToArray();

        // Tamper with the signature bytes (last bytes are the signature)
        if (messageBytes.Length > 10)
        {
            messageBytes[messageBytes.Length - 1] ^= 0xFF; // Flip bits in signature
            messageBytes[messageBytes.Length - 2] ^= 0xFF;
        }

        var tamperedMessage = CoseSign1Message.DecodeSign1(messageBytes);
        var validator = new CertificateSignatureValidator();
        var result = validator.Validate(tamperedMessage, ValidationStage.Signature);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.Failures, Has.Count.GreaterThan(0));
            Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("SIGNATURE_INVALID"));
        });
    }

    [Test]
    public void Validate_MultipleTimesOnSameMessage_ReturnsSameResult()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateSignatureValidator();

        var result1 = validator.Validate(ctx.ValidEmbeddedMessage, ValidationStage.Signature);
        var result2 = validator.Validate(ctx.ValidEmbeddedMessage, ValidationStage.Signature);
        var result3 = validator.Validate(ctx.ValidEmbeddedMessage, ValidationStage.Signature);

        Assert.Multiple(() =>
        {
            Assert.That(result1.IsValid, Is.EqualTo(result2.IsValid));
            Assert.That(result2.IsValid, Is.EqualTo(result3.IsValid));
            Assert.That(result1.ValidatorName, Is.EqualTo(result2.ValidatorName));
        });
    }

    [Test]
    public async Task ValidateAsync_MultipleTimesInParallel_AllSucceed()
    {
        using var ctx = CreateTestContext();
        var validator = new CertificateSignatureValidator();

        var tasks = Enumerable.Range(0, 5)
            .Select(_ => validator.ValidateAsync(ctx.ValidEmbeddedMessage, ValidationStage.Signature, CancellationToken.None))
            .ToList();

        var results = await Task.WhenAll(tasks);

        Assert.That(results.All(r => r.IsValid), Is.True);
    }

    private static IValidator CreateEmbeddedValidator(bool allowUnprotectedHeaders = false)
    {
        var validatorType = typeof(CertificateSignatureValidator)
            .Assembly
            .GetType("CoseSign1.Certificates.Validation.CertificateEmbeddedSignatureValidator", throwOnError: true)!;

        // Constructor signature: (bool allowUnprotectedHeaders, ILogger? logger)
        var instance = Activator.CreateInstance(validatorType, [allowUnprotectedHeaders, null]);
        Assert.That(instance, Is.Not.Null);
        return (IValidator)instance!;
    }
}
