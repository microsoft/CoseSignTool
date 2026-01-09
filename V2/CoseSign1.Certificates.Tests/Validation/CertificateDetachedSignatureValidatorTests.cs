// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Validation;
using CoseSign1.Direct;
using CoseSign1.Validation;

[TestFixture]
[System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
public class CertificateDetachedSignatureValidatorTests
{
    private sealed record TestContext(
        System.Security.Cryptography.X509Certificates.X509Certificate2 TestCert,
        byte[] Payload) : IDisposable
    {
        public void Dispose() => TestCert.Dispose();
    }

    private static TestContext CreateTestContext()
    {
        var testCert = TestCertificateUtils.CreateCertificate("CertificateDetachedSignatureValidatorTest");
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        return new TestContext(testCert, payload);
    }

    [Test]
    public void Constructor_WithByteArrayPayload_CreatesValidator()
    {
        // Arrange
        var payload = new byte[] { 1, 2, 3 };

        // Act
        var validator = new CertificateDetachedSignatureValidator(payload);

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithByteArrayPayloadAndAllowUnprotectedHeaders_CreatesValidator()
    {
        // Arrange
        var payload = new byte[] { 1, 2, 3 };

        // Act
        var validator = new CertificateDetachedSignatureValidator(payload, allowUnprotectedHeaders: true);

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithReadOnlyMemoryPayload_CreatesValidator()
    {
        // Arrange
        var payload = new ReadOnlyMemory<byte>(new byte[] { 1, 2, 3 });

        // Act
        var validator = new CertificateDetachedSignatureValidator(payload);

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithReadOnlyMemoryPayloadAndAllowUnprotectedHeaders_CreatesValidator()
    {
        // Arrange
        var payload = new ReadOnlyMemory<byte>(new byte[] { 1, 2, 3 });

        // Act
        var validator = new CertificateDetachedSignatureValidator(payload, allowUnprotectedHeaders: true);

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullPayload_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new CertificateDetachedSignatureValidator((byte[])null!));
    }

    [Test]
    public void Constructor_WithEmptyPayload_CreatesValidator()
    {
        // Arrange
        var payload = Array.Empty<byte>();

        // Act
        var validator = new CertificateDetachedSignatureValidator(payload);

        // Assert
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Validate_WithNullInput_ReturnsFailure()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var validator = new CertificateDetachedSignatureValidator(ctx.Payload);

        // Act
        var result = validator.Validate(null!, ValidationStage.Signature);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].Message, Does.Contain("null"));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("NULL_INPUT"));
    }

    [Test]
    public void Validate_WithEmbeddedContent_ReturnsFailure()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(ctx.TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);

        // Create message with embedded payload (not detached)
        var embeddedPayload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(embeddedPayload, "application/test");
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var validator = new CertificateDetachedSignatureValidator(ctx.Payload);

        // Act
        var result = validator.Validate(message, ValidationStage.Signature);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].Message, Does.Contain("embedded content"));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("UNEXPECTED_EMBEDDED_CONTENT"));
    }

    [Test]
    public void Validate_WithValidDetachedSignature_ReturnsSuccess()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(ctx.TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);

        // Create detached signature
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test", new DirectSignatureOptions { EmbedPayload = false });
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var validator = new CertificateDetachedSignatureValidator(payload);

        // Act
        var result = validator.Validate(message, ValidationStage.Signature);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Failures, Is.Empty);
    }

    [Test]
    public void Validate_WithMismatchedPayload_ReturnsFailure()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(ctx.TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);

        // Create detached signature with one payload
        var originalPayload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(originalPayload, "application/test", new DirectSignatureOptions { EmbedPayload = false });
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        // Validate with different payload
        var differentPayload = new byte[] { 9, 8, 7, 6, 5 };
        var validator = new CertificateDetachedSignatureValidator(differentPayload);

        // Act
        var result = validator.Validate(message, ValidationStage.Signature);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].Message, Does.Contain("verification failed"));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("SIGNATURE_INVALID"));
    }

    [Test]
    public void Validate_WithReadOnlyMemoryConstructor_ValidatesCorrectly()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(ctx.TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);

        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test", new DirectSignatureOptions { EmbedPayload = false });
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var payloadMemory = new ReadOnlyMemory<byte>(payload);
        var validator = new CertificateDetachedSignatureValidator(payloadMemory);

        // Act
        var result = validator.Validate(message, ValidationStage.Signature);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithLargePayload_ValidatesCorrectly()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(ctx.TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);

        // Create large payload (1MB)
        var largePayload = new byte[1024 * 1024];
        Random.Shared.NextBytes(largePayload);

        var messageBytes = factory.CreateCoseSign1MessageBytes(largePayload, "application/test", new DirectSignatureOptions { EmbedPayload = false });
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var validator = new CertificateDetachedSignatureValidator(largePayload);

        // Act
        var result = validator.Validate(message, ValidationStage.Signature);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_AllowUnprotectedHeadersFalse_ValidatesProtectedHeaders()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(ctx.TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);

        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test", new DirectSignatureOptions { EmbedPayload = false });
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var validator = new CertificateDetachedSignatureValidator(payload, allowUnprotectedHeaders: false);

        // Act
        var result = validator.Validate(message, ValidationStage.Signature);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_AllowUnprotectedHeadersTrue_AllowsUnprotectedHeaders()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(ctx.TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);

        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test", new DirectSignatureOptions { EmbedPayload = false });
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var validator = new CertificateDetachedSignatureValidator(payload, allowUnprotectedHeaders: true);

        // Act
        var result = validator.Validate(message, ValidationStage.Signature);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithValidDetachedSignature_ReturnsSuccess()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(ctx.TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);

        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test", new DirectSignatureOptions { EmbedPayload = false });
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var validator = new CertificateDetachedSignatureValidator(payload);

        // Act
        var result = await validator.ValidateAsync(message, ValidationStage.Signature);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Failures, Is.Empty);
    }

    [Test]
    public async Task ValidateAsync_WithNullInput_ReturnsFailure()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var validator = new CertificateDetachedSignatureValidator(ctx.Payload);

        // Act
        var result = await validator.ValidateAsync(null!, ValidationStage.Signature);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("NULL_INPUT"));
    }

    [Test]
    public async Task ValidateAsync_WithMismatchedPayload_ReturnsFailure()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(ctx.TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);

        var originalPayload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(originalPayload, "application/test", new DirectSignatureOptions { EmbedPayload = false });
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var differentPayload = new byte[] { 9, 8, 7, 6, 5 };
        var validator = new CertificateDetachedSignatureValidator(differentPayload);

        // Act
        var result = await validator.ValidateAsync(message, ValidationStage.Signature);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("SIGNATURE_INVALID"));
    }

    [Test]
    public async Task ValidateAsync_WithCancellationToken_CompletesSuccessfully()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(ctx.TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);

        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test", new DirectSignatureOptions { EmbedPayload = false });
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var validator = new CertificateDetachedSignatureValidator(payload);
        using var cts = new CancellationTokenSource();

        // Act
        var result = await validator.ValidateAsync(message, ValidationStage.Signature, cts.Token);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithSlightlyModifiedPayload_ReturnsFailure()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(ctx.TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);

        var originalPayload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(originalPayload, "application/test", new DirectSignatureOptions { EmbedPayload = false });
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        // Modify one byte
        var modifiedPayload = new byte[] { 1, 2, 99, 4, 5 }; // Changed 3rd byte
        var validator = new CertificateDetachedSignatureValidator(modifiedPayload);

        // Act
        var result = validator.Validate(message, ValidationStage.Signature);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("SIGNATURE_INVALID"));
    }

    [Test]
    public void Validate_WithDifferentPayloadLength_ReturnsFailure()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(ctx.TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);

        var originalPayload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(originalPayload, "application/test", new DirectSignatureOptions { EmbedPayload = false });
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        // Different length payload
        var shorterPayload = new byte[] { 1, 2, 3 };
        var validator = new CertificateDetachedSignatureValidator(shorterPayload);

        // Act
        var result = validator.Validate(message, ValidationStage.Signature);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("SIGNATURE_INVALID"));
    }

    [Test]
    public void Validate_MultipleValidationsWithSameValidator_AllSucceed()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(ctx.TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);

        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test", new DirectSignatureOptions { EmbedPayload = false });
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var validator = new CertificateDetachedSignatureValidator(payload);

        // Act - Validate multiple times
        var result1 = validator.Validate(message, ValidationStage.Signature);
        var result2 = validator.Validate(message, ValidationStage.Signature);
        var result3 = validator.Validate(message, ValidationStage.Signature);

        // Assert
        Assert.That(result1.IsValid, Is.True);
        Assert.That(result2.IsValid, Is.True);
        Assert.That(result3.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithDifferentContentTypes_ValidatesCorrectly()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(ctx.TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);

        var payload = new byte[] { 1, 2, 3, 4, 5 };

        // Create messages with different content types
        var message1 = CoseSign1Message.DecodeSign1(
            factory.CreateCoseSign1MessageBytes(payload, "application/json", new DirectSignatureOptions { EmbedPayload = false }));
        var message2 = CoseSign1Message.DecodeSign1(
            factory.CreateCoseSign1MessageBytes(payload, "application/xml", new DirectSignatureOptions { EmbedPayload = false }));

        var validator = new CertificateDetachedSignatureValidator(payload);

        // Act
        var result1 = validator.Validate(message1, ValidationStage.Signature);
        var result2 = validator.Validate(message2, ValidationStage.Signature);

        // Assert - Both should validate correctly with same payload
        Assert.That(result1.IsValid, Is.True);
        Assert.That(result2.IsValid, Is.True);
    }
}