// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Validation;
using CoseSign1.Direct;
using CoseSign1.Validation;

/// <summary>
/// Additional tests for CertificateSignatureValidator to improve coverage.
/// Focuses on detached signatures, invalid signatures, and error codes.
/// </summary>
[TestFixture]
public class CertificateSignatureValidatorAdditionalTests
{
    /// <summary>
    /// Holds the test state for each test method.
    /// </summary>
    private sealed record TestContext(System.Security.Cryptography.X509Certificates.X509Certificate2 TestCert) : IDisposable
    {
        public void Dispose() => TestCert?.Dispose();
    }

    /// <summary>
    /// Creates a fresh test context with isolated state.
    /// </summary>
    private static TestContext CreateTestContext()
    {
        var testCert = TestCertificateUtils.CreateCertificate("CertificateSignatureValidatorAdditionalTest");
        return new TestContext(testCert);
    }

    #region Error Code Tests

    [Test]
    public void Validate_WithNullInput_ReturnsNullInputErrorCode()
    {
        // Arrange
        var validator = new CertificateSignatureValidator();

        // Act
        var result = validator.Validate(null!, ValidationStage.Signature);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("NULL_INPUT"));
        Assert.That(result.Failures[0].Message, Does.Contain("null"));
    }

    [Test]
    public void Validate_WithDetachedSignature_ReturnsDetachedContentNotSupportedErrorCode()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var validator = new CertificateSignatureValidator();
        var detachedMessage = CreateDetachedSignature(ctx);

        // Act
        var result = validator.Validate(detachedMessage, ValidationStage.Signature);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        // When no payload is provided for a detached signature, the error is MISSING_DETACHED_PAYLOAD
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("MISSING_DETACHED_PAYLOAD"));
        Assert.That(result.Failures[0].Message, Does.Contain("detached"));
    }

    [Test]
    public void Validate_WithTamperedSignature_ReturnsSignatureInvalidErrorCode()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var validator = new CertificateSignatureValidator();
        var tamperedMessage = CreateTamperedSignature(ctx);

        // Act
        var result = validator.Validate(tamperedMessage, ValidationStage.Signature);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("SIGNATURE_INVALID"));
        Assert.That(result.Failures[0].Message, Does.Contain("Signature verification failed"));
    }

    #endregion

    #region Detached Signature Tests

    [Test]
    public void Validate_WithDetachedSignatureAllowUnprotected_ReturnsFailure()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var validator = new CertificateSignatureValidator(allowUnprotectedHeaders: true);
        var detachedMessage = CreateDetachedSignature(ctx);

        // Act
        var result = validator.Validate(detachedMessage, ValidationStage.Signature);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("MISSING_DETACHED_PAYLOAD"));
    }

    [Test]
    public async Task ValidateAsync_WithDetachedSignature_ReturnsFailure()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var validator = new CertificateSignatureValidator();
        var detachedMessage = CreateDetachedSignature(ctx);

        // Act
        var result = await validator.ValidateAsync(detachedMessage, ValidationStage.Signature, CancellationToken.None);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("MISSING_DETACHED_PAYLOAD"));
    }

    #endregion

    #region Invalid Signature Tests

    [Test]
    public void Validate_WithTamperedContent_ReturnsFailure()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var validator = new CertificateSignatureValidator();
        var tamperedMessage = CreateTamperedSignature(ctx);

        // Act
        var result = validator.Validate(tamperedMessage, ValidationStage.Signature);

        // Assert
        Assert.That(result.IsValid, Is.False);
        // CertificateSignatureValidator delegates to CertificateEmbeddedSignatureValidator for embedded messages
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateEmbeddedSignatureValidator)));
    }

    [Test]
    public void Validate_WithTamperedContentAllowUnprotected_ReturnsFailure()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var validator = new CertificateSignatureValidator(allowUnprotectedHeaders: true);
        var tamperedMessage = CreateTamperedSignature(ctx);

        // Act
        var result = validator.Validate(tamperedMessage, ValidationStage.Signature);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("SIGNATURE_INVALID"));
    }

    [Test]
    public async Task ValidateAsync_WithTamperedSignature_ReturnsFailure()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var validator = new CertificateSignatureValidator();
        var tamperedMessage = CreateTamperedSignature(ctx);

        // Act
        var result = await validator.ValidateAsync(tamperedMessage, ValidationStage.Signature, CancellationToken.None);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo("SIGNATURE_INVALID"));
    }

    #endregion

    #region Success Path Tests

    [Test]
    public void Validate_WithValidEmbeddedSignature_ReturnsSuccess()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var validator = new CertificateSignatureValidator();
        var validMessage = CreateValidEmbeddedSignature(ctx);

        // Act
        var result = validator.Validate(validMessage, ValidationStage.Signature);

        // Assert
        Assert.That(result.IsValid, Is.True);
        // CertificateSignatureValidator delegates to CertificateEmbeddedSignatureValidator for embedded messages
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateEmbeddedSignatureValidator)));
        Assert.That(result.Failures, Is.Empty);
    }

    [Test]
    public void Validate_WithValidEmbeddedSignatureAllowUnprotected_ReturnsSuccess()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var validator = new CertificateSignatureValidator(allowUnprotectedHeaders: true);
        var validMessage = CreateValidEmbeddedSignature(ctx);

        // Act
        var result = validator.Validate(validMessage, ValidationStage.Signature);

        // Assert
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Failures, Is.Empty);
    }

    [Test]
    public async Task ValidateAsync_WithValidEmbeddedSignature_ReturnsSuccess()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var validator = new CertificateSignatureValidator();
        var validMessage = CreateValidEmbeddedSignature(ctx);

        // Act
        var result = await validator.ValidateAsync(validMessage, ValidationStage.Signature, CancellationToken.None);

        // Assert
        Assert.That(result.IsValid, Is.True);
        // CertificateSignatureValidator delegates to CertificateEmbeddedSignatureValidator for embedded messages
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateEmbeddedSignatureValidator)));
    }

    [Test]
    public async Task ValidateAsync_WithCancellationTokenNotCancelled_CompletesSuccessfully()
    {
        // Arrange
        using var ctx = CreateTestContext();
        var validator = new CertificateSignatureValidator();
        var validMessage = CreateValidEmbeddedSignature(ctx);
        using var cts = new CancellationTokenSource();

        // Act
        var result = await validator.ValidateAsync(validMessage, ValidationStage.Signature, cts.Token);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    #endregion

    #region Helper Methods

    private static CoseSign1Message CreateValidEmbeddedSignature(TestContext ctx)
    {
        var chainBuilder = new X509ChainBuilder();
        using var signingService = CertificateSigningService.Create(ctx.TestCert!, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        return CoseSign1Message.DecodeSign1(messageBytes);
    }

    private static CoseSign1Message CreateDetachedSignature(TestContext ctx)
    {
        // Create a valid embedded signature using factory
        var chainBuilder = new X509ChainBuilder();
        using var signingService = CertificateSigningService.Create(ctx.TestCert!, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");

        // COSE_Sign1 CBOR structure: Array with 4 elements [protected, unprotected, payload, signature]
        // To create detached signature, we need to replace payload element with null (0xF6)
        // Parse the CBOR manually and replace the payload bytes

        // Simple approach: Find the payload in the byte array and replace with CBOR null
        // The payload is the 3rd element in the array
        // For a small payload like [1,2,3,4,5], it appears as: 0x45 (byte string of length 5) followed by the 5 bytes
        // We'll replace this with 0xF6 (CBOR null)

        // Find the pattern: look for the payload bytes
        for (int i = 0; i < messageBytes.Length - 6; i++)
        {
            if (messageBytes[i] == 0x45 && // CBOR byte string, length 5
                messageBytes[i + 1] == 1 &&
                messageBytes[i + 2] == 2 &&
                messageBytes[i + 3] == 3 &&
                messageBytes[i + 4] == 4 &&
                messageBytes[i + 5] == 5)
            {
                // Found the payload - replace with CBOR null (0xF6)
                var detachedBytes = new byte[messageBytes.Length - 5]; // Remove 5 bytes (0x45 + 5 payload bytes becomes 0xF6)
                Array.Copy(messageBytes, 0, detachedBytes, 0, i);
                detachedBytes[i] = 0xF6; // CBOR null
                Array.Copy(messageBytes, i + 6, detachedBytes, i + 1, messageBytes.Length - i - 6);

                return CoseSign1Message.DecodeSign1(detachedBytes);
            }
        }

        // If we couldn't find/modify, just return original (test will handle appropriately)
        return CoseSign1Message.DecodeSign1(messageBytes);
    }

    private static CoseSign1Message CreateTamperedSignature(TestContext ctx)
    {
        // Create a valid signature using factory
        var chainBuilder = new X509ChainBuilder();
        using var signingService = CertificateSigningService.Create(ctx.TestCert!, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");

        // Tamper with the signature bytes to make it invalid
        // The COSE_Sign1 structure is: [protected, unprotected, payload, signature]
        // We'll flip some bits in the signature portion
        if (messageBytes.Length > 20)
        {
            // Flip bits near the end (likely in signature)
            messageBytes[messageBytes.Length - 10] ^= 0xFF;
            messageBytes[messageBytes.Length - 5] ^= 0xFF;
            messageBytes[messageBytes.Length - 2] ^= 0xFF;
        }

        // Decode the tampered message
        return CoseSign1Message.DecodeSign1(messageBytes);
    }

    #endregion
}