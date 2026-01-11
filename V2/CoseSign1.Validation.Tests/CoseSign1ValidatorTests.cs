// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using CoseSign1.Validation.Trust;
using Microsoft.Extensions.Logging;
using Moq;

/// <summary>
/// Tests for <see cref="CoseSign1Validator"/>.
/// </summary>
[TestFixture]
[Category("Validation")]
public class CoseSign1ValidatorTests
{
    #region Constructor Tests

    [Test]
    public void Constructor_NullComponents_ThrowsArgumentNullException()
    {
        var policy = TrustPolicy.AllowAll();

        Assert.Throws<ArgumentNullException>(() => new CoseSign1Validator(null!, policy));
    }

    [Test]
    public void Constructor_NullTrustPolicy_ThrowsArgumentNullException()
    {
        var components = new List<IValidationComponent> { CreateMockResolver().Object };

        Assert.Throws<ArgumentNullException>(() => new CoseSign1Validator(components, null!));
    }

    [Test]
    public void Constructor_EmptyComponents_ThrowsInvalidOperationException()
    {
        var components = new List<IValidationComponent>();
        var policy = TrustPolicy.AllowAll();

        var ex = Assert.Throws<InvalidOperationException>(() => new CoseSign1Validator(components, policy));
        Assert.That(ex!.Message, Does.Contain("No validation components"));
    }

    [Test]
    public void Constructor_ValidParameters_CreatesInstance()
    {
        var mockResolver = CreateMockResolver();
        var components = new List<IValidationComponent> { mockResolver.Object };
        var policy = TrustPolicy.AllowAll();

        var validator = new CoseSign1Validator(components, policy);

        Assert.Multiple(() =>
        {
            Assert.That(validator.Components, Has.Count.EqualTo(1));
            Assert.That(validator.TrustPolicy, Is.SameAs(policy));
        });
    }

    [Test]
    public void Constructor_WithOptions_CreatesInstance()
    {
        var mockResolver = CreateMockResolver();
        var components = new List<IValidationComponent> { mockResolver.Object };
        var policy = TrustPolicy.AllowAll();
        var options = new CoseSign1ValidationOptions();

        var validator = new CoseSign1Validator(components, policy, options);

        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithLogger_CreatesInstance()
    {
        var mockResolver = CreateMockResolver();
        var components = new List<IValidationComponent> { mockResolver.Object };
        var policy = TrustPolicy.AllowAll();
        var mockLogger = new Mock<ILogger<CoseSign1Validator>>();

        var validator = new CoseSign1Validator(components, policy, null, mockLogger.Object);

        Assert.That(validator, Is.Not.Null);
    }

    #endregion

    #region Validate Instance Method Tests

    [Test]
    public void Validate_NullMessage_ThrowsArgumentNullException()
    {
        var validator = CreateValidator();

        Assert.Throws<ArgumentNullException>(() => validator.Validate(null!));
    }

    [Test]
    public void Validate_NoApplicableResolvers_ReturnsResolutionFailure()
    {
        // Create a resolver that says it's not applicable to any message
        var mockResolver = new Mock<ISigningKeyResolver>();
        mockResolver.Setup(r => r.IsApplicableTo(It.IsAny<CoseSign1Message>(), It.IsAny<CoseSign1ValidationOptions>()))
            .Returns(false);
        mockResolver.Setup(r => r.ComponentName).Returns("MockResolver");

        var components = new List<IValidationComponent> { mockResolver.Object };
        var validator = new CoseSign1Validator(components, TrustPolicy.AllowAll());

        var message = CreateSignedMessage();
        var result = validator.Validate(message);

        Assert.Multiple(() =>
        {
            Assert.That(result.Resolution.IsFailure, Is.True);
            Assert.That(result.Overall.IsFailure, Is.True);
            Assert.That(result.Trust.IsNotApplicable, Is.True);
        });
    }

    [Test]
    public void Validate_ResolverReturnsFailure_ReturnsResolutionFailure()
    {
        var mockResolver = new Mock<ISigningKeyResolver>();
        mockResolver.Setup(r => r.IsApplicableTo(It.IsAny<CoseSign1Message>(), It.IsAny<CoseSign1ValidationOptions>()))
            .Returns(true);
        mockResolver.Setup(r => r.ComponentName).Returns("MockResolver");
        mockResolver.Setup(r => r.Resolve(It.IsAny<CoseSign1Message>()))
            .Returns(SigningKeyResolutionResult.Failure("No key found"));

        var components = new List<IValidationComponent> { mockResolver.Object };
        var validator = new CoseSign1Validator(components, TrustPolicy.AllowAll());

        var message = CreateSignedMessage();
        var result = validator.Validate(message);

        Assert.Multiple(() =>
        {
            Assert.That(result.Resolution.IsFailure, Is.True);
            Assert.That(result.Overall.IsFailure, Is.True);
        });
    }

    [Test]
    public void Validate_TrustPolicyDenied_ReturnsTrustFailure()
    {
        using var key = ECDsa.Create();
        var message = CreateSignedMessage(key);
        var coseKey = new CoseKey(key, HashAlgorithmName.SHA256);

        var mockSigningKey = new Mock<ISigningKey>();
        mockSigningKey.Setup(k => k.GetCoseKey()).Returns(coseKey);

        var mockResolver = new Mock<ISigningKeyResolver>();
        mockResolver.Setup(r => r.IsApplicableTo(It.IsAny<CoseSign1Message>(), It.IsAny<CoseSign1ValidationOptions>()))
            .Returns(true);
        mockResolver.Setup(r => r.ComponentName).Returns("MockResolver");
        mockResolver.Setup(r => r.Resolve(It.IsAny<CoseSign1Message>()))
            .Returns(SigningKeyResolutionResult.Success(mockSigningKey.Object));

        var components = new List<IValidationComponent> { mockResolver.Object };
        var validator = new CoseSign1Validator(components, TrustPolicy.DenyAll("Test deny"));

        var result = validator.Validate(message);

        Assert.Multiple(() =>
        {
            Assert.That(result.Resolution.IsSuccess, Is.True);
            Assert.That(result.Trust.IsFailure, Is.True);
            Assert.That(result.Overall.IsFailure, Is.True);
        });
    }

    [Test]
    public void Validate_SignatureVerificationFails_ReturnsSignatureFailure()
    {
        // Create a message signed with one key, but resolve a different key
        using var key1 = ECDsa.Create();
        using var key2 = ECDsa.Create();

        var message = CreateSignedMessage(key1);
        var wrongCoseKey = new CoseKey(key2, HashAlgorithmName.SHA256);

        var mockSigningKey = new Mock<ISigningKey>();
        mockSigningKey.Setup(k => k.GetCoseKey()).Returns(wrongCoseKey);

        var mockResolver = new Mock<ISigningKeyResolver>();
        mockResolver.Setup(r => r.IsApplicableTo(It.IsAny<CoseSign1Message>(), It.IsAny<CoseSign1ValidationOptions>()))
            .Returns(true);
        mockResolver.Setup(r => r.ComponentName).Returns("MockResolver");
        mockResolver.Setup(r => r.Resolve(It.IsAny<CoseSign1Message>()))
            .Returns(SigningKeyResolutionResult.Success(mockSigningKey.Object));

        var components = new List<IValidationComponent> { mockResolver.Object };
        var validator = new CoseSign1Validator(components, TrustPolicy.AllowAll());

        var result = validator.Validate(message);

        Assert.Multiple(() =>
        {
            Assert.That(result.Resolution.IsSuccess, Is.True);
            Assert.That(result.Trust.IsSuccess, Is.True);
            Assert.That(result.Signature.IsFailure, Is.True);
            Assert.That(result.Overall.IsFailure, Is.True);
        });
    }

    [Test]
    public void Validate_AllStagesPass_ReturnsSuccess()
    {
        using var key = ECDsa.Create();
        var message = CreateSignedMessage(key);
        var coseKey = new CoseKey(key, HashAlgorithmName.SHA256);

        var mockSigningKey = new Mock<ISigningKey>();
        mockSigningKey.Setup(k => k.GetCoseKey()).Returns(coseKey);

        var mockResolver = new Mock<ISigningKeyResolver>();
        mockResolver.Setup(r => r.IsApplicableTo(It.IsAny<CoseSign1Message>(), It.IsAny<CoseSign1ValidationOptions>()))
            .Returns(true);
        mockResolver.Setup(r => r.ComponentName).Returns("MockResolver");
        mockResolver.Setup(r => r.Resolve(It.IsAny<CoseSign1Message>()))
            .Returns(SigningKeyResolutionResult.Success(mockSigningKey.Object));

        var components = new List<IValidationComponent> { mockResolver.Object };
        var validator = new CoseSign1Validator(components, TrustPolicy.AllowAll());

        var result = validator.Validate(message);

        Assert.Multiple(() =>
        {
            Assert.That(result.Resolution.IsSuccess, Is.True);
            Assert.That(result.Trust.IsSuccess, Is.True);
            Assert.That(result.Signature.IsSuccess, Is.True);
            Assert.That(result.PostSignaturePolicy.IsSuccess, Is.True);
            Assert.That(result.Overall.IsSuccess, Is.True);
        });
    }

    [Test]
    public void Validate_WithPostSignatureValidator_ExecutesPostValidation()
    {
        using var key = ECDsa.Create();
        var message = CreateSignedMessage(key);
        var coseKey = new CoseKey(key, HashAlgorithmName.SHA256);

        var mockSigningKey = new Mock<ISigningKey>();
        mockSigningKey.Setup(k => k.GetCoseKey()).Returns(coseKey);

        var mockResolver = new Mock<ISigningKeyResolver>();
        mockResolver.Setup(r => r.IsApplicableTo(It.IsAny<CoseSign1Message>(), It.IsAny<CoseSign1ValidationOptions>()))
            .Returns(true);
        mockResolver.Setup(r => r.ComponentName).Returns("MockResolver");
        mockResolver.Setup(r => r.Resolve(It.IsAny<CoseSign1Message>()))
            .Returns(SigningKeyResolutionResult.Success(mockSigningKey.Object));

        var mockPostValidator = new Mock<IPostSignatureValidator>();
        mockPostValidator.Setup(v => v.IsApplicableTo(It.IsAny<CoseSign1Message>(), It.IsAny<CoseSign1ValidationOptions>()))
            .Returns(true);
        mockPostValidator.Setup(v => v.ComponentName).Returns("MockPostValidator");
        mockPostValidator.Setup(v => v.Validate(It.IsAny<IPostSignatureValidationContext>()))
            .Returns(ValidationResult.Success("MockPostValidator"));

        var components = new List<IValidationComponent> { mockResolver.Object, mockPostValidator.Object };
        var validator = new CoseSign1Validator(components, TrustPolicy.AllowAll());

        var result = validator.Validate(message);

        Assert.That(result.PostSignaturePolicy.IsSuccess, Is.True);
        mockPostValidator.Verify(v => v.Validate(It.IsAny<IPostSignatureValidationContext>()), Times.Once);
    }

    [Test]
    public void Validate_PostSignatureValidatorFails_ReturnsPostSignatureFailure()
    {
        using var key = ECDsa.Create();
        var message = CreateSignedMessage(key);
        var coseKey = new CoseKey(key, HashAlgorithmName.SHA256);

        var mockSigningKey = new Mock<ISigningKey>();
        mockSigningKey.Setup(k => k.GetCoseKey()).Returns(coseKey);

        var mockResolver = new Mock<ISigningKeyResolver>();
        mockResolver.Setup(r => r.IsApplicableTo(It.IsAny<CoseSign1Message>(), It.IsAny<CoseSign1ValidationOptions>()))
            .Returns(true);
        mockResolver.Setup(r => r.ComponentName).Returns("MockResolver");
        mockResolver.Setup(r => r.Resolve(It.IsAny<CoseSign1Message>()))
            .Returns(SigningKeyResolutionResult.Success(mockSigningKey.Object));

        var mockPostValidator = new Mock<IPostSignatureValidator>();
        mockPostValidator.Setup(v => v.IsApplicableTo(It.IsAny<CoseSign1Message>(), It.IsAny<CoseSign1ValidationOptions>()))
            .Returns(true);
        mockPostValidator.Setup(v => v.ComponentName).Returns("MockPostValidator");
        mockPostValidator.Setup(v => v.Validate(It.IsAny<IPostSignatureValidationContext>()))
            .Returns(ValidationResult.Failure("MockPostValidator", "Post validation failed"));

        var components = new List<IValidationComponent> { mockResolver.Object, mockPostValidator.Object };
        var validator = new CoseSign1Validator(components, TrustPolicy.AllowAll());

        var result = validator.Validate(message);

        Assert.Multiple(() =>
        {
            Assert.That(result.PostSignaturePolicy.IsFailure, Is.True);
            Assert.That(result.Overall.IsFailure, Is.True);
        });
    }

    #endregion

    #region ValidateAsync Instance Method Tests

    [Test]
    public async Task ValidateAsync_NullMessage_ThrowsArgumentNullException()
    {
        var validator = CreateValidator();

        await Task.Run(() => Assert.ThrowsAsync<ArgumentNullException>(() => validator.ValidateAsync(null!)));
    }

    [Test]
    public async Task ValidateAsync_AllStagesPass_ReturnsSuccess()
    {
        using var key = ECDsa.Create();
        var message = CreateSignedMessage(key);
        var coseKey = new CoseKey(key, HashAlgorithmName.SHA256);

        var mockSigningKey = new Mock<ISigningKey>();
        mockSigningKey.Setup(k => k.GetCoseKey()).Returns(coseKey);

        var mockResolver = new Mock<ISigningKeyResolver>();
        mockResolver.Setup(r => r.IsApplicableTo(It.IsAny<CoseSign1Message>(), It.IsAny<CoseSign1ValidationOptions>()))
            .Returns(true);
        mockResolver.Setup(r => r.ComponentName).Returns("MockResolver");
        mockResolver.Setup(r => r.ResolveAsync(It.IsAny<CoseSign1Message>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(SigningKeyResolutionResult.Success(mockSigningKey.Object));

        var components = new List<IValidationComponent> { mockResolver.Object };
        var validator = new CoseSign1Validator(components, TrustPolicy.AllowAll());

        var result = await validator.ValidateAsync(message);

        Assert.Multiple(() =>
        {
            Assert.That(result.Resolution.IsSuccess, Is.True);
            Assert.That(result.Overall.IsSuccess, Is.True);
        });
    }

    [Test]
    public async Task ValidateAsync_WithCancellation_HonorsCancellationToken()
    {
        var mockResolver = new Mock<ISigningKeyResolver>();
        mockResolver.Setup(r => r.IsApplicableTo(It.IsAny<CoseSign1Message>(), It.IsAny<CoseSign1ValidationOptions>()))
            .Returns(true);
        mockResolver.Setup(r => r.ComponentName).Returns("MockResolver");
        mockResolver.Setup(r => r.ResolveAsync(It.IsAny<CoseSign1Message>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((CoseSign1Message _, CancellationToken ct) =>
            {
                ct.ThrowIfCancellationRequested();
                return SigningKeyResolutionResult.Failure("Test");
            });

        var components = new List<IValidationComponent> { mockResolver.Object };
        var validator = new CoseSign1Validator(components, TrustPolicy.AllowAll());

        var cts = new CancellationTokenSource();
        cts.Cancel();

        using var key = ECDsa.Create();
        var message = CreateSignedMessage(key);

        Assert.ThrowsAsync<OperationCanceledException>(async () => await validator.ValidateAsync(message, cts.Token));
    }

    #endregion

    #region Detached Signature Tests

    [Test]
    public void Validate_DetachedSignature_NoPayloadProvided_ReturnsSignatureFailure()
    {
        using var key = ECDsa.Create();
        var message = CreateDetachedSignatureMessage(key, TestPayload);
        var coseKey = new CoseKey(key, HashAlgorithmName.SHA256);

        var mockSigningKey = new Mock<ISigningKey>();
        mockSigningKey.Setup(k => k.GetCoseKey()).Returns(coseKey);

        var mockResolver = new Mock<ISigningKeyResolver>();
        mockResolver.Setup(r => r.IsApplicableTo(It.IsAny<CoseSign1Message>(), It.IsAny<CoseSign1ValidationOptions>()))
            .Returns(true);
        mockResolver.Setup(r => r.ComponentName).Returns("MockResolver");
        mockResolver.Setup(r => r.Resolve(It.IsAny<CoseSign1Message>()))
            .Returns(SigningKeyResolutionResult.Success(mockSigningKey.Object));

        // No detached payload in options
        var options = new CoseSign1ValidationOptions();
        var components = new List<IValidationComponent> { mockResolver.Object };
        var validator = new CoseSign1Validator(components, TrustPolicy.AllowAll(), options);

        var result = validator.Validate(message);

        Assert.Multiple(() =>
        {
            Assert.That(result.Signature.IsFailure, Is.True);
            Assert.That(result.Signature.Failures, Has.Some.Property("Message").Contain("payload"));
        });
    }

    [Test]
    public void Validate_DetachedSignature_ValidPayload_ReturnsSuccess()
    {
        using var key = ECDsa.Create();
        var message = CreateDetachedSignatureMessage(key, TestPayload);
        var coseKey = new CoseKey(key, HashAlgorithmName.SHA256);

        var mockSigningKey = new Mock<ISigningKey>();
        mockSigningKey.Setup(k => k.GetCoseKey()).Returns(coseKey);

        var mockResolver = new Mock<ISigningKeyResolver>();
        mockResolver.Setup(r => r.IsApplicableTo(It.IsAny<CoseSign1Message>(), It.IsAny<CoseSign1ValidationOptions>()))
            .Returns(true);
        mockResolver.Setup(r => r.ComponentName).Returns("MockResolver");
        mockResolver.Setup(r => r.Resolve(It.IsAny<CoseSign1Message>()))
            .Returns(SigningKeyResolutionResult.Success(mockSigningKey.Object));

        // Provide detached payload
        var options = new CoseSign1ValidationOptions
        {
            DetachedPayload = new MemoryStream(TestPayload)
        };
        var components = new List<IValidationComponent> { mockResolver.Object };
        var validator = new CoseSign1Validator(components, TrustPolicy.AllowAll(), options);

        var result = validator.Validate(message);

        Assert.That(result.Signature.IsSuccess, Is.True);
    }

    [Test]
    public void Validate_DetachedSignature_EmptyPayload_ReturnsSignatureFailure()
    {
        using var key = ECDsa.Create();
        var message = CreateDetachedSignatureMessage(key, TestPayload);
        var coseKey = new CoseKey(key, HashAlgorithmName.SHA256);

        var mockSigningKey = new Mock<ISigningKey>();
        mockSigningKey.Setup(k => k.GetCoseKey()).Returns(coseKey);

        var mockResolver = new Mock<ISigningKeyResolver>();
        mockResolver.Setup(r => r.IsApplicableTo(It.IsAny<CoseSign1Message>(), It.IsAny<CoseSign1ValidationOptions>()))
            .Returns(true);
        mockResolver.Setup(r => r.ComponentName).Returns("MockResolver");
        mockResolver.Setup(r => r.Resolve(It.IsAny<CoseSign1Message>()))
            .Returns(SigningKeyResolutionResult.Success(mockSigningKey.Object));

        // Provide empty detached payload
        var options = new CoseSign1ValidationOptions
        {
            DetachedPayload = new MemoryStream(Array.Empty<byte>())
        };
        var components = new List<IValidationComponent> { mockResolver.Object };
        var validator = new CoseSign1Validator(components, TrustPolicy.AllowAll(), options);

        var result = validator.Validate(message);

        Assert.Multiple(() =>
        {
            Assert.That(result.Signature.IsFailure, Is.True);
        });
    }

    [Test]
    public void Validate_DetachedSignature_WrongPayload_ReturnsSignatureFailure()
    {
        using var key = ECDsa.Create();
        var message = CreateDetachedSignatureMessage(key, TestPayload);
        var coseKey = new CoseKey(key, HashAlgorithmName.SHA256);

        var mockSigningKey = new Mock<ISigningKey>();
        mockSigningKey.Setup(k => k.GetCoseKey()).Returns(coseKey);

        var mockResolver = new Mock<ISigningKeyResolver>();
        mockResolver.Setup(r => r.IsApplicableTo(It.IsAny<CoseSign1Message>(), It.IsAny<CoseSign1ValidationOptions>()))
            .Returns(true);
        mockResolver.Setup(r => r.ComponentName).Returns("MockResolver");
        mockResolver.Setup(r => r.Resolve(It.IsAny<CoseSign1Message>()))
            .Returns(SigningKeyResolutionResult.Success(mockSigningKey.Object));

        // Provide wrong payload
        var wrongPayload = new byte[] { 0x01, 0x02, 0x03 };
        var options = new CoseSign1ValidationOptions
        {
            DetachedPayload = new MemoryStream(wrongPayload)
        };
        var components = new List<IValidationComponent> { mockResolver.Object };
        var validator = new CoseSign1Validator(components, TrustPolicy.AllowAll(), options);

        var result = validator.Validate(message);

        Assert.That(result.Signature.IsFailure, Is.True);
    }

    [Test]
    public async Task ValidateAsync_DetachedSignature_ValidPayload_ReturnsSuccess()
    {
        using var key = ECDsa.Create();
        var message = CreateDetachedSignatureMessage(key, TestPayload);
        var coseKey = new CoseKey(key, HashAlgorithmName.SHA256);

        var mockSigningKey = new Mock<ISigningKey>();
        mockSigningKey.Setup(k => k.GetCoseKey()).Returns(coseKey);

        var mockResolver = new Mock<ISigningKeyResolver>();
        mockResolver.Setup(r => r.IsApplicableTo(It.IsAny<CoseSign1Message>(), It.IsAny<CoseSign1ValidationOptions>()))
            .Returns(true);
        mockResolver.Setup(r => r.ComponentName).Returns("MockResolver");
        mockResolver.Setup(r => r.ResolveAsync(It.IsAny<CoseSign1Message>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(SigningKeyResolutionResult.Success(mockSigningKey.Object));

        // Provide detached payload
        var options = new CoseSign1ValidationOptions
        {
            DetachedPayload = new MemoryStream(TestPayload)
        };
        var components = new List<IValidationComponent> { mockResolver.Object };
        var validator = new CoseSign1Validator(components, TrustPolicy.AllowAll(), options);

        var result = await validator.ValidateAsync(message);

        Assert.That(result.Signature.IsSuccess, Is.True);
    }

    [Test]
    public void Validate_DetachedSignature_WithAssociatedData_ReturnsSuccess()
    {
        using var key = ECDsa.Create();
        var associatedData = new byte[] { 0xAA, 0xBB, 0xCC };
        var message = CreateDetachedSignatureMessageWithAad(key, TestPayload, associatedData);
        var coseKey = new CoseKey(key, HashAlgorithmName.SHA256);

        var mockSigningKey = new Mock<ISigningKey>();
        mockSigningKey.Setup(k => k.GetCoseKey()).Returns(coseKey);

        var mockResolver = new Mock<ISigningKeyResolver>();
        mockResolver.Setup(r => r.IsApplicableTo(It.IsAny<CoseSign1Message>(), It.IsAny<CoseSign1ValidationOptions>()))
            .Returns(true);
        mockResolver.Setup(r => r.ComponentName).Returns("MockResolver");
        mockResolver.Setup(r => r.Resolve(It.IsAny<CoseSign1Message>()))
            .Returns(SigningKeyResolutionResult.Success(mockSigningKey.Object));

        // Provide detached payload and associated data
        var options = new CoseSign1ValidationOptions
        {
            DetachedPayload = new MemoryStream(TestPayload),
            AssociatedData = associatedData
        };
        var components = new List<IValidationComponent> { mockResolver.Object };
        var validator = new CoseSign1Validator(components, TrustPolicy.AllowAll(), options);

        var result = validator.Validate(message);

        Assert.That(result.Signature.IsSuccess, Is.True);
    }

    #endregion

    #region Static Validate Method Tests

    [Test]
    public void StaticValidate_NullMessage_ThrowsArgumentNullException()
    {
        var mockResolver = CreateMockResolver();
        var components = new List<IValidationComponent> { mockResolver.Object };
        var policy = TrustPolicy.AllowAll();

        Assert.Throws<ArgumentNullException>(() => CoseSign1Validator.Validate(null!, components, policy));
    }

    [Test]
    public void StaticValidate_NullComponents_ThrowsArgumentNullException()
    {
        using var key = ECDsa.Create();
        var message = CreateSignedMessage(key);
        var policy = TrustPolicy.AllowAll();

        Assert.Throws<ArgumentNullException>(() => CoseSign1Validator.Validate(message, null!, policy));
    }

    [Test]
    public void StaticValidate_NullPolicy_ThrowsArgumentNullException()
    {
        using var key = ECDsa.Create();
        var message = CreateSignedMessage(key);
        var mockResolver = CreateMockResolver();
        var components = new List<IValidationComponent> { mockResolver.Object };

        Assert.Throws<ArgumentNullException>(() => CoseSign1Validator.Validate(message, components, null!));
    }

    [Test]
    public void StaticValidate_ValidParameters_ReturnsResult()
    {
        using var key = ECDsa.Create();
        var message = CreateSignedMessage(key);
        var coseKey = new CoseKey(key, HashAlgorithmName.SHA256);

        var mockSigningKey = new Mock<ISigningKey>();
        mockSigningKey.Setup(k => k.GetCoseKey()).Returns(coseKey);

        var mockResolver = new Mock<ISigningKeyResolver>();
        mockResolver.Setup(r => r.IsApplicableTo(It.IsAny<CoseSign1Message>(), It.IsAny<CoseSign1ValidationOptions>()))
            .Returns(true);
        mockResolver.Setup(r => r.ComponentName).Returns("MockResolver");
        mockResolver.Setup(r => r.Resolve(It.IsAny<CoseSign1Message>()))
            .Returns(SigningKeyResolutionResult.Success(mockSigningKey.Object));

        var components = new List<IValidationComponent> { mockResolver.Object };
        var policy = TrustPolicy.AllowAll();

        var result = CoseSign1Validator.Validate(message, components, policy);

        Assert.That(result.Overall.IsSuccess, Is.True);
    }

    #endregion

    #region Helper Methods

    private static readonly byte[] TestPayload = "Test payload for validation"u8.ToArray();

    private static Mock<ISigningKeyResolver> CreateMockResolver()
    {
        var mock = new Mock<ISigningKeyResolver>();
        mock.Setup(r => r.IsApplicableTo(It.IsAny<CoseSign1Message>(), It.IsAny<CoseSign1ValidationOptions>()))
            .Returns(true);
        mock.Setup(r => r.ComponentName).Returns("MockResolver");
        return mock;
    }

    private static CoseSign1Validator CreateValidator()
    {
        var mockResolver = CreateMockResolver();
        mockResolver.Setup(r => r.Resolve(It.IsAny<CoseSign1Message>()))
            .Returns(SigningKeyResolutionResult.Failure("Test"));
        var components = new List<IValidationComponent> { mockResolver.Object };
        return new CoseSign1Validator(components, TrustPolicy.AllowAll());
    }

    private static CoseSign1Message CreateSignedMessage(ECDsa? key = null)
    {
        key ??= ECDsa.Create();
        var payload = "Test payload"u8.ToArray();
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        var signedBytes = CoseSign1Message.SignEmbedded(payload, signer);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    private static CoseSign1Message CreateDetachedSignatureMessage(ECDsa key, byte[] payload)
    {
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        var signedBytes = CoseSign1Message.SignDetached(payload, signer);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    private static CoseSign1Message CreateDetachedSignatureMessageWithAad(ECDsa key, byte[] payload, byte[] associatedData)
    {
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        var signedBytes = CoseSign1Message.SignDetached(payload, signer, associatedData: associatedData);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    #endregion
}
