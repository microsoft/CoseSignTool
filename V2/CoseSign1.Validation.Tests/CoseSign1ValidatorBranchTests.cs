// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using CoseSign1.Validation.Trust;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Rules;

[TestFixture]
[Category("Validation")]
public sealed class CoseSign1ValidatorBranchTests
{
    private static readonly byte[] Payload = "payload"u8.ToArray();

    private sealed class FixedSigningKeyResolver : ISigningKeyResolver
    {
        private readonly ISigningKey SigningKey;

        public FixedSigningKeyResolver(ISigningKey signingKey)
        {
            SigningKey = signingKey ?? throw new ArgumentNullException(nameof(signingKey));
        }

        public SigningKeyResolutionResult Resolve(CoseSign1Message message)
        {
            return SigningKeyResolutionResult.Success(SigningKey);
        }

        public Task<SigningKeyResolutionResult> ResolveAsync(CoseSign1Message message, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(SigningKeyResolutionResult.Success(SigningKey));
        }
    }

    private sealed class EcdsaSigningKey : ISigningKey
    {
        private readonly ECDsa Key;

        public EcdsaSigningKey(ECDsa key)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
        }

        public CoseKey GetCoseKey() => new CoseKey(Key, HashAlgorithmName.SHA256);

        public void Dispose()
        {
            // The test owns the ECDsa instance.
        }
    }

    private sealed class ThrowingSigningKey : ISigningKey
    {
        private readonly Exception Exception;

        public ThrowingSigningKey(Exception exception)
        {
            Exception = exception ?? throw new ArgumentNullException(nameof(exception));
        }

        public CoseKey GetCoseKey() => throw Exception;

        public void Dispose()
        {
            // No-op.
        }
    }

    private sealed class NonSeekableReadStream : Stream
    {
        private readonly Stream Inner;

        public NonSeekableReadStream(byte[] bytes)
        {
            Inner = new MemoryStream(bytes, writable: false);
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => Inner.Length;

        public override long Position
        {
            get => Inner.Position;
            set => throw new NotSupportedException();
        }

        public override void Flush() => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count) => Inner.Read(buffer, offset, count);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => Inner.ReadAsync(buffer, offset, count, cancellationToken);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }

    private sealed class CountingFailingPostSignatureValidator : IPostSignatureValidator
    {
        public int ValidateCallCount { get; private set; }

        public int ValidateAsyncCallCount { get; private set; }

        public ValidationResult Validate(IPostSignatureValidationContext context)
        {
            ValidateCallCount++;
            return ValidationResult.Failure("post", "nope", "E_POST");
        }

        public Task<ValidationResult> ValidateAsync(IPostSignatureValidationContext context, CancellationToken cancellationToken = default)
        {
            ValidateAsyncCallCount++;
            return Task.FromResult(ValidationResult.Failure("post", "nope", "E_POST"));
        }
    }

    private sealed class DeniedWithoutReasonsRule : TrustRule
    {
        public override ValueTask<TrustDecision> EvaluateAsync(TrustRuleContext context)
        {
            return new ValueTask<TrustDecision>(TrustDecision.Denied(Array.Empty<string>()));
        }
    }

    private static CoseSign1Message CreateSignedEmbeddedMessage(ECDsa signingKey)
    {
        var signer = new CoseSigner(signingKey, HashAlgorithmName.SHA256);
        byte[] messageBytes = CoseSign1Message.SignEmbedded(Payload, signer);
        return CoseMessage.DecodeSign1(messageBytes);
    }

    private static CoseSign1Message CreateSignedDetachedMessage(ECDsa signingKey, ReadOnlySpan<byte> associatedData)
    {
        var signer = new CoseSigner(signingKey, HashAlgorithmName.SHA256);
        byte[] messageBytes = CoseSign1Message.SignDetached(Payload, signer, associatedData);
        return CoseMessage.DecodeSign1(messageBytes);
    }

    private static CompiledTrustPlan CreateAllowAllTrustPlan()
    {
        return new CompiledTrustPlan(TrustRules.AllowAll(), Array.Empty<IMultiTrustFactProducer>());
    }

    [Test]
    public void Validate_WhenMessageIsNull_ThrowsArgumentNullException()
    {
        var validator = new CoseSign1Validator(
            signingKeyResolvers: Array.Empty<ISigningKeyResolver>(),
            postSignatureValidators: null,
            toBeSignedAttestors: null,
            trustPlan: CreateAllowAllTrustPlan());

        Assert.That(() => validator.Validate(null!), Throws.ArgumentNullException);
    }

    [Test]
    public void Validate_WhenSigningKeyGetCoseKeyThrows_ReturnsSignatureFailureWithExceptionMessage()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var message = CreateSignedEmbeddedMessage(signingKey);

        var resolver = new FixedSigningKeyResolver(new ThrowingSigningKey(new InvalidOperationException("boom")));

        var validator = new CoseSign1Validator(
            signingKeyResolvers: new[] { resolver },
            postSignatureValidators: null,
            toBeSignedAttestors: null,
            trustPlan: CreateAllowAllTrustPlan());

        var result = validator.Validate(message);

        Assert.That(result.Signature.IsFailure, Is.True);
        Assert.That(result.Signature.Failures, Is.Not.Empty);
        Assert.That(result.Signature.Failures[0].ErrorCode, Is.EqualTo("SIGNATURE_VERIFICATION_FAILED"));
        Assert.That(result.Signature.Failures[0].Message, Is.EqualTo("boom"));
    }

    [Test]
    public void Validate_WhenDetachedSignatureAndNoPayloadProvided_ReturnsSignatureMissingPayloadFailure()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var message = CreateSignedDetachedMessage(signingKey, ReadOnlySpan<byte>.Empty);

        var resolver = new FixedSigningKeyResolver(new EcdsaSigningKey(signingKey));

        var validator = new CoseSign1Validator(
            signingKeyResolvers: new[] { resolver },
            postSignatureValidators: null,
            toBeSignedAttestors: null,
            trustPlan: CreateAllowAllTrustPlan(),
            options: new CoseSign1ValidationOptions { DetachedPayload = null });

        var result = validator.Validate(message);

        Assert.That(result.Signature.IsFailure, Is.True);
        Assert.That(result.Signature.Failures[0].ErrorCode, Is.EqualTo("SIGNATURE_MISSING_PAYLOAD"));
    }

    [Test]
    public void Validate_WhenDetachedSignatureAndEmptyPayloadStream_ReturnsSignatureMissingPayloadFailure()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var message = CreateSignedDetachedMessage(signingKey, ReadOnlySpan<byte>.Empty);

        var resolver = new FixedSigningKeyResolver(new EcdsaSigningKey(signingKey));

        var options = new CoseSign1ValidationOptions
        {
            DetachedPayload = new MemoryStream(Array.Empty<byte>(), writable: false)
        };

        var validator = new CoseSign1Validator(
            signingKeyResolvers: new[] { resolver },
            postSignatureValidators: null,
            toBeSignedAttestors: null,
            trustPlan: CreateAllowAllTrustPlan(),
            options: options);

        var result = validator.Validate(message);

        Assert.That(result.Signature.IsFailure, Is.True);
        Assert.That(result.Signature.Failures[0].ErrorCode, Is.EqualTo("SIGNATURE_MISSING_PAYLOAD"));
    }

    [Test]
    public async Task ValidateAsync_WhenDetachedSignatureWithAssociatedData_Succeeds()
    {
        byte[] associatedData = "aad"u8.ToArray();

        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var message = CreateSignedDetachedMessage(signingKey, associatedData);

        var resolver = new FixedSigningKeyResolver(new EcdsaSigningKey(signingKey));

        var options = new CoseSign1ValidationOptions
        {
            DetachedPayload = new MemoryStream(Payload, writable: false),
            AssociatedData = associatedData
        };

        var validator = new CoseSign1Validator(
            signingKeyResolvers: new[] { resolver },
            postSignatureValidators: null,
            toBeSignedAttestors: null,
            trustPlan: CreateAllowAllTrustPlan(),
            options: options);

        var result = await validator.ValidateAsync(message, CancellationToken.None);

        Assert.That(result.Overall.IsValid, Is.True);
    }

    [Test]
    public void Validate_WhenDetachedSignatureAndPayloadStreamIsNonSeekable_ReturnsSignatureFailure()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var message = CreateSignedDetachedMessage(signingKey, ReadOnlySpan<byte>.Empty);

        var resolver = new FixedSigningKeyResolver(new EcdsaSigningKey(signingKey));

        var options = new CoseSign1ValidationOptions
        {
            DetachedPayload = new NonSeekableReadStream(Payload)
        };

        var validator = new CoseSign1Validator(
            signingKeyResolvers: new[] { resolver },
            postSignatureValidators: null,
            toBeSignedAttestors: null,
            trustPlan: CreateAllowAllTrustPlan(),
            options: options);

        var result = validator.Validate(message);

        Assert.That(result.Signature.IsFailure, Is.True);
        Assert.That(result.Signature.Failures, Is.Not.Empty);
        Assert.That(result.Signature.Failures[0].ErrorCode, Is.EqualTo("SIGNATURE_VERIFICATION_FAILED"));
    }

    [Test]
    public void Validate_WhenTrustIsDenied_ProducesTrustFailureAndSkipsPostSignatureStage()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var message = CreateSignedEmbeddedMessage(signingKey);

        var resolver = new FixedSigningKeyResolver(new EcdsaSigningKey(signingKey));

        var trustPlan = new CompiledTrustPlan(new DeniedWithoutReasonsRule(), Array.Empty<IMultiTrustFactProducer>());

        var validator = new CoseSign1Validator(
            signingKeyResolvers: new[] { resolver },
            postSignatureValidators: new[] { new CountingFailingPostSignatureValidator() },
            toBeSignedAttestors: null,
            trustPlan: trustPlan);

        var result = validator.Validate(message);

        Assert.That(result.Trust.IsFailure, Is.True);
        Assert.That(result.Trust.Failures, Is.Not.Empty);
        Assert.That(result.Trust.Failures[0].ErrorCode, Is.EqualTo("TRUST_PLAN_NOT_SATISFIED"));

        Assert.That(result.Signature.IsNotApplicable, Is.True);

        Assert.That(result.PostSignaturePolicy.IsNotApplicable, Is.True);
        Assert.That(result.Overall.IsFailure, Is.True);
    }

    [Test]
    public void Validate_WhenBypassingTrust_StillSucceedsAndIncludesBypassMetadata()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var message = CreateSignedEmbeddedMessage(signingKey);

        var resolver = new FixedSigningKeyResolver(new EcdsaSigningKey(signingKey));

        var trustPlan = new CompiledTrustPlan(TrustRules.DenyAll("would-fail"), Array.Empty<IMultiTrustFactProducer>());

        var validator = new CoseSign1Validator(
            signingKeyResolvers: new[] { resolver },
            postSignatureValidators: null,
            toBeSignedAttestors: null,
            trustPlan: trustPlan,
            options: null,
            trustEvaluationOptions: new TrustEvaluationOptions { BypassTrust = true });

        var result = validator.Validate(message);

        Assert.That(result.Overall.IsValid, Is.True);
        Assert.That(result.Trust.Metadata.ContainsKey(nameof(TrustEvaluationOptions.BypassTrust)), Is.True);
        Assert.That(result.Trust.Metadata[nameof(TrustEvaluationOptions.BypassTrust)], Is.EqualTo(true));
    }

    [Test]
    public void Validate_WhenSkipPostSignatureValidationIsTrue_DoesNotInvokePostValidators()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var message = CreateSignedEmbeddedMessage(signingKey);

        var resolver = new FixedSigningKeyResolver(new EcdsaSigningKey(signingKey));
        var postValidator = new CountingFailingPostSignatureValidator();

        var validator = new CoseSign1Validator(
            signingKeyResolvers: new[] { resolver },
            postSignatureValidators: new[] { postValidator },
            toBeSignedAttestors: null,
            trustPlan: CreateAllowAllTrustPlan(),
            options: new CoseSign1ValidationOptions { SkipPostSignatureValidation = true });

        var result = validator.Validate(message);

        Assert.That(result.Overall.IsValid, Is.True);
        Assert.That(result.PostSignaturePolicy.IsValid, Is.True);
        Assert.That(postValidator.ValidateCallCount, Is.EqualTo(0));
        Assert.That(postValidator.ValidateAsyncCallCount, Is.EqualTo(0));
    }

    [Test]
    public async Task ValidateAsync_WhenCancellationIsRequested_ThrowsOperationCanceledException()
    {
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var message = CreateSignedEmbeddedMessage(signingKey);

        var resolver = new FixedSigningKeyResolver(new EcdsaSigningKey(signingKey));

        var validator = new CoseSign1Validator(
            signingKeyResolvers: new[] { resolver },
            postSignatureValidators: null,
            toBeSignedAttestors: null,
            trustPlan: CreateAllowAllTrustPlan());

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        _ = await Task.Run(
            () => Assert.ThrowsAsync<OperationCanceledException>(() => validator.ValidateAsync(message, cts.Token)));
    }
}
