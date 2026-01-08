// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using CoseSign1.Validation.Validators;

namespace CoseSign1.Validation.Tests;

public class AnySignatureValidatorTests
{
    private sealed class ApplicableButReturnsNotApplicableValidator : IValidator
    {
        public IReadOnlyCollection<ValidationStage> Stages { get; } = new[] { ValidationStage.Signature };

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
            => ValidationResult.NotApplicable("NA", stage, "deliberate");

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
            => Task.FromResult(Validate(input, stage));
    }

    private sealed class AlwaysNotApplicableValidator : IConditionalValidator
    {
        public IReadOnlyCollection<ValidationStage> Stages { get; } = new[] { ValidationStage.Signature };

        public bool IsApplicable(CoseSign1Message input, ValidationStage stage) => false;

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
            => ValidationResult.Failure("Never", stage, "should not run", "NEVER");

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
            => Task.FromResult(Validate(input, stage));
    }

    private sealed class AlwaysFailValidator : IValidator
    {
        public IReadOnlyCollection<ValidationStage> Stages { get; } = new[] { ValidationStage.Signature };

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
            => ValidationResult.Failure("Fail", stage, "nope", "FAIL");

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
            => Task.FromResult(Validate(input, stage));
    }

    private sealed class AlwaysPassValidator : IValidator
    {
        public IReadOnlyCollection<ValidationStage> Stages { get; } = new[] { ValidationStage.Signature };

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
            => ValidationResult.Success("Pass", stage, new Dictionary<string, object> { ["ok"] = true });

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
            => Task.FromResult(Validate(input, stage));
    }

    private sealed class FailWithNoFailuresValidator : IValidator
    {
        public IReadOnlyCollection<ValidationStage> Stages { get; } = new[] { ValidationStage.Signature };

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
            => ValidationResult.Failure("FailNoFailures", stage);

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
            => Task.FromResult(Validate(input, stage));
    }

    [Test]
    public void Validate_WhenNoApplicableValidators_FailsWithExpectedCode()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA256);
        var msgBytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(msgBytes);

        var validator = new AnySignatureValidator(new IValidator[]
        {
            new AlwaysNotApplicableValidator()
        });

        var result = validator.Validate(msg, ValidationStage.Signature);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Stage, Is.EqualTo(ValidationStage.Signature));
        Assert.That(result.Failures.Any(f => f.ErrorCode == "NO_APPLICABLE_SIGNATURE_VALIDATOR"), Is.True);
    }

    [Test]
    public void Validate_WhenInputIsNull_FailsWithExpectedCode()
    {
        var validator = new AnySignatureValidator(new IValidator[]
        {
            new AlwaysPassValidator()
        });

        var result = validator.Validate(null!, ValidationStage.Signature);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Stage, Is.EqualTo(ValidationStage.Signature));
        Assert.That(result.Failures.Any(f => f.ErrorCode == "NULL_INPUT"), Is.True);
    }

    [Test]
    public void Validate_WhenOneValidatorPasses_ReturnsSuccess()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA256);
        var msgBytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(msgBytes);

        var validator = new AnySignatureValidator(new IValidator[]
        {
            new AlwaysFailValidator(),
            new AlwaysPassValidator(),
            new AlwaysFailValidator()
        });

        var result = validator.Validate(msg, ValidationStage.Signature);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Stage, Is.EqualTo(ValidationStage.Signature));
        Assert.That(result.Metadata.ContainsKey("SelectedValidator"), Is.True);
    }

    [Test]
    public void Validate_WhenStageIsNotSignature_ReturnsNotApplicable()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA256);
        var msgBytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(msgBytes);

        var validator = new AnySignatureValidator(new IValidator[]
        {
            new AlwaysPassValidator()
        });

        var result = validator.Validate(msg, ValidationStage.PostSignature);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.IsNotApplicable, Is.True);
        Assert.That(result.IsFailure, Is.False);
        Assert.That(result.Stage, Is.EqualTo(ValidationStage.PostSignature));
    }

    [Test]
    public void Validate_WhenApplicableValidatorReturnsNotApplicable_FailsWithExpectedCode()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA256);
        var msgBytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(msgBytes);

        var validator = new AnySignatureValidator(new IValidator[]
        {
            new ApplicableButReturnsNotApplicableValidator()
        });

        var result = validator.Validate(msg, ValidationStage.Signature);
        Assert.That(result.IsFailure, Is.True);
        Assert.That(result.Stage, Is.EqualTo(ValidationStage.Signature));
        Assert.That(result.Failures.Any(f => f.ErrorCode == "NO_APPLICABLE_SIGNATURE_VALIDATOR"), Is.True);
    }

    [Test]
    public async Task ValidateAsync_WhenNoApplicableValidators_FailsWithExpectedCode()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA256);
        var msgBytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(msgBytes);

        var validator = new AnySignatureValidator(new IValidator[]
        {
            new AlwaysNotApplicableValidator()
        });

        var result = await validator.ValidateAsync(msg, ValidationStage.Signature);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Stage, Is.EqualTo(ValidationStage.Signature));
        Assert.That(result.Failures.Any(f => f.ErrorCode == "NO_APPLICABLE_SIGNATURE_VALIDATOR"), Is.True);
    }

    [Test]
    public async Task ValidateAsync_WhenStageIsNotSignature_ReturnsNotApplicable()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA256);
        var msgBytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(msgBytes);

        var validator = new AnySignatureValidator(new IValidator[]
        {
            new AlwaysPassValidator()
        });

        var result = await validator.ValidateAsync(msg, ValidationStage.PostSignature);
        Assert.That(result.IsNotApplicable, Is.True);
        Assert.That(result.Stage, Is.EqualTo(ValidationStage.PostSignature));
    }

    [Test]
    public async Task ValidateAsync_WhenValidatorFailsWithNoFailures_ReturnsFailureWithNoFailuresList()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA256);
        var msgBytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(msgBytes);

        var validator = new AnySignatureValidator(new IValidator[]
        {
            new FailWithNoFailuresValidator()
        });

        var result = await validator.ValidateAsync(msg, ValidationStage.Signature);
        Assert.That(result.IsFailure, Is.True);
        Assert.That(result.Stage, Is.EqualTo(ValidationStage.Signature));
        Assert.That(result.Failures, Is.Empty);
    }

    [Test]
    public async Task ValidateAsync_WhenInputIsNull_FailsWithExpectedCode()
    {
        var validator = new AnySignatureValidator(new IValidator[]
        {
            new AlwaysPassValidator()
        });

        var result = await validator.ValidateAsync(null!, ValidationStage.Signature);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "NULL_INPUT"), Is.True);
    }

    [Test]
    public async Task ValidateAsync_WhenOneValidatorPasses_ReturnsSuccess()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA256);
        var msgBytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(msgBytes);

        var validator = new AnySignatureValidator(new IValidator[]
        {
            new AlwaysFailValidator(),
            new AlwaysPassValidator()
        });

        var result = await validator.ValidateAsync(msg, ValidationStage.Signature);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata.ContainsKey("SelectedValidator"), Is.True);
    }

    [Test]
    public async Task ValidateAsync_WhenAllApplicableFail_ReturnsFailure()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA256);
        var msgBytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(msgBytes);

        var validator = new AnySignatureValidator(new IValidator[]
        {
            new AlwaysFailValidator(),
            new AlwaysFailValidator()
        });

        var result = await validator.ValidateAsync(msg, ValidationStage.Signature);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Is.Not.Empty);
    }

    [Test]
    public void Validate_WhenAllApplicableFail_ReturnsFailure()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA256);
        var msgBytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(msgBytes);

        var validator = new AnySignatureValidator(new IValidator[]
        {
            new AlwaysFailValidator(),
            new AlwaysFailValidator()
        });

        var result = validator.Validate(msg, ValidationStage.Signature);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Is.Not.Empty);
    }

    [Test]
    public void Validate_WhenFailureListIsEmpty_AddsDefaultNoApplicableFailure()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA256);
        var msgBytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(msgBytes);

        var validator = new AnySignatureValidator(new IValidator[]
        {
            new FailWithNoFailuresValidator()
        });

        var result = validator.Validate(msg, ValidationStage.Signature);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Is.Not.Empty);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "NO_APPLICABLE_SIGNATURE_VALIDATOR"), Is.True);
    }
}
