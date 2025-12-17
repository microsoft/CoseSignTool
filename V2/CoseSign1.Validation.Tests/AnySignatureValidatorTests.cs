// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Validation;
using NUnit.Framework;

namespace CoseSign1.Validation.Tests;

public class AnySignatureValidatorTests
{
    private sealed class AlwaysNotApplicableValidator : IValidator<CoseSign1Message>, IConditionalValidator<CoseSign1Message>
    {
        public bool IsApplicable(CoseSign1Message input) => false;
        public ValidationResult Validate(CoseSign1Message input) => ValidationResult.Failure("Never", "should not run", "NEVER");
        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
            => Task.FromResult(Validate(input));
    }

    private sealed class AlwaysFailValidator : IValidator<CoseSign1Message>
    {
        public ValidationResult Validate(CoseSign1Message input)
            => ValidationResult.Failure("Fail", "nope", "FAIL");

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
            => Task.FromResult(Validate(input));
    }

    private sealed class AlwaysPassValidator : IValidator<CoseSign1Message>
    {
        public ValidationResult Validate(CoseSign1Message input)
            => ValidationResult.Success("Pass", new Dictionary<string, object> { ["ok"] = true });

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
            => Task.FromResult(Validate(input));
    }

    private sealed class FailWithNoFailuresValidator : IValidator<CoseSign1Message>
    {
        public ValidationResult Validate(CoseSign1Message input)
            => ValidationResult.Failure("FailNoFailures");

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
            => Task.FromResult(Validate(input));
    }

    [Test]
    public void Validate_WhenNoApplicableValidators_FailsWithExpectedCode()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA256);
        var msgBytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(msgBytes);

        var validator = new AnySignatureValidator(new IValidator<CoseSign1Message>[]
        {
            new AlwaysNotApplicableValidator()
        });

        var result = validator.Validate(msg);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "NO_APPLICABLE_SIGNATURE_VALIDATOR"), Is.True);
    }

    [Test]
    public void Validate_WhenInputIsNull_FailsWithExpectedCode()
    {
        var validator = new AnySignatureValidator(new IValidator<CoseSign1Message>[]
        {
            new AlwaysPassValidator()
        });

        var result = validator.Validate(null!);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "NULL_INPUT"), Is.True);
    }

    [Test]
    public void Validate_WhenOneValidatorPasses_ReturnsSuccess()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA256);
        var msgBytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(msgBytes);

        var validator = new AnySignatureValidator(new IValidator<CoseSign1Message>[]
        {
            new AlwaysFailValidator(),
            new AlwaysPassValidator(),
            new AlwaysFailValidator()
        });

        var result = validator.Validate(msg);
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata.ContainsKey("SelectedValidator"), Is.True);
    }

    [Test]
    public async Task ValidateAsync_WhenNoApplicableValidators_FailsWithExpectedCode()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA256);
        var msgBytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(msgBytes);

        var validator = new AnySignatureValidator(new IValidator<CoseSign1Message>[]
        {
            new AlwaysNotApplicableValidator()
        });

        var result = await validator.ValidateAsync(msg);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "NO_APPLICABLE_SIGNATURE_VALIDATOR"), Is.True);
    }

    [Test]
    public async Task ValidateAsync_WhenInputIsNull_FailsWithExpectedCode()
    {
        var validator = new AnySignatureValidator(new IValidator<CoseSign1Message>[]
        {
            new AlwaysPassValidator()
        });

        var result = await validator.ValidateAsync(null!);
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

        var validator = new AnySignatureValidator(new IValidator<CoseSign1Message>[]
        {
            new AlwaysFailValidator(),
            new AlwaysPassValidator()
        });

        var result = await validator.ValidateAsync(msg);
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

        var validator = new AnySignatureValidator(new IValidator<CoseSign1Message>[]
        {
            new AlwaysFailValidator(),
            new AlwaysFailValidator()
        });

        var result = await validator.ValidateAsync(msg);
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

        var validator = new AnySignatureValidator(new IValidator<CoseSign1Message>[]
        {
            new AlwaysFailValidator(),
            new AlwaysFailValidator()
        });

        var result = validator.Validate(msg);
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

        var validator = new AnySignatureValidator(new IValidator<CoseSign1Message>[]
        {
            new FailWithNoFailuresValidator()
        });

        var result = validator.Validate(msg);
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Is.Not.Empty);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "NO_APPLICABLE_SIGNATURE_VALIDATOR"), Is.True);
    }
}
