// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using CoseSign1.Validation.Validators;

[TestFixture]
public sealed class CompositeValidatorNotApplicableTests
{
    [Test]
    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    public void Validate_WhenValidatorReturnsNotApplicable_IgnoresItAndSucceeds()
    {
        var msg = CreateMessage();

        var notApplicable = new NotApplicableValidator();
        var wrongStage = new WrongStageValidator();

        var composite = new CompositeValidator(new IValidator[] { notApplicable, wrongStage });

        var result = composite.Validate(msg, ValidationStage.Signature);

        Assert.That(wrongStage.Calls, Is.EqualTo(0));
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Stage, Is.EqualTo(ValidationStage.Signature));
    }

    [Test]
    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    public async Task ValidateAsync_WhenValidatorReturnsNotApplicable_IgnoresItAndSucceeds()
    {
        var msg = CreateMessage();

        var notApplicable = new NotApplicableValidator();
        var wrongStage = new WrongStageValidator();

        var composite = new CompositeValidator(new IValidator[] { notApplicable, wrongStage }, runInParallel: false);

        var result = await composite.ValidateAsync(msg, ValidationStage.Signature, CancellationToken.None);

        Assert.That(wrongStage.Calls, Is.EqualTo(0));
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Stage, Is.EqualTo(ValidationStage.Signature));
    }

    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    private static CoseSign1Message CreateMessage()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA256);
        var msgBytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        return CoseSign1Message.DecodeSign1(msgBytes);
    }

    private sealed class NotApplicableValidator : IValidator
    {
        public IReadOnlyCollection<ValidationStage> Stages { get; } = new[] { ValidationStage.Signature };

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
            => ValidationResult.NotApplicable(nameof(NotApplicableValidator), stage);

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
            => Task.FromResult(Validate(input, stage));
    }

    private sealed class WrongStageValidator : IValidator
    {
        public int Calls { get; private set; }

        public IReadOnlyCollection<ValidationStage> Stages { get; } = new[] { ValidationStage.KeyMaterialTrust };

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
        {
            Calls++;
            return ValidationResult.Success(nameof(WrongStageValidator), stage);
        }

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
        {
            Calls++;
            return Task.FromResult(ValidationResult.Success(nameof(WrongStageValidator), stage));
        }
    }
}
