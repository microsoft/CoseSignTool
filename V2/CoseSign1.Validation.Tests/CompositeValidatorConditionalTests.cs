// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using CoseSign1.Validation.Validators;

namespace CoseSign1.Validation.Tests;

public class CompositeValidatorConditionalTests
{
    private sealed class ConditionalNoOpValidator : IConditionalValidator
    {
        public int Calls;

        public IReadOnlyCollection<ValidationStage> Stages { get; } = new[] { ValidationStage.Signature };

        public bool IsApplicable(CoseSign1Message input, ValidationStage stage) => false;

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
        {
            Calls++;
            return ValidationResult.Failure("ShouldNotRun", stage, "ran", "RAN");
        }

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
        {
            Calls++;
            return Task.FromResult(ValidationResult.Failure("ShouldNotRun", stage, "ran", "RAN"));
        }
    }

    [Test]
    public void Validate_SkipsNotApplicableValidators()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signer = new CoseSigner(ecdsa, HashAlgorithmName.SHA256);
        var msgBytes = CoseSign1Message.SignEmbedded(new byte[] { 1, 2, 3 }, signer);
        var msg = CoseSign1Message.DecodeSign1(msgBytes);

        var conditional = new ConditionalNoOpValidator();
        var composite = new CompositeValidator(new IValidator[]
        {
            conditional
        });

        var result = composite.Validate(msg, ValidationStage.Signature);
        Assert.That(conditional.Calls, Is.EqualTo(0));
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Stage, Is.EqualTo(ValidationStage.Signature));
    }
}
