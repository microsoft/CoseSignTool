// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Validation;
using NUnit.Framework;

namespace CoseSign1.Validation.Tests;

public class CompositeValidatorConditionalTests
{
    private sealed class ConditionalNoOpValidator : IValidator<CoseSign1Message>, IConditionalValidator<CoseSign1Message>
    {
        public int Calls;

        public bool IsApplicable(CoseSign1Message input) => false;

        public ValidationResult Validate(CoseSign1Message input)
        {
            Calls++;
            return ValidationResult.Failure("ShouldNotRun", "ran", "RAN");
        }

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
        {
            Calls++;
            return Task.FromResult(ValidationResult.Failure("ShouldNotRun", "ran", "RAN"));
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
        var composite = new CompositeValidator(new IValidator<CoseSign1Message>[]
        {
            conditional
        });

        var result = composite.Validate(msg);
        Assert.That(conditional.Calls, Is.EqualTo(0));
        Assert.That(result.IsValid, Is.True);
    }
}
