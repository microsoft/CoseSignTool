// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Direct;
using CoseSign1.Tests.Common;
using CoseSign1.Validation.Builders;
using CoseSign1.Validation.Extensions;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;

[TestFixture]
public sealed class VerificationBuilderTests
{
    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    private static CoseSign1Message CreateValidMessage()
    {
        using var cert = TestCertificateUtils.CreateCertificate("VerificationBuilderTest");
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(cert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        return CoseSign1Message.DecodeSign1(messageBytes);
    }

    [Test]
    public void Cose_Sign1Message_ReturnsBuilder()
    {
        var builder = Cose.Sign1Message();
        Assert.That(builder, Is.Not.Null);
    }

    [Test]
    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    public void VerificationBuilder_DefaultTrustIsDenyAll()
    {
        var validMessage = CreateValidMessage();
        var signatureValidator = new TrackingSignatureValidator();

        var validator = Cose.Sign1Message()
            .AddValidator(signatureValidator)
            .Build();

        var result = validator.Validate(validMessage);

        Assert.That(result.Trust.IsValid, Is.False);
        Assert.That(result.Trust.Failures, Is.Not.Empty);
        Assert.That(result.Trust.Failures[0].ErrorCode, Is.EqualTo("TRUST_POLICY_NOT_SATISFIED"));
        Assert.That(signatureValidator.Calls, Is.EqualTo(0), "Signature validation should not run until trust is established");
    }

    [Test]
    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    public void VerificationBuilder_AllowAllTrust_AllowsTrustStageToPass()
    {
        var validMessage = CreateValidMessage();
        var validator = Cose.Sign1Message()
            .AllowAllTrust("test")
            .AddValidator(new AlwaysPassSignatureValidator())
            .Build();

        var result = validator.Validate(validMessage);

        Assert.That(result.Trust.IsValid, Is.True);
        Assert.That(result.Signature.IsValid, Is.True);
        Assert.That(result.Overall.IsValid, Is.True);
    }

    [Test]
    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    public void VerificationBuilder_TrustValidatorWithoutPolicy_AllowsTrustWhenValidatorPasses()
    {
        var validMessage = CreateValidMessage();
        var validator = Cose.Sign1Message()
            .AddValidator(new TrustValidatorWithoutPolicy())
            .AddValidator(new AlwaysPassSignatureValidator())
            .Build();

        var result = validator.Validate(validMessage);

        Assert.That(result.Trust.IsValid, Is.True);
        Assert.That(result.Signature.IsValid, Is.True);
        Assert.That(result.Overall.IsValid, Is.True);
    }

    [Test]
    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    public void VerificationBuilder_DefaultTrustPolicyFromValidator_IsRequiredByDefault()
    {
        var validMessage = CreateValidMessage();
        var validator = Cose.Sign1Message()
            .AddValidator(new DefaultPolicyTrustValidator(claimSatisfied: true))
            .AddValidator(new AlwaysPassSignatureValidator())
            .Build();

        var result = validator.Validate(validMessage);

        Assert.That(result.Trust.IsValid, Is.True);
        Assert.That(result.Overall.IsValid, Is.True);
    }

    [Test]
    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    public void VerificationBuilder_OverrideDefaultTrustPolicy_Works()
    {
        var validMessage = CreateValidMessage();
        var validator = Cose.Sign1Message()
            .AddTrustValidator(new DefaultPolicyTrustValidator(claimSatisfied: false), TrustPolicy.AllowAll("override"))
            .AddValidator(new AlwaysPassSignatureValidator())
            .Build();

        var result = validator.Validate(validMessage);

        Assert.That(result.Trust.IsValid, Is.True);
        Assert.That(result.Overall.IsValid, Is.True);
    }

    private sealed class AlwaysPassSignatureValidator : IValidator
    {
        public IReadOnlyCollection<ValidationStage> Stages { get; } = new[] { ValidationStage.Signature };

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
            => ValidationResult.Success(nameof(AlwaysPassSignatureValidator), stage);

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
            => Task.FromResult(Validate(input, stage));
    }

    private sealed class TrackingSignatureValidator : IValidator
    {
        public int Calls { get; private set; }

        public IReadOnlyCollection<ValidationStage> Stages { get; } = new[] { ValidationStage.Signature };

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
        {
            Calls++;
            return ValidationResult.Success(nameof(TrackingSignatureValidator), stage);
        }

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
            => Task.FromResult(Validate(input, stage));
    }

    private sealed class TrustValidatorWithoutPolicy : IValidator
    {
        public IReadOnlyCollection<ValidationStage> Stages { get; } = new[] { ValidationStage.KeyMaterialTrust };

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
            => ValidationResult.Success(nameof(TrustValidatorWithoutPolicy), stage);

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
            => Task.FromResult(Validate(input, stage));
    }

    private sealed class DefaultPolicyTrustValidator : IValidator, IProvidesDefaultTrustPolicy
    {
        private const string ClaimId = "test.claim";
        private readonly bool ClaimSatisfied;

        public DefaultPolicyTrustValidator(bool claimSatisfied)
        {
            ClaimSatisfied = claimSatisfied;
        }

        public IReadOnlyCollection<ValidationStage> Stages { get; } = new[] { ValidationStage.KeyMaterialTrust };

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
            => ValidationResult.Success(nameof(DefaultPolicyTrustValidator), stage, new Dictionary<string, object>
            {
                [TrustAssertionMetadata.AssertionsKey] = new[]
                {
                    new TrustAssertion(ClaimId, ClaimSatisfied)
                }
            });

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
            => Task.FromResult(Validate(input, stage));

        public TrustPolicy GetDefaultTrustPolicy(ValidationBuilderContext context)
            => TrustPolicy.Claim(ClaimId);
    }
}
