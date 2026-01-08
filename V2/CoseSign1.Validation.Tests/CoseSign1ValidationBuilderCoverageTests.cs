// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Validation.Builders;
using CoseSign1.Validation.Extensions;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;

namespace CoseSign1.Validation.Tests;

[TestFixture]
public sealed class CoseSign1ValidationBuilderCoverageTests
{
    private const string TrustPolicyOverridesKey = "CoseSign1.Validation.TrustPolicyOverrides";

    [Test]
    public void Build_WithNoSignatureValidators_Throws()
    {
        var builder = new CoseSign1ValidationBuilder();
        Assert.That(() => builder.Build(), Throws.InvalidOperationException);
    }

    [Test]
    public void Build_WithNoTrustValidatorsAndNoPolicies_DefaultsToDenyAll()
    {
        var builder = new CoseSign1ValidationBuilder();
        builder.AddValidator(new NoOpValidator(ValidationStage.Signature));

        var validator = builder.Build();

        Assert.That(validator.TrustPolicy.IsSatisfied(new Dictionary<string, bool>()), Is.False);
    }

    [Test]
    public void Build_WithTrustValidatorsButNoPolicies_DefaultsToAllowAll()
    {
        var builder = new CoseSign1ValidationBuilder();
        builder.AddValidator(new NoOpValidator(ValidationStage.Signature));
        builder.AddValidator(new NoOpValidator(ValidationStage.KeyMaterialTrust));

        var validator = builder.Build();

        Assert.That(validator.TrustPolicy.IsSatisfied(new Dictionary<string, bool>()), Is.True);
    }

    [Test]
    public void AllowAllTrust_OverridesAndClearsRequiredPolicies()
    {
        var builder = new CoseSign1ValidationBuilder();
        builder.AddValidator(new NoOpValidator(ValidationStage.Signature));
        builder.RequireTrust(TrustPolicy.Claim("x"));
        builder.AllowAllTrust("ok");

        var validator = builder.Build();
        Assert.That(validator.TrustPolicy.IsSatisfied(new Dictionary<string, bool>()), Is.True);

        var reasons = new List<string>();
        validator.TrustPolicy.Explain(new Dictionary<string, bool>(), reasons);
        Assert.That(reasons, Does.Contain("ok"));
    }

    [Test]
    public void DenyAllTrust_OverridesAndClearsRequiredPolicies()
    {
        var builder = new CoseSign1ValidationBuilder();
        builder.AddValidator(new NoOpValidator(ValidationStage.Signature));
        builder.RequireTrust(TrustPolicy.Claim("x"));
        builder.DenyAllTrust("no");

        var validator = builder.Build();
        Assert.That(validator.TrustPolicy.IsSatisfied(new Dictionary<string, bool>()), Is.False);

        var reasons = new List<string>();
        validator.TrustPolicy.Explain(new Dictionary<string, bool>(), reasons);
        Assert.That(reasons, Does.Contain("no"));
    }

    [Test]
    public void OverridePolicy_FromEnumerable_IsUsedInsteadOfDefaultPolicy()
    {
        var builder = new CoseSign1ValidationBuilder();
        builder.AddValidator(new NoOpValidator(ValidationStage.Signature));

        var trustValidator = new DefaultPolicyTrustValidator();
        builder.AddValidator(trustValidator);

        builder.Context.Properties[TrustPolicyOverridesKey] = Enumerable
            .Repeat(new TrustPolicyOverride(trustValidator, TrustPolicy.Claim("override")), 1)
            .Select(x => x);

        var validator = builder.Build();

        Assert.That(validator.TrustPolicy.IsSatisfied(new Dictionary<string, bool>
        {
            ["default"] = false,
            ["override"] = true
        }), Is.True);
    }

    [Test]
    public void OverridePolicy_FromIReadOnlyList_IsUsedInsteadOfDefaultPolicy()
    {
        var builder = new CoseSign1ValidationBuilder();
        builder.AddValidator(new NoOpValidator(ValidationStage.Signature));

        var trustValidator = new DefaultPolicyTrustValidator();
        builder.AddValidator(trustValidator);

        builder.Context.Properties[TrustPolicyOverridesKey] = new List<TrustPolicyOverride>
        {
            new(trustValidator, TrustPolicy.Claim("override"))
        };

        var validator = builder.Build();

        Assert.That(validator.TrustPolicy.IsSatisfied(new Dictionary<string, bool>
        {
            ["default"] = false,
            ["override"] = true
        }), Is.True);
    }

    [Test]
    public void Build_WhenOverridesValueIsUnknownType_IgnoresIt()
    {
        var builder = new CoseSign1ValidationBuilder();
        builder.AddValidator(new NoOpValidator(ValidationStage.Signature));
        builder.Context.Properties[TrustPolicyOverridesKey] = 123;
        builder.AddValidator(new DefaultPolicyTrustValidator());

        var validator = builder.Build();

        Assert.That(validator.TrustPolicy.IsSatisfied(new Dictionary<string, bool> { ["default"] = true }), Is.True);
    }

    [Test]
    public void AddTrustValidatorExtension_CreatesOverrideList_EvenIfExistingIsNotList()
    {
        ICoseSign1ValidationBuilder builder = new CoseSign1ValidationBuilder();
        builder.AddValidator(new NoOpValidator(ValidationStage.Signature));

        builder.Context.Properties[TrustPolicyOverridesKey] = Array.Empty<TrustPolicyOverride>();

        var trustValidator = new DefaultPolicyTrustValidator();
        builder.AddTrustValidator(trustValidator, TrustPolicy.Claim("override"));

        var validator = ((CoseSign1ValidationBuilder)builder).Build();
        Assert.That(validator.TrustPolicy.IsSatisfied(new Dictionary<string, bool> { ["override"] = true }), Is.True);
    }

    [Test]
    public void AddTrustValidatorExtension_WhenBuilderNull_Throws()
    {
        var validator = new NoOpValidator(ValidationStage.KeyMaterialTrust);
        Assert.That(
            () => ValidationBuilderExtensions.AddTrustValidator(null!, validator, TrustPolicy.Claim("x")),
            Throws.ArgumentNullException);
    }

    [Test]
    public void AddTrustValidatorExtension_WhenValidatorNull_Throws()
    {
        ICoseSign1ValidationBuilder builder = new CoseSign1ValidationBuilder();
        Assert.That(() => builder.AddTrustValidator(null!, TrustPolicy.Claim("x")), Throws.ArgumentNullException);
    }

    [Test]
    public void AddTrustValidatorExtension_WhenPolicyNull_Throws()
    {
        ICoseSign1ValidationBuilder builder = new CoseSign1ValidationBuilder();
        builder.AddValidator(new NoOpValidator(ValidationStage.Signature));

        Assert.That(
            () => builder.AddTrustValidator(new NoOpValidator(ValidationStage.KeyMaterialTrust), null!),
            Throws.ArgumentNullException);
    }

    [Test]
    public void AddValidator_Null_Throws()
    {
        var builder = new CoseSign1ValidationBuilder();
        Assert.That(() => builder.AddValidator(null!), Throws.ArgumentNullException);
    }

    [Test]
    public void AddValidator_NullStages_Throws()
    {
        var builder = new CoseSign1ValidationBuilder();
        Assert.That(() => builder.AddValidator(new NullStagesValidator()), Throws.InvalidOperationException);
    }

    [Test]
    public void AddValidator_EmptyStages_Throws()
    {
        var builder = new CoseSign1ValidationBuilder();
        Assert.That(() => builder.AddValidator(new EmptyStagesValidator()), Throws.InvalidOperationException);
    }

    [Test]
    public void AddValidator_UnsupportedStage_Throws()
    {
        var builder = new CoseSign1ValidationBuilder();
        Assert.That(() => builder.AddValidator(new SingleStageValidator((ValidationStage)999)), Throws.InvalidOperationException);
    }

    [Test]
    public void RequireTrust_Null_Throws()
    {
        var builder = new CoseSign1ValidationBuilder();
        Assert.That(() => builder.RequireTrust(null!), Throws.ArgumentNullException);
    }

    [Test]
    public void Build_WithSingleRequiredTrustPolicy_UsesThatPolicy()
    {
        var builder = new CoseSign1ValidationBuilder();
        builder.AddValidator(new NoOpValidator(ValidationStage.Signature));
        builder.RequireTrust(TrustPolicy.Claim("required"));

        var validator = builder.Build();

        Assert.That(validator.TrustPolicy.IsSatisfied(new Dictionary<string, bool> { ["required"] = true }), Is.True);
        Assert.That(validator.TrustPolicy.IsSatisfied(new Dictionary<string, bool> { ["required"] = false }), Is.False);
    }

    [Test]
    public void Build_WithMultipleRequiredTrustPolicies_UsesAllOf()
    {
        var builder = new CoseSign1ValidationBuilder();
        builder.AddValidator(new NoOpValidator(ValidationStage.Signature));
        builder.RequireTrust(TrustPolicy.Claim("a"));
        builder.RequireTrust(TrustPolicy.Claim("b"));

        var validator = builder.Build();

        Assert.That(validator.TrustPolicy.IsSatisfied(new Dictionary<string, bool> { ["a"] = true, ["b"] = true }), Is.True);
        Assert.That(validator.TrustPolicy.IsSatisfied(new Dictionary<string, bool> { ["a"] = true, ["b"] = false }), Is.False);
    }

    [Test]
    public void Build_UsesDefaultTrustPolicy_WhenValidatorProvidesDefault_AndNoOverride()
    {
        var builder = new CoseSign1ValidationBuilder();
        builder.AddValidator(new NoOpValidator(ValidationStage.Signature));
        builder.AddValidator(new DefaultPolicyTrustValidator());

        var validator = builder.Build();

        Assert.That(validator.TrustPolicy.IsSatisfied(new Dictionary<string, bool> { ["default"] = true }), Is.True);
        Assert.That(validator.TrustPolicy.IsSatisfied(new Dictionary<string, bool> { ["default"] = false }), Is.False);
    }

    private sealed class NoOpValidator : IValidator
    {
        private readonly ValidationStage Stage;

        public NoOpValidator(ValidationStage stage)
        {
            Stage = stage;
        }

        public IReadOnlyCollection<ValidationStage> Stages => new[] { Stage };

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
            => ValidationResult.Success(nameof(NoOpValidator), stage);

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
            => Task.FromResult(Validate(input, stage));
    }

    private sealed class DefaultPolicyTrustValidator : IValidator, IProvidesDefaultTrustPolicy
    {
        public IReadOnlyCollection<ValidationStage> Stages => new[] { ValidationStage.KeyMaterialTrust };

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
            => ValidationResult.Success(nameof(DefaultPolicyTrustValidator), stage);

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
            => Task.FromResult(Validate(input, stage));

        public TrustPolicy GetDefaultTrustPolicy(ValidationBuilderContext context)
            => TrustPolicy.Claim("default");
    }

    private sealed class NullStagesValidator : IValidator
    {
        public IReadOnlyCollection<ValidationStage> Stages => null!;

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
            => ValidationResult.Success(nameof(NullStagesValidator), stage);

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
            => Task.FromResult(Validate(input, stage));
    }

    private sealed class EmptyStagesValidator : IValidator
    {
        public IReadOnlyCollection<ValidationStage> Stages => Array.Empty<ValidationStage>();

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
            => ValidationResult.Success(nameof(EmptyStagesValidator), stage);

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
            => Task.FromResult(Validate(input, stage));
    }

    private sealed class SingleStageValidator : IValidator
    {
        private readonly ValidationStage Stage;

        public SingleStageValidator(ValidationStage stage)
        {
            Stage = stage;
        }

        public IReadOnlyCollection<ValidationStage> Stages => new[] { Stage };

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
            => ValidationResult.Success(nameof(SingleStageValidator), stage);

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
            => Task.FromResult(Validate(input, stage));
    }
}
