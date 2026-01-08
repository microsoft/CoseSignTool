// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Validation.Builders;
using CoseSign1.Validation.Extensions;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;

namespace CoseSign1.Validation.Tests;

[TestFixture]
public sealed class VerificationBuilderExtensionsCoverageTests
{
    [Test]
    public void AddTrustValidator_NullBuilder_Throws()
    {
        Assert.That(
            () => CoseSign1.Validation.Extensions.ValidationBuilderExtensions.AddTrustValidator(null!, new TrustStageValidator(), TrustPolicy.AllowAll("x")),
            Throws.ArgumentNullException);
    }

    [Test]
    public void AddTrustValidator_NullValidator_Throws()
    {
        ICoseSign1ValidationBuilder builder = new RecordingBuilder();

        Assert.That(
            () => builder.AddTrustValidator(null!, TrustPolicy.AllowAll("x")),
            Throws.ArgumentNullException);
    }

    [Test]
    public void AddTrustValidator_NullPolicy_Throws()
    {
        ICoseSign1ValidationBuilder builder = new RecordingBuilder();

        Assert.That(
            () => builder.AddTrustValidator(new TrustStageValidator(), null!),
            Throws.ArgumentNullException);
    }

    [Test]
    public void AddTrustValidator_WithRequiredPolicy_StoresOverride_AndAddsValidator()
    {
        var builder = new RecordingBuilder();
        var validator = new TrustStageValidator();

        builder.AddTrustValidator(validator, TrustPolicy.AllowAll("override"));

        Assert.That(builder.Calls, Does.Contain("AddValidator"));
        Assert.That(builder.Context.Properties.ContainsKey("CoseSign1.Validation.TrustPolicyOverrides"), Is.True);

        var overrides = (System.Collections.Generic.List<TrustPolicyOverride>)builder.Context.Properties["CoseSign1.Validation.TrustPolicyOverrides"]!;
        Assert.That(overrides, Has.Count.EqualTo(1));
        Assert.That(overrides[0].Validator, Is.SameAs(validator));
    }

    private sealed class RecordingBuilder : ICoseSign1ValidationBuilder
    {
        public ValidationBuilderContext Context { get; } = new();

        public System.Collections.Generic.List<string> Calls { get; } = new();

        public ICoseSign1ValidationBuilder AddValidator(IValidator validator)
        {
            Calls.Add("AddValidator");
            return this;
        }

        public ICoseSign1ValidationBuilder RequireTrust(TrustPolicy policy)
        {
            Calls.Add("RequireTrust");
            return this;
        }

        public ICoseSign1ValidationBuilder AllowAllTrust(string? reason = null)
        {
            Calls.Add("AllowAllTrust");
            return this;
        }

        public ICoseSign1ValidationBuilder DenyAllTrust(string? reason = null)
        {
            Calls.Add("DenyAllTrust");
            return this;
        }

        public ICoseSign1Validator Build() => new NoopValidator();

        private sealed class NoopValidator : ICoseSign1Validator
        {
            public TrustPolicy TrustPolicy { get; } = TrustPolicy.AllowAll("noop");

            public IReadOnlyList<IValidator> Validators { get; } = Array.Empty<IValidator>();

            public CoseSign1ValidationResult Validate(CoseSign1Message message)
                => throw new NotSupportedException("Not used in this test.");
        }
    }

    private sealed class TrustStageValidator : IValidator
    {
        public IReadOnlyCollection<ValidationStage> Stages { get; } = new[] { ValidationStage.KeyMaterialTrust };

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
            => ValidationResult.Success(nameof(TrustStageValidator), stage);

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
            => Task.FromResult(Validate(input, stage));
    }
}
