// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Builders;

using CoseSign1.Validation.Interfaces;
using Microsoft.Extensions.Logging;

internal sealed class CoseSign1ValidationBuilder : ICoseSign1ValidationBuilder
{
    internal static class ClassStrings
    {
        public const string TrustPolicyOverridesKey = "CoseSign1.Validation.TrustPolicyOverrides";
        public const string ErrorValidationRequiresSignatureValidator = "Validation requires at least one signature validator.";
        public const string TrustPolicyReasonNoTrustPolicyProvided = "No trust policy was provided";
        public const string TrustPolicyReasonNoExplicitTrustPolicy = "No explicit trust policy; trust validators enforced by validator failures";
        public const string ErrorValidatorDoesNotSpecifyStagesFormat = "Validator '{0}' does not specify any stages.";
        public const string ErrorUnsupportedValidationStageFormat = "Unsupported validation stage: {0}";
    }

    private const string TrustPolicyOverridesKey = ClassStrings.TrustPolicyOverridesKey;

    private readonly List<IValidator> Validators = new();

    private TrustPolicy? ExplicitTrustPolicy;

    private readonly ValidationBuilderContext ContextField = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="CoseSign1ValidationBuilder"/> class.
    /// </summary>
    /// <param name="loggerFactory">Optional logger factory for creating loggers in validators.</param>
    public CoseSign1ValidationBuilder(ILoggerFactory? loggerFactory = null)
    {
        LoggerFactory = loggerFactory;
    }

    /// <inheritdoc/>
    public ILoggerFactory? LoggerFactory { get; }

    public ValidationBuilderContext Context => ContextField;

    /// <summary>
    /// Adds a validator to the builder.
    /// </summary>
    /// <param name="validator">The validator to add.</param>
    /// <returns>The same builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="validator"/> is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when <paramref name="validator"/> does not specify valid stages.</exception>
    public ICoseSign1ValidationBuilder AddValidator(IValidator validator)
    {
        if (validator == null)
        {
            throw new ArgumentNullException(nameof(validator));
        }

        if (validator.Stages == null || validator.Stages.Count == 0)
        {
            var name = validator.GetType().FullName ?? validator.GetType().Name;
            throw new InvalidOperationException(string.Format(ClassStrings.ErrorValidatorDoesNotSpecifyStagesFormat, name));
        }

        foreach (var stage in validator.Stages)
        {
            switch (stage)
            {
                case ValidationStage.KeyMaterialResolution:
                case ValidationStage.KeyMaterialTrust:
                case ValidationStage.Signature:
                case ValidationStage.PostSignature:
                    break;

                default:
                    throw new InvalidOperationException(string.Format(ClassStrings.ErrorUnsupportedValidationStageFormat, stage));
            }
        }

        Validators.Add(validator);
        return this;
    }

    /// <summary>
    /// Overrides the default trust policy with a custom policy.
    /// </summary>
    /// <param name="policy">The trust policy to use.</param>
    /// <returns>The same builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="policy"/> is null.</exception>
    public ICoseSign1ValidationBuilder OverrideDefaultTrustPolicy(TrustPolicy policy)
    {
        if (policy == null)
        {
            throw new ArgumentNullException(nameof(policy));
        }

        ExplicitTrustPolicy = policy;
        return this;
    }

    public ICoseSign1ValidationBuilder AllowAllTrust(string? reason = null)
    {
        ExplicitTrustPolicy = TrustPolicy.AllowAll(reason);
        return this;
    }

    public ICoseSign1ValidationBuilder DenyAllTrust(string? reason = null)
    {
        ExplicitTrustPolicy = TrustPolicy.DenyAll(reason);
        return this;
    }

    /// <summary>
    /// Builds a reusable validator instance.
    /// </summary>
    /// <returns>A validator instance.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the builder does not include a signature validator.</exception>
    public ICoseSign1Validator Build()
    {
        if (!Validators.Any(v => HasStage(v, ValidationStage.Signature)))
        {
            throw new InvalidOperationException(ClassStrings.ErrorValidationRequiresSignatureValidator);
        }

        var trustValidators = Validators.Where(v => HasStage(v, ValidationStage.KeyMaterialTrust)).ToArray();

        TrustPolicy trustPolicy;
        if (ExplicitTrustPolicy != null)
        {
            // Explicit trust policy overrides all defaults from validators
            trustPolicy = ExplicitTrustPolicy;
        }
        else
        {
            // Collect default trust policies from trust validators
            var policies = new List<TrustPolicy>();

            var overrides = GetTrustPolicyOverridesOrEmpty();
            foreach (var validator in trustValidators)
            {
                var overridePolicy = FindOverride(overrides, validator);
                if (overridePolicy != null)
                {
                    policies.Add(overridePolicy);
                    continue;
                }

                if (validator is IProvidesDefaultTrustPolicy provider)
                {
                    policies.Add(provider.GetDefaultTrustPolicy(ContextField));
                }
            }

            if (policies.Count == 0)
            {
                // Secure-by-default: if the caller didn't add any trust validators or requirements,
                // do not silently allow trust.
                //
                // However, if the caller *did* add trust validators, those validators may implement
                // trust checks by returning failures rather than emitting assertions. In that case,
                // we allow the trust policy to be permissive and rely on the validators.
                trustPolicy = trustValidators.Length == 0
                    ? TrustPolicy.DenyAll(ClassStrings.TrustPolicyReasonNoTrustPolicyProvided)
                    : TrustPolicy.AllowAll(ClassStrings.TrustPolicyReasonNoExplicitTrustPolicy);
            }
            else if (policies.Count == 1)
            {
                trustPolicy = policies[0];
            }
            else
            {
                trustPolicy = TrustPolicy.And(policies.ToArray());
            }
        }

        return new CoseSign1Validator(Validators.ToArray(), trustPolicy);
    }

    private static bool HasStage(IValidator validator, ValidationStage stage)
    {
        if (validator == null)
        {
            return false;
        }

        if (validator.Stages == null)
        {
            return false;
        }

        foreach (var s in validator.Stages)
        {
            if (s == stage)
            {
                return true;
            }
        }

        return false;
    }

    private IReadOnlyList<TrustPolicyOverride> GetTrustPolicyOverridesOrEmpty()
    {
        if (!ContextField.Properties.TryGetValue(TrustPolicyOverridesKey, out var value) || value == null)
        {
            return Array.Empty<TrustPolicyOverride>();
        }

        if (value is IReadOnlyList<TrustPolicyOverride> list)
        {
            return list;
        }

        if (value is IEnumerable<TrustPolicyOverride> enumerable)
        {
            return enumerable.ToList();
        }

        return Array.Empty<TrustPolicyOverride>();
    }

    private static TrustPolicy? FindOverride(IReadOnlyList<TrustPolicyOverride> overrides, IValidator validator)
    {
        foreach (var o in overrides)
        {
            if (ReferenceEquals(o.Validator, validator))
            {
                return o.Policy;
            }
        }

        return null;
    }

}
