// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Extensions;

using CoseSign1.Validation.Builders;
using CoseSign1.Validation.Interfaces;

/// <summary>
/// Convenience extension methods for composing validation pipelines.
/// </summary>
public static class ValidationBuilderExtensions
{
    private const string TrustPolicyOverridesKey = ClassStrings.TrustPolicyOverridesKey;

    /// <summary>
    /// Adds a trust-stage validator and a corresponding trust requirement.
    /// This is the recommended pattern when a validator emits trust assertions and you want the verifier
    /// to require those assertions.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="validator">The trust-stage validator to add.</param>
    /// <param name="requiredPolicy">The trust policy requirement associated with the validator.</param>
    /// <returns>The same builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/>, <paramref name="validator"/>, or <paramref name="requiredPolicy"/> is null.</exception>
    public static ICoseSign1ValidationBuilder AddTrustValidator(
        this ICoseSign1ValidationBuilder builder,
        IValidator validator,
        TrustPolicy requiredPolicy)
    {
        if (builder == null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        if (validator == null)
        {
            throw new ArgumentNullException(nameof(validator));
        }

        if (requiredPolicy == null)
        {
            throw new ArgumentNullException(nameof(requiredPolicy));
        }

        builder.AddValidator(validator);

        // Treat this as an override of any default policy the validator may contribute.
        // This prevents accidental AND-ing of a default and a caller-specified policy.
        if (!builder.Context.Properties.TryGetValue(TrustPolicyOverridesKey, out var value) || value is not List<TrustPolicyOverride> list)
        {
            list = new List<TrustPolicyOverride>();
            builder.Context.Properties[TrustPolicyOverridesKey] = list;
        }

        list.Add(new TrustPolicyOverride(validator, requiredPolicy));
        return builder;
    }

    internal static class ClassStrings
    {
        public const string TrustPolicyOverridesKey = "CoseSign1.Validation.TrustPolicyOverrides";
        public const string ErrorValidatorDoesNotSpecifyStagesFormat = "Validator '{0}' does not specify any stages.";
        public const string ErrorUnsupportedValidationStageFormat = "Unsupported validation stage: {0}";
    }
}
