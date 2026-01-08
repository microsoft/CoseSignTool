// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;

namespace CoseSign1.Validation.Validators;

/// <summary>
/// Executes a set of signature validators and requires that at least one applicable validator succeeds.
/// Intended for scenarios where multiple signature schemes may be present (e.g., X.509 vs embedded COSE_Key).
/// </summary>
public sealed class AnySignatureValidator : IValidator
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ValidatorName = nameof(AnySignatureValidator);

        public static readonly string ErrorCodeNullInput = "NULL_INPUT";
        public static readonly string ErrorMessageNullInput = "Input message is null";

        public static readonly string ErrorCodeNoApplicableValidator = "NO_APPLICABLE_SIGNATURE_VALIDATOR";
        public static readonly string ErrorMessageNoApplicableValidator = "No applicable signature verifier was found for this message";

        public static readonly string NotApplicableReasonUnsupportedStageFormat = "Unsupported validation stage: {0}";

        public static readonly string MetadataKeySelectedValidator = "SelectedValidator";
    }

    private readonly IReadOnlyList<IValidator> Validators;
    private static readonly IReadOnlyCollection<ValidationStage> StagesField = new[] { ValidationStage.Signature };

    /// <summary>
    /// Initializes a new instance of the <see cref="AnySignatureValidator"/> class.
    /// </summary>
    /// <param name="validators">The candidate signature validators to execute.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="validators"/> is null.</exception>
    public AnySignatureValidator(IEnumerable<IValidator> validators)
    {
        Validators = validators?.ToList() ?? throw new ArgumentNullException(nameof(validators));
    }

    /// <inheritdoc/>
    public IReadOnlyCollection<ValidationStage> Stages => StagesField;

    /// <inheritdoc/>
    public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
    {
        if (input is null)
        {
            return ValidationResult.Failure(ClassStrings.ValidatorName, stage, ClassStrings.ErrorMessageNullInput, ClassStrings.ErrorCodeNullInput);
        }

        if (stage != ValidationStage.Signature)
        {
            return ValidationResult.NotApplicable(
                ClassStrings.ValidatorName,
                stage,
                string.Format(ClassStrings.NotApplicableReasonUnsupportedStageFormat, stage));
        }

        var failures = new List<ValidationFailure>();
        bool executedAny = false;

        foreach (var validator in Validators)
        {
            if (!validator.Stages.Contains(stage))
            {
                continue;
            }

            if (validator is IConditionalValidator conditional && !conditional.IsApplicable(input, stage))
            {
                continue;
            }

            executedAny = true;
            var result = validator.Validate(input, stage);
            if (result.IsNotApplicable)
            {
                executedAny = false;
                continue;
            }

            if (result.IsValid)
            {
                var metadata = new Dictionary<string, object>();
                foreach (var kvp in result.Metadata)
                {
                    metadata[kvp.Key] = kvp.Value;
                }

                metadata[ClassStrings.MetadataKeySelectedValidator] = result.ValidatorName;

                return ValidationResult.Success(ClassStrings.ValidatorName, stage, metadata);
            }

            if (result.IsFailure)
            {
                failures.AddRange(result.Failures);
            }
        }

        if (!executedAny)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                stage,
                ClassStrings.ErrorMessageNoApplicableValidator,
                ClassStrings.ErrorCodeNoApplicableValidator);
        }

        if (failures.Count == 0)
        {
            failures.Add(new ValidationFailure
            {
                ErrorCode = ClassStrings.ErrorCodeNoApplicableValidator,
                Message = ClassStrings.ErrorMessageNoApplicableValidator
            });
        }

        return ValidationResult.Failure(ClassStrings.ValidatorName, stage, failures.ToArray());
    }

    /// <inheritdoc/>
    public async Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
    {
        if (input is null)
        {
            return ValidationResult.Failure(ClassStrings.ValidatorName, stage, ClassStrings.ErrorMessageNullInput, ClassStrings.ErrorCodeNullInput);
        }

        if (stage != ValidationStage.Signature)
        {
            return ValidationResult.NotApplicable(
                ClassStrings.ValidatorName,
                stage,
                string.Format(ClassStrings.NotApplicableReasonUnsupportedStageFormat, stage));
        }

        var failures = new List<ValidationFailure>();
        bool executedAny = false;

        foreach (var validator in Validators)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!validator.Stages.Contains(stage))
            {
                continue;
            }

            if (validator is IConditionalValidator conditional && !conditional.IsApplicable(input, stage))
            {
                continue;
            }

            executedAny = true;
            var result = await validator.ValidateAsync(input, stage, cancellationToken).ConfigureAwait(false);
            if (result.IsNotApplicable)
            {
                executedAny = false;
                continue;
            }

            if (result.IsValid)
            {
                var metadata = new Dictionary<string, object>();
                foreach (var kvp in result.Metadata)
                {
                    metadata[kvp.Key] = kvp.Value;
                }

                metadata[ClassStrings.MetadataKeySelectedValidator] = result.ValidatorName;

                return ValidationResult.Success(ClassStrings.ValidatorName, stage, metadata);
            }

            if (result.IsFailure)
            {
                failures.AddRange(result.Failures);
            }
        }

        if (!executedAny)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                stage,
                ClassStrings.ErrorMessageNoApplicableValidator,
                ClassStrings.ErrorCodeNoApplicableValidator);
        }

        return ValidationResult.Failure(ClassStrings.ValidatorName, stage, failures.ToArray());
    }
}
