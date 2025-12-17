// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.Cose;

namespace CoseSign1.Validation;

/// <summary>
/// Executes a set of signature validators and requires that at least one applicable validator succeeds.
/// Intended for scenarios where multiple signature schemes may be present (e.g., X.509 vs embedded COSE_Key).
/// </summary>
public sealed class AnySignatureValidator : IValidator<CoseSign1Message>
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ValidatorName = nameof(AnySignatureValidator);

        public static readonly string ErrorCodeNullInput = "NULL_INPUT";
        public static readonly string ErrorMessageNullInput = "Input message is null";

        public static readonly string ErrorCodeNoApplicableValidator = "NO_APPLICABLE_SIGNATURE_VALIDATOR";
        public static readonly string ErrorMessageNoApplicableValidator = "No applicable signature verifier was found for this message";
    }

    private readonly IReadOnlyList<IValidator<CoseSign1Message>> Validators;

    public AnySignatureValidator(IEnumerable<IValidator<CoseSign1Message>> validators)
    {
        Validators = validators?.ToList() ?? throw new ArgumentNullException(nameof(validators));
    }

    public ValidationResult Validate(CoseSign1Message input)
    {
        if (input is null)
        {
            return ValidationResult.Failure(ClassStrings.ValidatorName, ClassStrings.ErrorMessageNullInput, ClassStrings.ErrorCodeNullInput);
        }

        var failures = new List<ValidationFailure>();
        bool executedAny = false;

        foreach (var validator in Validators)
        {
            if (validator is IConditionalValidator<CoseSign1Message> conditional && !conditional.IsApplicable(input))
            {
                continue;
            }

            executedAny = true;
            var result = validator.Validate(input);
            if (result.IsValid)
            {
                var metadata = new Dictionary<string, object>();
                foreach (var kvp in result.Metadata)
                {
                    metadata[kvp.Key] = kvp.Value;
                }

                metadata["SelectedValidator"] = result.ValidatorName;

                return ValidationResult.Success(ClassStrings.ValidatorName, metadata);
            }

            failures.AddRange(result.Failures);
        }

        if (!executedAny)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
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

        return ValidationResult.Failure(ClassStrings.ValidatorName, failures.ToArray());
    }

    public async Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
    {
        if (input is null)
        {
            return ValidationResult.Failure(ClassStrings.ValidatorName, ClassStrings.ErrorMessageNullInput, ClassStrings.ErrorCodeNullInput);
        }

        var failures = new List<ValidationFailure>();
        bool executedAny = false;

        foreach (var validator in Validators)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (validator is IConditionalValidator<CoseSign1Message> conditional && !conditional.IsApplicable(input))
            {
                continue;
            }

            executedAny = true;
            var result = await validator.ValidateAsync(input, cancellationToken).ConfigureAwait(false);
            if (result.IsValid)
            {
                var metadata = new Dictionary<string, object>();
                foreach (var kvp in result.Metadata)
                {
                    metadata[kvp.Key] = kvp.Value;
                }

                metadata["SelectedValidator"] = result.ValidatorName;

                return ValidationResult.Success(ClassStrings.ValidatorName, metadata);
            }

            failures.AddRange(result.Failures);
        }

        if (!executedAny)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageNoApplicableValidator,
                ClassStrings.ErrorCodeNoApplicableValidator);
        }

        return ValidationResult.Failure(ClassStrings.ValidatorName, failures.ToArray());
    }
}
