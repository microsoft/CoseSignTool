// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Validators;

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;

/// <summary>
/// Adapter to wrap a simple validation function as an IValidator.
/// </summary>
internal sealed class FunctionValidator : IValidator
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string DefaultName = nameof(FunctionValidator);
        public static readonly string ErrorCodeValidatorException = "VALIDATOR_EXCEPTION";
        public static readonly string ErrorMessageValidatorExceptionFormat = "Validation function threw an exception: {0}";
    }

    private readonly Func<CoseSign1Message, ValidationStage, ValidationResult> ValidatorFunc;
    private readonly string Name;
    private readonly IReadOnlyCollection<ValidationStage> StagesField;

    /// <summary>
    /// Initializes a new instance of the <see cref="FunctionValidator"/> class.
    /// </summary>
    /// <param name="validatorFunc">A validation function.</param>
    /// <param name="name">Optional validator name.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="validatorFunc"/> is null.</exception>
    public FunctionValidator(Func<CoseSign1Message, ValidationResult> validatorFunc, string? name = null)
        : this((msg, _) => validatorFunc(msg), name, stages: null)
    {
        if (validatorFunc == null)
        {
            throw new ArgumentNullException(nameof(validatorFunc));
        }
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="FunctionValidator"/> class.
    /// </summary>
    /// <param name="validatorFunc">A validation function that receives the stage.</param>
    /// <param name="name">Optional validator name.</param>
    /// <param name="stages">Optional set of stages this validator applies to.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="validatorFunc"/> is null.</exception>
    public FunctionValidator(
        Func<CoseSign1Message, ValidationStage, ValidationResult> validatorFunc,
        string? name = null,
        IReadOnlyCollection<ValidationStage>? stages = null)
    {
        ValidatorFunc = validatorFunc ?? throw new ArgumentNullException(nameof(validatorFunc));
        Name = name ?? ClassStrings.DefaultName;
        StagesField = stages ?? (ValidationStage[])Enum.GetValues(typeof(ValidationStage));
    }

    public IReadOnlyCollection<ValidationStage> Stages => StagesField;

    public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
    {
        try
        {
            return ValidatorFunc(input, stage);
        }
        catch (Exception ex)
        {
            return ValidationResult.Failure(Name, new ValidationFailure
            {
                Message = string.Format(ClassStrings.ErrorMessageValidatorExceptionFormat, ex.Message),
                ErrorCode = ClassStrings.ErrorCodeValidatorException,
                Exception = ex
            });
        }
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input, stage));
    }
}