// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation;

/// <summary>
/// Adapter to wrap a simple validation function as an IValidator.
/// </summary>
internal sealed class FunctionValidator : IValidator<CoseSign1Message>
{
    private readonly Func<CoseSign1Message, ValidationResult> _validatorFunc;
    private readonly string _name;

    public FunctionValidator(Func<CoseSign1Message, ValidationResult> validatorFunc, string? name = null)
    {
        _validatorFunc = validatorFunc ?? throw new ArgumentNullException(nameof(validatorFunc));
        _name = name ?? "FunctionValidator";
    }

    public ValidationResult Validate(CoseSign1Message input)
    {
        try
        {
            return _validatorFunc(input);
        }
        catch (Exception ex)
        {
            return ValidationResult.Failure(_name, new ValidationFailure
            {
                Message = $"Validation function threw an exception: {ex.Message}",
                ErrorCode = "VALIDATOR_EXCEPTION",
                Exception = ex
            });
        }
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input));
    }
}
