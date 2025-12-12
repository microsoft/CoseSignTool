// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation;

/// <summary>
/// Implementation of the COSE message validation builder.
/// </summary>
internal sealed class CoseMessageValidationBuilder : ICoseMessageValidationBuilder
{
    private readonly List<IValidator<CoseSign1Message>> Validators = new();
    private readonly ValidationBuilderContext ContextField = new();

    public ValidationBuilderContext Context => ContextField;

    public ICoseMessageValidationBuilder AddValidator(IValidator<CoseSign1Message> validator)
    {
        if (validator == null)
        {
            throw new ArgumentNullException(nameof(validator));
        }

        Validators.Add(validator);
        return this;
    }

    public ICoseMessageValidationBuilder AddValidator(Func<CoseSign1Message, ValidationResult> validatorFunc)
    {
        if (validatorFunc == null)
        {
            throw new ArgumentNullException(nameof(validatorFunc));
        }

        Validators.Add(new FunctionValidator(validatorFunc));
        return this;
    }

    public ICoseMessageValidationBuilder StopOnFirstFailure(bool stopOnFirstFailure = true)
    {
        ContextField.StopOnFirstFailure = stopOnFirstFailure;
        return this;
    }

    public ICoseMessageValidationBuilder RunInParallel(bool parallel = true)
    {
        ContextField.RunInParallel = parallel;
        return this;
    }

    public IValidator<CoseSign1Message> Build()
    {
        return new CompositeValidator(Validators, ContextField.StopOnFirstFailure, ContextField.RunInParallel);
    }
}