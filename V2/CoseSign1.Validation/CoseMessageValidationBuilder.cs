// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation;

/// <summary>
/// Implementation of the COSE message validation builder.
/// </summary>
internal sealed class CoseMessageValidationBuilder : ICoseMessageValidationBuilder
{
    private readonly List<IValidator<CoseSign1Message>> _validators = new();
    private readonly ValidationBuilderContext _context = new();

    public ValidationBuilderContext Context => _context;

    public ICoseMessageValidationBuilder AddValidator(IValidator<CoseSign1Message> validator)
    {
        if (validator == null)
        {
            throw new ArgumentNullException(nameof(validator));
        }

        _validators.Add(validator);
        return this;
    }

    public ICoseMessageValidationBuilder AddValidator(Func<CoseSign1Message, ValidationResult> validatorFunc)
    {
        if (validatorFunc == null)
        {
            throw new ArgumentNullException(nameof(validatorFunc));
        }

        _validators.Add(new FunctionValidator(validatorFunc));
        return this;
    }

    public ICoseMessageValidationBuilder StopOnFirstFailure(bool stopOnFirstFailure = true)
    {
        _context.StopOnFirstFailure = stopOnFirstFailure;
        return this;
    }

    public ICoseMessageValidationBuilder RunInParallel(bool parallel = true)
    {
        _context.RunInParallel = parallel;
        return this;
    }

    public IValidator<CoseSign1Message> Build()
    {
        return new CompositeValidator(_validators, _context.StopOnFirstFailure, _context.RunInParallel);
    }
}
