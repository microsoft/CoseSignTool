// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.Cose;

namespace CoseSign1.Validation;

/// <summary>
/// Builder for configuring <see cref="AnySignatureValidator"/>.
/// </summary>
public interface IAnySignatureValidatorBuilder
{
    /// <summary>
    /// Adds a candidate signature validator.
    /// Typically these implement <see cref="ISignatureValidator"/> (and optionally <see cref="IConditionalValidator{T}"/>).
    /// </summary>
    IAnySignatureValidatorBuilder Add(IValidator<CoseSign1Message> validator);
}

/// <summary>
/// Extension methods for composing signature validation.
/// </summary>
public static class AnySignatureValidationExtensions
{
    /// <summary>
    /// Adds an <see cref="AnySignatureValidator"/> configured via a builder.
    /// At least one candidate validator must be added.
    /// </summary>
    public static ICoseMessageValidationBuilder AddAnySignatureValidator(
        this ICoseMessageValidationBuilder builder,
        Action<IAnySignatureValidatorBuilder> configure)
    {
        if (builder == null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        if (configure == null)
        {
            throw new ArgumentNullException(nameof(configure));
        }

        var b = new Builder();
        configure(b);

        return builder.AddValidator(new AnySignatureValidator(b.Build()));
    }

    private sealed class Builder : IAnySignatureValidatorBuilder
    {
        private readonly List<IValidator<CoseSign1Message>> Validators = new();

        public IAnySignatureValidatorBuilder Add(IValidator<CoseSign1Message> validator)
        {
            Validators.Add(validator ?? throw new ArgumentNullException(nameof(validator)));
            return this;
        }

        public IReadOnlyList<IValidator<CoseSign1Message>> Build()
        {
            if (Validators.Count == 0)
            {
                throw new InvalidOperationException("No signature validators configured");
            }

            return Validators;
        }
    }
}
