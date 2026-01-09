// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Extensions;

using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Validators;
using Microsoft.Extensions.Logging;

/// <summary>
/// Extension methods for composing signature validation.
/// </summary>
public static class AnySignatureValidationExtensions
{
    /// <summary>
    /// Adds an <see cref="AnySignatureValidator"/> configured via a builder.
    /// At least one candidate validator must be added.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="configure">Delegate used to configure the candidate signature validators.</param>
    /// <returns>The same builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> or <paramref name="configure"/> is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when no candidate signature validators are configured.</exception>
    public static ICoseSign1ValidationBuilder AddAnySignatureValidator(
        this ICoseSign1ValidationBuilder builder,
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

        var b = new Builder(builder.LoggerFactory);
        configure(b);

        var logger = builder.LoggerFactory?.CreateLogger<AnySignatureValidator>();
        return builder.AddValidator(new AnySignatureValidator(b.Build(), logger));
    }

    private sealed class Builder : IAnySignatureValidatorBuilder
    {
        [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
        internal static class ClassStrings
        {
            public static readonly string ErrorNoSignatureValidatorsConfigured = "No signature validators configured";
        }

        private readonly List<IValidator> Validators = new();

        public Builder(ILoggerFactory? loggerFactory)
        {
            LoggerFactory = loggerFactory;
        }

        /// <inheritdoc/>
        public ILoggerFactory? LoggerFactory { get; }

        /// <summary>
        /// Adds a candidate signature validator.
        /// </summary>
        /// <param name="validator">The candidate validator.</param>
        /// <returns>The same builder instance.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="validator"/> is null.</exception>
        public IAnySignatureValidatorBuilder Add(IValidator validator)
        {
            Validators.Add(validator ?? throw new ArgumentNullException(nameof(validator)));
            return this;
        }

        /// <summary>
        /// Builds the configured candidate validator list.
        /// </summary>
        /// <returns>The configured validators.</returns>
        /// <exception cref="InvalidOperationException">Thrown when no candidate validators were added.</exception>
        public IReadOnlyList<IValidator> Build()
        {
            if (Validators.Count == 0)
            {
                throw new InvalidOperationException(ClassStrings.ErrorNoSignatureValidatorsConfigured);
            }

            return Validators;
        }
    }
}
