// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Interfaces;

using Microsoft.Extensions.Logging;

/// <summary>
/// Builder for configuring a signature validator that tries multiple candidate signature validators.
/// </summary>
public interface IAnySignatureValidatorBuilder
{
    /// <summary>
    /// Gets the logger factory for creating loggers in validators.
    /// May be null if logging is not configured.
    /// </summary>
    ILoggerFactory? LoggerFactory { get; }

    /// <summary>
    /// Adds a candidate signature validator.
    /// Typically these include <see cref="ValidationStage.Signature"/> in <see cref="IValidator.Stages"/>
    /// (and optionally implement <see cref="IConditionalValidator"/>).
    /// </summary>
    /// <param name="validator">The candidate validator to add.</param>
    /// <returns>The same builder instance.</returns>
    IAnySignatureValidatorBuilder Add(IValidator validator);
}
