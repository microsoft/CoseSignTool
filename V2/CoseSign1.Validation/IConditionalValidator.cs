// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation;

/// <summary>
/// Optional interface for validators that only apply to some inputs.
/// When implemented, <see cref="CompositeValidator"/> will skip validators
/// whose <see cref="IsApplicable"/> returns false.
/// </summary>
/// <typeparam name="T">The type of input to validate.</typeparam>
public interface IConditionalValidator<in T>
{
    /// <summary>
    /// Returns true if this validator should be executed for the given input.
    /// </summary>
    bool IsApplicable(T input);
}
