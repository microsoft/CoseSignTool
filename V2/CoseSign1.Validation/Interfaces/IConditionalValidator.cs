// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Interfaces;

/// <summary>
/// Optional interface for validators that only apply to some inputs.
/// When implemented, <see cref="global::CoseSign1.Validation.Validators.CompositeValidator"/> will skip validators
/// whose <see cref="IsApplicable"/> returns false.
/// </summary>
public interface IConditionalValidator : IValidator
{
    /// <summary>
    /// Returns true if this validator should be executed for the given input.
    /// </summary>
    /// <param name="input">The input message.</param>
    /// <param name="stage">The validation stage being executed.</param>
    /// <returns><c>true</c> if the validator should run; otherwise <c>false</c>.</returns>
    bool IsApplicable(CoseSign1Message input, ValidationStage stage);
}
