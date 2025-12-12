// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation;

/// <summary>
/// Core builder interface for COSE message validation.
/// Validators extend this through extension methods to add domain-specific APIs.
/// </summary>
public interface ICoseMessageValidationBuilder
{
    /// <summary>
    /// Adds a validator to the validation pipeline.
    /// Used internally by extension methods to register validators.
    /// </summary>
    /// <param name="validator">The validator to add.</param>
    /// <returns>The builder for method chaining.</returns>
    ICoseMessageValidationBuilder AddValidator(IValidator<CoseSign1Message> validator);

    /// <summary>
    /// Adds a simple function-based validator to the validation pipeline.
    /// </summary>
    /// <param name="validatorFunc">The validation function.</param>
    /// <returns>The builder for method chaining.</returns>
    ICoseMessageValidationBuilder AddValidator(Func<CoseSign1Message, ValidationResult> validatorFunc);

    /// <summary>
    /// Configures whether to stop on first failure or collect all failures.
    /// Default: collect all failures.
    /// </summary>
    /// <param name="stopOnFirstFailure">True to stop on first failure, false to collect all.</param>
    /// <returns>The builder for method chaining.</returns>
    ICoseMessageValidationBuilder StopOnFirstFailure(bool stopOnFirstFailure = true);

    /// <summary>
    /// Configures whether to run validators in parallel when safe.
    /// Default: sequential.
    /// </summary>
    /// <param name="parallel">True to enable parallel execution, false for sequential.</param>
    /// <returns>The builder for method chaining.</returns>
    ICoseMessageValidationBuilder RunInParallel(bool parallel = true);

    /// <summary>
    /// Builds the final composite validator.
    /// </summary>
    /// <returns>The composed validator.</returns>
    IValidator<CoseSign1Message> Build();

    /// <summary>
    /// Gets the current builder configuration (for advanced scenarios).
    /// </summary>
    ValidationBuilderContext Context { get; }
}