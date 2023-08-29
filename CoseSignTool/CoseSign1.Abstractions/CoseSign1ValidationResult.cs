// ---------------------------------------------------------------------------
// <copyright file="CoseSign1ValidationResult.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ---------------------------------------------------------------------------

namespace CoseSign1.Abstractions;

/// <summary>
/// Represents a validation result.
/// </summary>
public class CoseSign1ValidationResult
{
    /// <summary>
    /// Creates a new instance of <see cref="CoseSign1ValidationResult"/>.
    /// </summary>
    /// <param name="validator">The <see cref="Type"/> of the validator producing this result.</param>
    /// <param name="include">An Exception or other object to pass to the caller, if any.</param>
    public CoseSign1ValidationResult(Type validator, object? include = null)
    {
        Validator = validator;
        if (include != null) { Includes.Add(include); }
    }

    /// <summary>
    /// Creates a new <see cref="CoseSign1ValidationResult"/> object.
    /// </summary>
    /// <param name="validator">The type of validator that generated the result.</param>
    /// <param name="passedValidation">True if validation passed, false otherwise.</param>
    /// <param name="resultMessage">A message describing the success, error, or warning.</param>
    /// <param name="includes">An optinal list of optional objects to pass to the caller, such as Exceptions and ChainStatus objects.</param>
    public CoseSign1ValidationResult(Type validator, bool passedValidation, string resultMessage, List<object>? includes = null)
    {
        Validator = validator;
        PassedValidation = passedValidation;
        ResultMessage = resultMessage;
        Includes = includes;
    }

    /// <summary>
    /// The type of the validator performing the result.
    /// </summary>
    public Type Validator { get; }

    /// <summary>
    /// True if validation passed, false otherwise.
    /// </summary>
    public bool PassedValidation { get; set; } = false;

    /// <summary>
    /// An error or warning message, if any.
    /// </summary>
    public string ResultMessage { get; set; } = string.Empty;

    /// <summary>
    /// An optional list of optional objects to pass to the caller, such as Exceptions and ChainStatus objects.
    /// </summary>
    public List<object>? Includes { get; set; } = new();
}
