// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation;

/// <summary>
/// Context that can be shared between validators and extension methods during the build process.
/// Allows validators to coordinate and share state.
/// </summary>
public sealed class ValidationBuilderContext
{
    /// <summary>
    /// Gets a dictionary for storing arbitrary properties that can be shared between validators.
    /// </summary>
    public IDictionary<string, object> Properties { get; } = new Dictionary<string, object>();

    /// <summary>
    /// Gets or sets a value indicating whether validation should stop on the first failure.
    /// Default is false (collect all failures).
    /// </summary>
    public bool StopOnFirstFailure { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether validators should run in parallel when safe.
    /// Default is false (sequential execution).
    /// </summary>
    public bool RunInParallel { get; set; }
}
