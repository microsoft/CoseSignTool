// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Builders;

/// <summary>
/// Context that can be shared between validation builder extension methods during the build process.
/// </summary>
public sealed class ValidationBuilderContext
{
    /// <summary>
    /// Gets a dictionary for storing arbitrary properties that can be shared between builder extensions.
    /// </summary>
    public IDictionary<string, object> Properties { get; } = new Dictionary<string, object>();
}
