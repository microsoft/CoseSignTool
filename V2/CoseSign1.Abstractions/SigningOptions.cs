// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace CoseSign1.Abstractions;

/// <summary>
/// Base options for signing operations.
/// Provides a future-proof way to pass optional customization parameters to signing methods.
/// </summary>
public class SigningOptions
{
    /// <summary>
    /// Gets or sets additional header contributors to apply for this specific operation.
    /// Applied after the signing service's required contributors.
    /// </summary>
    public IReadOnlyList<IHeaderContributor>? AdditionalHeaderContributors { get; set; }

    /// <summary>
    /// Gets or sets additional context for custom header contributors.
    /// </summary>
    public IDictionary<string, object>? AdditionalContext { get; set; }

    /// <summary>
    /// Gets or sets additional authenticated data to include in the signature.
    /// This data is covered by the signature but not included in the COSE message payload.
    /// Defaults to <see cref="ReadOnlyMemory{T}.Empty"/>.
    /// </summary>
    public ReadOnlyMemory<byte> AdditionalData { get; set; } = ReadOnlyMemory<byte>.Empty;
}
