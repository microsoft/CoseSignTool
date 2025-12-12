// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using CoseSign1.Abstractions.Transparency;

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

    /// <summary>
    /// Gets or sets a value indicating whether to disable transparency for this specific operation.
    /// </summary>
    /// <remarks>
    /// When true, transparency providers configured at the factory level will be skipped
    /// for this operation only. This allows selective opt-out of transparency on a per-operation basis.
    /// 
    /// Default: false (use factory-configured transparency providers)
    /// 
    /// Example - disable transparency for a specific operation:
    /// <code>
    /// var options = new SigningOptions
    /// {
    ///     DisableTransparency = true  // Skip transparency for this operation
    /// };
    /// 
    /// // Factory has transparency configured, but this message won't have transparency proof
    /// var message = await factory.CreateCoseSign1MessageAsync(payload, contentType, options);
    /// </code>
    /// </remarks>
    public bool DisableTransparency { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether to fail the entire operation
    /// if transparency proof addition fails.
    /// </summary>
    /// <remarks>
    /// When true (default): If transparency provider fails, the entire signing operation fails.
    /// When false: If transparency provider fails, the signed message is still returned without transparency proof.
    /// 
    /// Set to false if you want best-effort transparency (succeed with signature even if transparency fails).
    /// </remarks>
    public bool FailOnTransparencyError { get; set; } = true;
}