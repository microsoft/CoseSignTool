// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Trust;

using System.Diagnostics.CodeAnalysis;

/// <summary>
/// Builder for configuring MST trust-pack registrations.
/// </summary>
public sealed class MstTrustBuilder
{
    /// <summary>
    /// Initializes a new instance of the <see cref="MstTrustBuilder"/> class.
    /// </summary>
    public MstTrustBuilder()
    {
    }

    /// <summary>
    /// Gets the configured trust options.
    /// </summary>
    public MstTrustOptions Options { get; } = new();

    /// <summary>
    /// Enables receipt verification using the specified MST endpoint.
    /// </summary>
    /// <param name="endpoint">The MST service endpoint URL.</param>
    /// <returns>The same builder instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="endpoint"/> is null.</exception>
    public MstTrustBuilder VerifyReceipts(Uri endpoint)
    {
        if (endpoint == null)
        {
            throw new ArgumentNullException(nameof(endpoint));
        }

        Options.VerifyReceipts = true;
        Options.Endpoint = endpoint;
        return this;
    }

    /// <summary>
    /// Configures the trust pack for offline-only behavior.
    /// </summary>
    /// <returns>The same builder instance.</returns>
    public MstTrustBuilder OfflineOnly()
    {
        Options.OfflineOnly = true;
        return this;
    }
}

/// <summary>
/// Configuration options for the MST trust pack.
/// </summary>
[ExcludeFromCodeCoverage]
public sealed class MstTrustOptions
{
    /// <summary>
    /// Gets or sets a value indicating whether receipt verification is enabled.
    /// When false, <see cref="MstReceiptTrustedFact"/> will be produced as "unavailable".
    /// </summary>
    public bool VerifyReceipts { get; set; }

    /// <summary>
    /// Gets or sets the MST service endpoint used for receipt verification.
    /// Required when <see cref="VerifyReceipts"/> is true.
    /// </summary>
    public Uri? Endpoint { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the trust pack must operate in offline-only mode.
    /// </summary>
    public bool OfflineOnly { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether offline MST signing keys were provided.
    /// </summary>
    /// <remarks>
    /// This option is a compatibility bridge for callers that want to distinguish
    /// "offline requested but no keys provided" (missing) vs "offline keys were provided" (available).
    /// The current implementation does not yet perform full offline receipt verification.
    /// </remarks>
    public bool HasOfflineKeys { get; set; }
}
