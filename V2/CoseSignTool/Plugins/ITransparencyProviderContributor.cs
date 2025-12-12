// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Abstractions.Transparency;

namespace CoseSignTool.Plugins;

/// <summary>
/// Interface for plugins that contribute transparency providers.
/// Transparency providers augment signed messages with verifiable transparency proofs.
/// </summary>
public interface ITransparencyProviderContributor
{
    /// <summary>
    /// Gets the name of the transparency provider (e.g., "Microsoft Signing Transparency").
    /// </summary>
    string ProviderName { get; }

    /// <summary>
    /// Gets the description of the transparency provider.
    /// </summary>
    string ProviderDescription { get; }

    /// <summary>
    /// Creates a transparency provider instance with the given configuration options.
    /// </summary>
    /// <param name="options">Configuration options from command line arguments.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A configured transparency provider instance.</returns>
    Task<ITransparencyProvider> CreateTransparencyProviderAsync(
        IDictionary<string, object?> options,
        CancellationToken cancellationToken = default);
}
