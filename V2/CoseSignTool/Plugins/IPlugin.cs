// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;

namespace CoseSignTool.Plugins;

/// <summary>
/// Interface for CoseSignTool plugins that can extend functionality.
/// Plugins can provide signing commands, verification providers, or other extensions.
/// </summary>
public interface IPlugin
{
    /// <summary>
    /// Gets the unique name of the plugin.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Gets the version of the plugin.
    /// </summary>
    string Version { get; }

    /// <summary>
    /// Gets the description of the plugin.
    /// </summary>
    string Description { get; }

    /// <summary>
    /// Gets the signing command providers offered by this plugin.
    /// Return empty collection if plugin doesn't provide signing commands.
    /// </summary>
    IEnumerable<ISigningCommandProvider> GetSigningCommandProviders();

    /// <summary>
    /// Gets the verification providers offered by this plugin.
    /// Return empty collection if plugin doesn't provide verification capabilities.
    /// </summary>
    IEnumerable<IVerificationProvider> GetVerificationProviders();

    /// <summary>
    /// Gets the transparency provider contributors offered by this plugin.
    /// Return empty collection if plugin doesn't provide transparency services.
    /// </summary>
    IEnumerable<ITransparencyProviderContributor> GetTransparencyProviderContributors();

    /// <summary>
    /// Registers additional (non-signing) commands with the root command.
    /// For example: verify commands, utility commands, etc.
    /// Signing commands are registered automatically via GetSigningCommandProviders().
    /// </summary>
    /// <param name="rootCommand">The root command to register with.</param>
    void RegisterCommands(Command rootCommand);

    /// <summary>
    /// Initializes the plugin with the given configuration.
    /// </summary>
    /// <param name="configuration">Optional configuration dictionary.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task InitializeAsync(IDictionary<string, string>? configuration = null);
}