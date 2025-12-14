// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;

namespace CoseSignTool.Abstractions;

/// <summary>
/// Interface for CoseSignTool plugins that can extend functionality.
/// Plugins can provide signing commands, verification providers, transparency providers, or other extensions.
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
    /// Gets all extension points this plugin provides.
    /// Return <see cref="PluginExtensions.None"/> if plugin provides no extensions.
    /// </summary>
    PluginExtensions GetExtensions();

    /// <summary>
    /// Registers additional commands with the root command.
    /// Use this for utility commands that don't fit the standard signing/verification pattern.
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