// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

/// <summary>
/// Defines the interface for a CoseSignTool plugin.
/// </summary>
public interface ICoseSignToolPlugin
{
    /// <summary>
    /// Gets the name of the plugin.
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
    /// Gets the commands provided by this plugin.
    /// </summary>
    IEnumerable<IPluginCommand> Commands { get; }

    /// <summary>
    /// Initializes the plugin with the provided configuration.
    /// This method is called once when the plugin is loaded.
    /// </summary>
    /// <param name="configuration">The global configuration for the plugin.</param>
    void Initialize(IConfiguration? configuration = null);
}
