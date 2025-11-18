// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

/// <summary>
/// Defines the interface for a command that can be executed by a plugin.
/// </summary>
public interface IPluginCommand
{
    /// <summary>
    /// Gets the name of the command (e.g., "register", "verify").
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Gets the description of the command for help output.
    /// </summary>
    string Description { get; }

    /// <summary>
    /// Gets the usage string for the command.
    /// </summary>
    string Usage { get; }

    /// <summary>
    /// Gets the command line options supported by this command.
    /// </summary>
    IDictionary<string, string> Options { get; }

    /// <summary>
    /// Executes the command with the provided configuration.
    /// </summary>
    /// <param name="configuration">The command line configuration containing the parsed arguments.</param>
    /// <param name="cancellationToken">A cancellation token to observe while waiting for the task to complete.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the exit code.</returns>
    Task<PluginExitCode> ExecuteAsync(IConfiguration configuration, CancellationToken cancellationToken = default);

    /// <summary>
    /// Sets the logger instance for this command. Called by the CLI infrastructure before ExecuteAsync.
    /// </summary>
    /// <param name="logger">The logger instance to use for diagnostic output.</param>
    void SetLogger(IPluginLogger logger);
}
