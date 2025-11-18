// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

/// <summary>
/// Abstract base class for plugin commands that provides common functionality.
/// </summary>
public abstract class PluginCommandBase : IPluginCommand
{
    /// <summary>
    /// Gets the logger instance for this command. Set by the CLI infrastructure via SetLogger.
    /// </summary>
    protected IPluginLogger Logger { get; private set; } = new ConsolePluginLogger();

    /// <inheritdoc/>
    public void SetLogger(IPluginLogger logger)
    {
        Logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc/>
    public abstract string Name { get; }

    /// <inheritdoc/>
    public abstract string Description { get; }

    /// <inheritdoc/>
    public abstract string Usage { get; }

    /// <inheritdoc/>
    public abstract IDictionary<string, string> Options { get; }

    /// <inheritdoc/>
    public abstract Task<PluginExitCode> ExecuteAsync(IConfiguration configuration, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a required configuration value.
    /// </summary>
    /// <param name="configuration">The configuration to read from.</param>
    /// <param name="key">The configuration key.</param>
    /// <returns>The configuration value.</returns>
    /// <exception cref="ArgumentNullException">Thrown when the configuration value is missing.</exception>
    protected static string GetRequiredValue(IConfiguration configuration, string key)
    {
        string? value = configuration[key];
        return value ?? throw new ArgumentNullException(key, $"Required configuration value '{key}' is missing.");
    }

    /// <summary>
    /// Gets an optional configuration value.
    /// </summary>
    /// <param name="configuration">The configuration to read from.</param>
    /// <param name="key">The configuration key.</param>
    /// <param name="defaultValue">The default value to return if the key is not found.</param>
    /// <returns>The configuration value or the default value.</returns>
    protected static string? GetOptionalValue(IConfiguration configuration, string key, string? defaultValue = null)
    {
        return configuration[key] ?? defaultValue;
    }
}
