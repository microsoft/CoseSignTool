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
    /// <remarks>
    /// Override this property in derived classes to specify which options are boolean flags.
    /// Boolean flags can be specified without an explicit value (e.g., --verbose instead of --verbose true).
    /// </remarks>
    public virtual IReadOnlyCollection<string> BooleanOptions => Array.Empty<string>();

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

    /// <summary>
    /// Gets a boolean flag from configuration. Handles CLI switches that may not have explicit values.
    /// Returns true if the flag is present (with any non-"false" value or no value), false otherwise.
    /// </summary>
    /// <param name="configuration">The configuration to read from.</param>
    /// <param name="key">The configuration key.</param>
    /// <returns>True if the flag is set, false otherwise.</returns>
    /// <remarks>
    /// This method handles the common CLI pattern where a flag can be specified in multiple ways:
    /// --flag (no value, implies true)
    /// --flag true (explicit true)
    /// --flag false (explicit false)
    /// The flag is considered true if:
    /// - The key exists in configuration AND
    /// - The value is not explicitly "false" (case-insensitive)
    /// </remarks>
    protected static bool GetBooleanFlag(IConfiguration configuration, string key)
    {
        // Check if the key exists in the configuration
        string? value = configuration[key];
        
        // If the key doesn't exist, return false
        if (value == null)
        {
            return false;
        }
        
        // If the value is explicitly "false", return false
        if (string.Equals(value, "false", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        
        // Otherwise, the flag was specified (with any value or no value), so return true
        return true;
    }
}
