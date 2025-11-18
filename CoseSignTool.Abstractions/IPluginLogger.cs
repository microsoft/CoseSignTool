// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

/// <summary>
/// Defines logging levels for plugin output.
/// </summary>
public enum LogLevel
{
    /// <summary>
    /// No output.
    /// </summary>
    Quiet = 0,

    /// <summary>
    /// Normal informational messages only.
    /// </summary>
    Normal = 1,

    /// <summary>
    /// Detailed diagnostic information.
    /// </summary>
    Verbose = 2
}

/// <summary>
/// Interface for logging within plugins, supporting different verbosity levels.
/// </summary>
public interface IPluginLogger
{
    /// <summary>
    /// Gets or sets the current log level.
    /// </summary>
    LogLevel Level { get; set; }

    /// <summary>
    /// Logs an informational message (shown at Normal and Verbose levels).
    /// </summary>
    /// <param name="message">The message to log.</param>
    void LogInformation(string message);

    /// <summary>
    /// Logs a verbose/debug message (shown only at Verbose level).
    /// </summary>
    /// <param name="message">The message to log.</param>
    void LogVerbose(string message);

    /// <summary>
    /// Logs a warning message (shown at all levels except Quiet).
    /// </summary>
    /// <param name="message">The message to log.</param>
    void LogWarning(string message);

    /// <summary>
    /// Logs an error message (shown at all levels).
    /// </summary>
    /// <param name="message">The message to log.</param>
    void LogError(string message);

    /// <summary>
    /// Logs an exception with its message (shown at all levels).
    /// </summary>
    /// <param name="ex">The exception to log.</param>
    /// <param name="message">Optional context message.</param>
    void LogException(Exception ex, string? message = null);
}
