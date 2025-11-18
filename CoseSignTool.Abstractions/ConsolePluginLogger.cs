// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

/// <summary>
/// Console-based implementation of <see cref="IPluginLogger"/>.
/// </summary>
public class ConsolePluginLogger : IPluginLogger
{
    /// <summary>
    /// Gets or sets the current log level.
    /// </summary>
    public LogLevel Level { get; set; } = LogLevel.Normal;

    /// <summary>
    /// Creates a new instance with the specified log level.
    /// </summary>
    /// <param name="level">The initial log level.</param>
    public ConsolePluginLogger(LogLevel level = LogLevel.Normal)
    {
        Level = level;
    }

    /// <inheritdoc/>
    public void LogInformation(string message)
    {
        if (Level >= LogLevel.Normal)
        {
            Console.WriteLine(message);
        }
    }

    /// <inheritdoc/>
    public void LogVerbose(string message)
    {
        if (Level >= LogLevel.Verbose)
        {
            Console.WriteLine($"[VERBOSE] {message}");
        }
    }

    /// <inheritdoc/>
    public void LogWarning(string message)
    {
        if (Level > LogLevel.Quiet)
        {
            var originalColor = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"Warning: {message}");
            Console.ForegroundColor = originalColor;
        }
    }

    /// <inheritdoc/>
    public void LogError(string message)
    {
        // Errors are always shown
        var originalColor = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Error.WriteLine($"Error: {message}");
        Console.ForegroundColor = originalColor;
    }

    /// <inheritdoc/>
    public void LogException(Exception ex, string? message = null)
    {
        // Exceptions are always shown
        var originalColor = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Red;
        
        if (!string.IsNullOrEmpty(message))
        {
            Console.Error.WriteLine($"Error: {message}");
        }
        
        Console.Error.WriteLine($"Exception: {ex.Message}");
        
        if (Level >= LogLevel.Verbose && ex.StackTrace != null)
        {
            Console.Error.WriteLine($"Stack Trace:{Environment.NewLine}{ex.StackTrace}");
            
            if (ex.InnerException != null)
            {
                Console.Error.WriteLine($"Inner Exception: {ex.InnerException.Message}");
            }
        }
        
        Console.ForegroundColor = originalColor;
    }
}
