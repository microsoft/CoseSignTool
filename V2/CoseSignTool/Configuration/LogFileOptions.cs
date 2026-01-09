// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Configuration;

using System.Diagnostics.CodeAnalysis;
using CoseSignTool.Output;

/// <summary>
/// Configuration options for file-based logging.
/// </summary>
[ExcludeFromCodeCoverage]
public sealed class LogFileOptions
{
    /// <summary>
    /// String constants specific to this class.
    /// </summary>
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Command line argument names
        public const string ArgLogFile = "--log-file";
        public const string ArgLogFileAppend = "--log-file-append";
        public const string ArgLogFileOverwrite = "--log-file-overwrite";
        public const string ArgOutputFormat = "--output-format";
        public const string ArgOutputFormatShort = "-f";

        // Separator characters for --arg:value and --arg=value syntax
        public const string ColonSeparator = ":";
        public const string EqualsSeparator = "=";

        // Output format values
        public const string FormatJson = "json";
        public const string FormatXml = "xml";
        public const string FormatQuiet = "quiet";
    }

    /// <summary>
    /// Gets or sets the path to the log file. When null, file logging is disabled.
    /// </summary>
    public string? FilePath { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether to append to an existing log file.
    /// When false (default), the log file is overwritten.
    /// </summary>
    public bool Append { get; set; }

    /// <summary>
    /// Gets or sets the output format for log file entries.
    /// Note: Quiet format is treated as Text for log files since logs are for diagnostics.
    /// </summary>
    public OutputFormat Format { get; set; } = OutputFormat.Text;

    /// <summary>
    /// Gets the effective format for log file output.
    /// Quiet is converted to Text since log files are for diagnostics.
    /// </summary>
    public OutputFormat EffectiveFormat => Format == OutputFormat.Quiet ? OutputFormat.Text : Format;

    /// <summary>
    /// Gets a value indicating whether file logging is enabled.
    /// </summary>
    public bool IsEnabled => !string.IsNullOrWhiteSpace(FilePath);

    /// <summary>
    /// Parses log file options from command line arguments and removes them from the array.
    /// Also extracts output format for log file formatting (but keeps it in args for command processing).
    /// </summary>
    /// <param name="args">Command line arguments (will be modified to remove log file args).</param>
    /// <returns>The parsed log file options.</returns>
    public static LogFileOptions Parse(ref string[] args)
    {
        var options = new LogFileOptions();
        var remainingArgs = new List<string>();

        for (int i = 0; i < args.Length; i++)
        {
            var arg = args[i];

            if (arg == ClassStrings.ArgLogFile && i + 1 < args.Length)
            {
                options.FilePath = args[i + 1];
                i++; // Skip next arg (the file path)
            }
            else if (arg.StartsWith(ClassStrings.ArgLogFile + ClassStrings.ColonSeparator, StringComparison.OrdinalIgnoreCase))
            {
                // Support --log-file:path syntax
                options.FilePath = arg[(ClassStrings.ArgLogFile.Length + 1)..];
            }
            else if (arg.StartsWith(ClassStrings.ArgLogFile + ClassStrings.EqualsSeparator, StringComparison.OrdinalIgnoreCase))
            {
                // Support --log-file=path syntax
                options.FilePath = arg[(ClassStrings.ArgLogFile.Length + 1)..];
            }
            else if (arg == ClassStrings.ArgLogFileAppend)
            {
                options.Append = true;
            }
            else if (arg == ClassStrings.ArgLogFileOverwrite)
            {
                options.Append = false; // Explicit overwrite (default behavior)
            }
            else if ((arg == ClassStrings.ArgOutputFormat || arg == ClassStrings.ArgOutputFormatShort) && i + 1 < args.Length)
            {
                // Extract output format but keep in args for System.CommandLine
                options.Format = ParseOutputFormat(args[i + 1]);
                remainingArgs.Add(arg);
                remainingArgs.Add(args[i + 1]);
                i++; // Skip next arg (the format value)
                continue;
            }
            else
            {
                remainingArgs.Add(arg);
            }
        }

        args = remainingArgs.ToArray();
        return options;
    }

    /// <summary>
    /// Parses an output format string value.
    /// </summary>
    private static OutputFormat ParseOutputFormat(string value)
    {
        return value.ToLowerInvariant() switch
        {
            ClassStrings.FormatJson => OutputFormat.Json,
            ClassStrings.FormatXml => OutputFormat.Xml,
            ClassStrings.FormatQuiet => OutputFormat.Quiet,
            _ => OutputFormat.Text
        };
    }

    /// <summary>
    /// Opens a StreamWriter for the log file based on the current options.
    /// </summary>
    /// <returns>A StreamWriter for the log file, or null if file logging is disabled.</returns>
    /// <exception cref="IOException">Thrown when the log file cannot be opened.</exception>
    /// <exception cref="UnauthorizedAccessException">Thrown when access to the log file is denied.</exception>
    public StreamWriter? OpenLogFile()
    {
        if (!IsEnabled || FilePath == null)
        {
            return null;
        }

        // Ensure directory exists
        var directory = Path.GetDirectoryName(FilePath);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        return new StreamWriter(FilePath, append: Append)
        {
            AutoFlush = true
        };
    }
}
