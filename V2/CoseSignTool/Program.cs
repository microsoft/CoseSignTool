// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool;

using System.CommandLine;
using System.CommandLine.IO;
using System.Diagnostics.CodeAnalysis;
using CoseSignTool.Commands;
using CoseSignTool.Configuration;
using Microsoft.Extensions.Logging;

/// <summary>
/// Main entry point for the CoseSignTool CLI application.
/// </summary>
public static class Program
{
    /// <summary>
    /// String constants specific to this class.
    /// </summary>
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string LoggerCategory = "CoseSignTool";
        public static readonly string OptionAdditionalPluginDir = "--additional-plugin-dir";
        public static readonly string ErrorFatal = "Fatal error: {0}";

        // Log message templates
        public static readonly string LogStarting = "CoseSignTool starting with verbosity level {Verbosity}";
        public static readonly string LogExiting = "CoseSignTool exiting with code {ExitCode}";
        public static readonly string LogBanner = "{Banner}";
        public static readonly string LogBannerLogFile = "Log file: {FilePath} (mode: {Mode})";

        // Mode strings
        public static readonly string ModeAppend = "append";
        public static readonly string ModeOverwrite = "overwrite";
    }

    /// <summary>
    /// Application entry point.
    /// </summary>
    /// <param name="args">Command-line arguments.</param>
    /// <returns>Exit code indicating success or failure.</returns>
    public static int Main(string[] args)
    {
        return Run(args, console: null);
    }

    /// <summary>
    /// Application entry point with injectable console.
    /// Intended for tests to avoid any shared global console state.
    /// </summary>
    /// <param name="args">Command-line arguments.</param>
    /// <param name="console">Optional console abstraction. When null, uses SystemConsole.Instance.</param>
    /// <returns>Exit code indicating success or failure.</returns>
    public static int Run(string[] args, Abstractions.IO.IConsole? console)
    {
        ArgumentNullException.ThrowIfNull(args);

        // Use provided console or fall back to system console
        var effectiveConsole = console ?? Abstractions.Security.SystemConsole.Instance;

        ILoggerFactory? loggerFactory = null;

        try
        {
            // Parse verbosity before anything else - this modifies args to remove verbosity args
            var verbosity = LoggingConfiguration.ParseVerbosity(ref args);

            // Parse log file options - this also modifies args
            var logFileOptions = LogFileOptions.Parse(ref args);

            // Create logger factory using the console's stderr and optional log file
            loggerFactory = LoggingConfiguration.CreateLoggerFactory(verbosity, effectiveConsole, logFileOptions);

            var logger = loggerFactory.CreateLogger(ClassStrings.LoggerCategory);

            // Log startup banner
            LogStartupBanner(logger, verbosity, logFileOptions, effectiveConsole);

            // Parse for global --additional-plugin-dir option before building commands
            var additionalPluginDirs = ExtractAdditionalPluginDirectories(ref args);

            var builder = new CommandBuilder(effectiveConsole, loggerFactory);
            var rootCommand = builder.BuildRootCommand(additionalPluginDirs);

            // Ensure System.CommandLine writes help and parse errors to the injected writers.
            var systemCommandLineConsole = new TextWriterConsole(
                effectiveConsole.StandardOutput,
                effectiveConsole.StandardError);
            var result = rootCommand.Invoke(args, systemCommandLineConsole);

            logger.LogDebug(ClassStrings.LogExiting, result);

            // Map System.CommandLine exit codes to our ExitCode enum
            return result switch
            {
                0 => (int)ExitCode.Success,
                1 => (int)ExitCode.InvalidArguments, // System.CommandLine returns 1 for parse errors
                _ => (int)ExitCode.GeneralError
            };
        }
        catch (Exception ex)
        {
            try
            {
                var logger = loggerFactory?.CreateLogger(ClassStrings.LoggerCategory);
                logger?.LogCritical(ex, ClassStrings.ErrorFatal, ex.Message);
            }
            catch
            {
                // Best effort. Avoid throwing from error handling.
            }

            effectiveConsole.StandardError.WriteLine(string.Format(ClassStrings.ErrorFatal, ex.Message));
            return (int)ExitCode.GeneralError;
        }
        finally
        {
            loggerFactory?.Dispose();
        }
    }

    /// <summary>
    /// Logs the startup banner with tool version and binary hash information.
    /// The banner is written to stderr unless quiet mode is enabled.
    /// The banner is always written to log file at Debug level.
    /// </summary>
    private static void LogStartupBanner(ILogger logger, int verbosity, LogFileOptions logFileOptions, Abstractions.IO.IConsole console)
    {
        // Always log startup and banner at Debug level (appears in log file)
        logger.LogDebug(ClassStrings.LogStarting, verbosity);
        logger.LogDebug(ClassStrings.LogBanner, ApplicationInfo.GetBanner());

        if (logFileOptions.IsEnabled)
        {
            logger.LogDebug(ClassStrings.LogBannerLogFile, logFileOptions.FilePath, logFileOptions.Append ? ClassStrings.ModeAppend : ClassStrings.ModeOverwrite);
        }

        // Write banner to console stderr unless quiet mode (verbosity 0)
        if (verbosity > 0)
        {
            console.StandardError.WriteLine(ApplicationInfo.GetBanner());
        }
    }

    /// <summary>
    /// Extracts --additional-plugin-dir arguments before command parsing.
    /// </summary>
    private static List<string> ExtractAdditionalPluginDirectories(ref string[] args)
    {
        var additionalDirs = new List<string>();
        var remainingArgs = new List<string>();

        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == ClassStrings.OptionAdditionalPluginDir && i + 1 < args.Length)
            {
                additionalDirs.Add(args[i + 1]);
                i++; // Skip next arg (the directory path)
            }
            else
            {
                remainingArgs.Add(args[i]);
            }
        }

        args = remainingArgs.ToArray();
        return additionalDirs;
    }

    /// <summary>
    /// Adapter from TextWriter to System.CommandLine.IConsole for help and error output.
    /// </summary>
    private sealed class TextWriterConsole : System.CommandLine.IConsole
    {
        private sealed class Writer : IStandardStreamWriter
        {
            private readonly TextWriter _inner;

            public Writer(TextWriter inner)
            {
                _inner = inner;
            }

            public void Write(string? value)
            {
                _inner.Write(value);
            }
        }

        public TextWriterConsole(TextWriter stdout, TextWriter stderr)
        {
            ArgumentNullException.ThrowIfNull(stdout);
            ArgumentNullException.ThrowIfNull(stderr);

            Out = new Writer(stdout);
            Error = new Writer(stderr);
        }

        public IStandardStreamWriter Out { get; }

        public bool IsOutputRedirected => true;

        public IStandardStreamWriter Error { get; }

        public bool IsErrorRedirected => true;

        public bool IsInputRedirected => true;
    }
}