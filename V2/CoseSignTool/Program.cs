// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.CommandLine.IO;
using System.Diagnostics.CodeAnalysis;
using CoseSignTool.Commands;
using CoseSignTool.Configuration;
using Microsoft.Extensions.Logging;

namespace CoseSignTool;

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
    }

    /// <summary>
    /// Application entry point.
    /// </summary>
    /// <param name="args">Command-line arguments.</param>
    /// <returns>Exit code indicating success or failure.</returns>
    public static int Main(string[] args)
    {
        return Run(args, standardInput: null, standardOutput: null, standardError: null);
    }

    /// <summary>
    /// Application entry point with injectable standard streams.
    /// Intended for tests to avoid any shared global console state.
    /// </summary>
    /// <param name="args">Command-line arguments.</param>
    /// <param name="standardInput">Optional standard input stream (stdin). When null, uses Console.OpenStandardInput().</param>
    /// <param name="standardOutput">Optional standard output writer (stdout). When null, uses Console.Out.</param>
    /// <param name="standardError">Optional standard error writer (stderr). When null, uses Console.Error.</param>
    /// <returns>Exit code indicating success or failure.</returns>
    public static int Run(string[] args, Stream? standardInput, TextWriter? standardOutput, TextWriter? standardError)
    {
        ArgumentNullException.ThrowIfNull(args);

        var stdout = standardOutput ?? Console.Out;
        var stderr = standardError ?? Console.Error;
        var stdinProvider = standardInput != null
            ? () => standardInput!
            : Console.OpenStandardInput;

        ILoggerFactory? loggerFactory = null;

        try
        {
            // Parse verbosity before anything else - this modifies args to remove verbosity args
            var verbosity = LoggingConfiguration.ParseVerbosity(ref args);

            // If streams were injected, avoid the built-in console logger (which writes to global System.Console)
            // and instead log to the injected stderr.
            loggerFactory = standardInput != null || standardOutput != null || standardError != null
                ? LoggingConfiguration.CreateLoggerFactory(verbosity, stderr)
                : LoggingConfiguration.CreateLoggerFactory(verbosity);

            var logger = loggerFactory.CreateLogger(ClassStrings.LoggerCategory);
            logger.LogDebug(ClassStrings.LogStarting, verbosity);

            // Parse for global --additional-plugin-dir option before building commands
            var additionalPluginDirs = ExtractAdditionalPluginDirectories(ref args);

            var rootCommand = CreateRootCommand(
                additionalPluginDirs,
                loggerFactory,
                stdout,
                stderr,
                stdinProvider);

            // Ensure System.CommandLine writes help and parse errors to the injected writers.
            var console = new TextWriterConsole(stdout, stderr, stdinProvider);
            var result = rootCommand.Invoke(args, console);

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

            stderr.WriteLine(string.Format(ClassStrings.ErrorFatal, ex.Message));
            return (int)ExitCode.GeneralError;
        }
        finally
        {
            loggerFactory?.Dispose();
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
    /// Creates and configures the root command with all subcommands.
    /// </summary>
    /// <param name="additionalPluginDirectories">Additional plugin directories to load.</param>
    /// <param name="loggerFactory">Optional logger factory for creating loggers.</param>
    /// <param name="standardOutput">Optional standard output writer (stdout). When null, uses Console.Out.</param>
    /// <param name="standardError">Optional standard error writer (stderr). When null, uses Console.Error.</param>
    /// <param name="standardInputProvider">Optional standard input provider (stdin). When null, uses Console.OpenStandardInput.</param>
    /// <returns>The configured root command.</returns>
    internal static RootCommand CreateRootCommand(
        IEnumerable<string>? additionalPluginDirectories = null,
        ILoggerFactory? loggerFactory = null,
        TextWriter? standardOutput = null,
        TextWriter? standardError = null,
        Func<Stream>? standardInputProvider = null)
    {
        var builder = new CommandBuilder(
            loggerFactory,
            standardOutput,
            standardError,
            standardInputProvider);
        return builder.BuildRootCommand(additionalPluginDirectories);
    }

    private sealed class TextWriterConsole : IConsole
    {
        private sealed class Writer : IStandardStreamWriter
        {
            private readonly TextWriter Inner;

            public Writer(TextWriter inner)
            {
                Inner = inner;
            }

            public void Write(string? value)
            {
                Inner.Write(value);
            }
        }

        public TextWriterConsole(TextWriter stdout, TextWriter stderr, Func<Stream> stdinProvider)
        {
            ArgumentNullException.ThrowIfNull(stdout);
            ArgumentNullException.ThrowIfNull(stderr);
            ArgumentNullException.ThrowIfNull(stdinProvider);

            Out = new Writer(stdout);
            Error = new Writer(stderr);
            In = new StreamReader(stdinProvider(), leaveOpen: true);
        }

        public IStandardStreamWriter Out { get; }

        public bool IsOutputRedirected => true;

        public IStandardStreamWriter Error { get; }

        public bool IsErrorRedirected => true;

        public TextReader In { get; }

        public bool IsInputRedirected => true;
    }
}