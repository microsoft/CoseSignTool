// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
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
    internal static class ClassStrings
    {
        public static readonly string LoggerCategory = "CoseSignTool";
        public static readonly string OptionAdditionalPluginDir = "--additional-plugin-dir";
        public static readonly string ErrorFatal = "Fatal error: {0}";

        // Log message templates
        public static readonly string LogStarting = "CoseSignTool starting with verbosity level {Verbosity}";
        public static readonly string LogExiting = "CoseSignTool exiting with code {ExitCode}";
    }

    private static ILoggerFactory? LoggerFactoryInstance;

    /// <summary>
    /// Gets the global logger factory for the application.
    /// </summary>
    public static ILoggerFactory LoggerFactory => LoggerFactoryInstance ??= LoggingConfiguration.CreateLoggerFactory();

    /// <summary>
    /// Application entry point.
    /// </summary>
    /// <param name="args">Command-line arguments.</param>
    /// <returns>Exit code indicating success or failure.</returns>
    public static int Main(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        try
        {
            // Parse verbosity before anything else - this modifies args to remove verbosity args
            var verbosity = LoggingConfiguration.ParseVerbosity(ref args);
            LoggerFactoryInstance = LoggingConfiguration.CreateLoggerFactory(verbosity);
            var logger = LoggerFactoryInstance.CreateLogger(ClassStrings.LoggerCategory);

            logger.LogDebug(ClassStrings.LogStarting, verbosity);

            // Parse for global --additional-plugin-dir option before building commands
            var additionalPluginDirs = ExtractAdditionalPluginDirectories(ref args);

            var rootCommand = CreateRootCommand(additionalPluginDirs);
            var result = rootCommand.Invoke(args);

            logger.LogDebug(ClassStrings.LogExiting, result);

            // Map System.CommandLine exit codes to our ExitCode enum
            return result switch
            {
                0 => (int)ExitCode.Success,
                1 => (int)ExitCode.InvalidArguments, // System.CommandLine returns 1 for parse errors
                _ => (int)ExitCode.GeneralError
            };
        }
        catch (ArgumentNullException)
        {
            throw;
        }
        catch (Exception ex)
        {
            var logger = LoggerFactoryInstance?.CreateLogger(ClassStrings.LoggerCategory);
            logger?.LogCritical(ex, ClassStrings.ErrorFatal, ex.Message);
            Console.Error.WriteLine(string.Format(ClassStrings.ErrorFatal, ex.Message));
            return (int)ExitCode.GeneralError;
        }
        finally
        {
            LoggerFactoryInstance?.Dispose();
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
    /// <returns>The configured root command.</returns>
    internal static RootCommand CreateRootCommand(IEnumerable<string>? additionalPluginDirectories = null)
    {
        var builder = new CommandBuilder(LoggerFactoryInstance);
        return builder.BuildRootCommand(additionalPluginDirectories);
    }
}