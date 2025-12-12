// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Commands;
using System.CommandLine;

namespace CoseSignTool;

/// <summary>
/// Main entry point for the CoseSignTool CLI application.
/// </summary>
public static class Program
{
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
            // Parse for global --additional-plugin-dir option before building commands
            var additionalPluginDirs = ExtractAdditionalPluginDirectories(ref args);
            
            var rootCommand = CreateRootCommand(additionalPluginDirs);
            var result = rootCommand.Invoke(args);
            
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
            Console.Error.WriteLine($"Fatal error: {ex.Message}");
            return (int)ExitCode.GeneralError;
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
            if (args[i] == "--additional-plugin-dir" && i + 1 < args.Length)
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
        var builder = new CommandBuilder();
        return builder.BuildRootCommand(additionalPluginDirectories);
    }
}
