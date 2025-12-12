// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Abstractions.Transparency;
using CoseSignTool.Commands.Handlers;
using CoseSignTool.Commands.Builders;
using CoseSignTool.Commands.Providers;
using CoseSignTool.Output;
using CoseSignTool.Plugins;
using System.CommandLine;
using System.CommandLine.Help;

namespace CoseSignTool.Commands;

/// <summary>
/// Builds the command-line interface structure using System.CommandLine.
/// </summary>
public class CommandBuilder
{
    /// <summary>
    /// Builds and returns the root command with all subcommands configured.
    /// </summary>
    /// <param name="additionalPluginDirectories">Additional plugin directories to load from.</param>
    /// <returns>The configured root command.</returns>
    public RootCommand BuildRootCommand(IEnumerable<string>? additionalPluginDirectories = null)
    {
        var description = "Modern CLI tool for COSE Sign1 signing and verification\n\n" +
            "PIPELINE SUPPORT:\n" +
            "  CoseSignTool supports Unix-style pipelines for flexible workflow integration:\n" +
            "  - Read payload from stdin: omit payload argument or use '-'\n" +
            "  - Write signature to stdout: use '--output -' or automatic when input is stdin\n" +
            "  - Chain commands: output can feed directly into verification or encoding\n\n" +
            "QUICK EXAMPLES:\n" +
            "  # Sign from stdin to stdout:\n" +
            "    echo 'data' | CoseSignTool sign-pfx --pfx cert.pfx > signed.cose\n\n" +
            "  # Sign file, verify in pipeline:\n" +
            "    CoseSignTool sign-pfx file.txt --pfx cert.pfx -o - | CoseSignTool verify -\n\n" +
            "  # JSON output for scripting:\n" +
            "    CoseSignTool verify signature.cose --output-format json\n\n" +
            "Use 'CoseSignTool [command] --help' for detailed command-specific examples.";

        var rootCommand = new RootCommand(description);

        // Add global options
        var outputFormatOption = new Option<OutputFormat>(
            name: "--output-format",
            getDefaultValue: () => OutputFormat.Text,
            description: "Output format for command results");
        outputFormatOption.AddAlias("-f");
        outputFormatOption.FromAmong("text", "json", "xml", "quiet");

        var verboseHelpOption = new Option<bool>(
            name: "--verbose",
            description: "Show detailed help including all options and examples");

        rootCommand.AddGlobalOption(outputFormatOption);
        rootCommand.Add(verboseHelpOption);

        // Customize help to support --verbose
        rootCommand.SetHandler((bool verbose) =>
        {
            // This only runs when help is requested with --verbose
            // Regular help is handled automatically by System.CommandLine
        }, verboseHelpOption);

        // Load and register plugins first to collect transparency providers
        LoadPlugins(rootCommand, additionalPluginDirectories, out var transparencyProviders);

        // Create signing command builder with transparency providers
        var signingCommandBuilder = new SigningCommandBuilder(
            transparencyProviders: transparencyProviders);

        // Add built-in ephemeral signing command using the same infrastructure as plugins
        var ephemeralProvider = new EphemeralSigningCommandProvider();
        rootCommand.AddCommand(signingCommandBuilder.BuildSigningCommand(ephemeralProvider));

        // Add built-in verify and inspect commands
        rootCommand.AddCommand(BuildVerifyCommand());
        rootCommand.AddCommand(BuildInspectCommand());

        return rootCommand;
    }

    /// <summary>
    /// Loads plugins and registers their commands.
    /// </summary>
    private static void LoadPlugins(
        RootCommand rootCommand, 
        IEnumerable<string>? additionalPluginDirectories,
        out IReadOnlyList<ITransparencyProvider> transparencyProviders)
    {
        transparencyProviders = Array.Empty<ITransparencyProvider>();

        try
        {
            // Determine plugin directory (relative to executable)
            var executableDir = AppContext.BaseDirectory;
            var pluginDir = Path.Combine(executableDir, "plugins");

            if (!Directory.Exists(pluginDir) && (additionalPluginDirectories == null || !additionalPluginDirectories.Any()))
            {
                // No plugins directory and no additional directories - silently continue
                return;
            }

            var loader = new PluginLoader();
            var loadTask = loader.LoadPluginsAsync(pluginDir, additionalPluginDirectories);
            loadTask.Wait(); // Synchronous wait since we can't make BuildRootCommand async

            // Collect transparency providers from all plugins
            var providers = new List<ITransparencyProvider>();
            var plugins = loader.Plugins;

            foreach (var plugin in plugins)
            {
                try
                {
                    var contributors = plugin.GetTransparencyProviderContributors();
                    foreach (var contributor in contributors)
                    {
                        // Create transparency provider with empty options for now
                        // In the future, these could be configured via global options
                        var providerTask = contributor.CreateTransparencyProviderAsync(new Dictionary<string, object?>());
                        providerTask.Wait();
                        providers.Add(providerTask.Result);
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Warning: Failed to load transparency provider from plugin '{plugin.Name}': {ex.Message}");
                }
            }

            transparencyProviders = providers;

            // Create signing command builder with transparency providers
            var signingCommandBuilder = new SigningCommandBuilder(
                transparencyProviders: transparencyProviders.Count > 0 ? transparencyProviders : null);

            // Register all loaded plugins
            foreach (var plugin in plugins)
            {
                try
                {
                    // Register signing commands via providers (centralized I/O, factories managed by main exe)
                    var signingProviders = plugin.GetSigningCommandProviders();
                    foreach (var provider in signingProviders)
                    {
                        var signingCommand = signingCommandBuilder.BuildSigningCommand(provider);
                        rootCommand.AddCommand(signingCommand);
                    }

                    // Register other commands directly (verify, utilities, etc.)
                    plugin.RegisterCommands(rootCommand);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Warning: Failed to register plugin '{plugin.Name}': {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Warning: Failed to load plugins: {ex.Message}");
            Console.Error.WriteLine($"Stack trace: {ex.StackTrace}");
            if (ex.InnerException != null)
            {
                Console.Error.WriteLine($"Inner exception: {ex.InnerException.Message}");
            }
        }
    }

    /// <summary>
    /// Builds the 'verify' command for validating COSE signatures.
    /// </summary>
    private static Command BuildVerifyCommand()
    {
        var command = new Command("verify", "Verify a COSE Sign1 signature");

        // Required signature argument
        var signatureArgument = new Argument<FileInfo>(
            "signature",
            "Path to the COSE signature file");
        command.AddArgument(signatureArgument);

        // Set handler
        command.SetHandler(async (context) =>
        {
            // Get global output format option
            var outputFormat = OutputFormat.Text; // default
            foreach (var option in context.ParseResult.RootCommandResult.Command.Options)
            {
                if (option.Name == "output-format")
                {
                    var formatValue = context.ParseResult.GetValueForOption(option);
                    if (formatValue != null && Enum.TryParse<OutputFormat>(formatValue.ToString(), true, out var parsed))
                    {
                        outputFormat = parsed;
                    }
                    break;
                }
            }

            var formatter = OutputFormatterFactory.Create(outputFormat);
            var handler = new VerifyCommandHandler(formatter);
            var exitCode = await handler.HandleAsync(context);
            context.ExitCode = exitCode;
        });

        return command;
    }

    /// <summary>
    /// Builds the 'inspect' command for examining COSE signatures.
    /// </summary>
    private static Command BuildInspectCommand()
    {
        var command = new Command("inspect", "Inspect and display COSE Sign1 signature details");

        // Required file argument
        var fileArgument = new Argument<FileInfo>(
            "file",
            "Path to the COSE signature file to inspect");
        command.AddArgument(fileArgument);

        // Set handler
        command.SetHandler(async (context) =>
        {
            // Get global output format option
            var outputFormat = OutputFormat.Text; // default
            foreach (var option in context.ParseResult.RootCommandResult.Command.Options)
            {
                if (option.Name == "output-format")
                {
                    var formatValue = context.ParseResult.GetValueForOption(option);
                    if (formatValue != null && Enum.TryParse<OutputFormat>(formatValue.ToString(), true, out var parsed))
                    {
                        outputFormat = parsed;
                    }
                    break;
                }
            }

            var formatter = OutputFormatterFactory.Create(outputFormat);
            var handler = new InspectCommandHandler(formatter);
            var exitCode = await handler.HandleAsync(context);
            context.ExitCode = exitCode;
        });

        return command;
    }
}
