// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.CommandLine.Help;
using CoseSign1.Abstractions.Transparency;
using CoseSignTool.Abstractions;
using CoseSignTool.Commands.Builders;
using CoseSignTool.Commands.Handlers;
using CoseSignTool.Commands.Providers;
using CoseSignTool.Output;
using CoseSignTool.Plugins;
using Microsoft.Extensions.Logging;

namespace CoseSignTool.Commands;

/// <summary>
/// Builds the command-line interface structure using System.CommandLine.
/// </summary>
public class CommandBuilder
{
    private readonly ILoggerFactory? LoggerFactory;

    /// <summary>
    /// Initializes a new instance of the <see cref="CommandBuilder"/> class.
    /// </summary>
    /// <param name="loggerFactory">Optional logger factory for creating loggers.</param>
    public CommandBuilder(ILoggerFactory? loggerFactory = null)
    {
        LoggerFactory = loggerFactory;
    }

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

        // Add logging verbosity options (these are parsed/stripped before System.CommandLine,
        // but we add them so they appear in help)
        var verbosityOption = new Option<int>(
            name: "--verbosity",
            getDefaultValue: () => 1,
            description: "Set logging verbosity level (0=quiet, 1=normal, 2=verbose, 3=debug, 4=trace)");

        var vvOption = new Option<bool>(
            name: "-vv",
            description: "Enable debug logging (equivalent to --verbosity 3)");

        var vvvOption = new Option<bool>(
            name: "-vvv",
            description: "Enable trace logging (equivalent to --verbosity 4)");

        rootCommand.AddGlobalOption(outputFormatOption);
        rootCommand.AddGlobalOption(verbosityOption);
        rootCommand.AddGlobalOption(vvOption);
        rootCommand.AddGlobalOption(vvvOption);
        rootCommand.Add(verboseHelpOption);

        // Customize help to support --verbose
        rootCommand.SetHandler((bool verbose) =>
        {
            // This only runs when help is requested with --verbose
            // Regular help is handled automatically by System.CommandLine
        }, verboseHelpOption);

        // Load and register plugins first to collect providers
        LoadPlugins(
            rootCommand,
            additionalPluginDirectories,
            out var transparencyProviders,
            out var verificationProviders);

        // Create signing command builder with transparency providers and logger factory
        var signingCommandBuilder = new SigningCommandBuilder(
            transparencyProviders: transparencyProviders,
            loggerFactory: LoggerFactory);

        // Add built-in ephemeral signing command using the same infrastructure as plugins
        var ephemeralProvider = new EphemeralSigningCommandProvider();
        rootCommand.AddCommand(signingCommandBuilder.BuildSigningCommand(ephemeralProvider));

        // Add built-in verify and inspect commands with verification providers
        rootCommand.AddCommand(BuildVerifyCommand(verificationProviders));
        rootCommand.AddCommand(BuildInspectCommand());

        return rootCommand;
    }

    /// <summary>
    /// Loads plugins and registers their commands.
    /// </summary>
    private static void LoadPlugins(
        RootCommand rootCommand,
        IEnumerable<string>? additionalPluginDirectories,
        out IReadOnlyList<ITransparencyProvider> transparencyProviders,
        out IReadOnlyList<IVerificationProvider> verificationProviders)
    {
        transparencyProviders = Array.Empty<ITransparencyProvider>();
        verificationProviders = Array.Empty<IVerificationProvider>();

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

            // Collect providers from all plugins
            var transparencyProvidersList = new List<ITransparencyProvider>();
            var verificationProvidersList = new List<IVerificationProvider>();
            var plugins = loader.Plugins;

            foreach (var plugin in plugins)
            {
                // Get all extensions from this plugin
                PluginExtensions extensions;
                try
                {
                    extensions = plugin.GetExtensions();
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Warning: Failed to get extensions from plugin '{plugin.Name}': {ex.Message}");
                    continue;
                }

                // Collect transparency providers
                try
                {
                    foreach (var contributor in extensions.TransparencyProviders)
                    {
                        var providerTask = contributor.CreateTransparencyProviderAsync(new Dictionary<string, object?>());
                        providerTask.Wait();
                        transparencyProvidersList.Add(providerTask.Result);
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Warning: Failed to load transparency provider from plugin '{plugin.Name}': {ex.Message}");
                }

                // Collect verification providers
                try
                {
                    verificationProvidersList.AddRange(extensions.VerificationProviders);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Warning: Failed to load verification provider from plugin '{plugin.Name}': {ex.Message}");
                }
            }

            transparencyProviders = transparencyProvidersList;
            verificationProviders = verificationProvidersList.OrderBy(p => p.Priority).ToList();

            // Create signing command builder with transparency providers
            var signingCommandBuilder = new SigningCommandBuilder(
                transparencyProviders: transparencyProviders.Count > 0 ? transparencyProviders : null);

            // Register all loaded plugins
            foreach (var plugin in plugins)
            {
                try
                {
                    var extensions = plugin.GetExtensions();

                    // Register signing commands via providers (centralized I/O, factories managed by main exe)
                    foreach (var provider in extensions.SigningCommandProviders)
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
    private static Command BuildVerifyCommand(IReadOnlyList<IVerificationProvider> verificationProviders)
    {
        var description = "Verify a COSE Sign1 signature\n\n" +
            "EXAMPLES:\n" +
            "  # Basic verification:\n" +
            "    cosesigntool verify signature.cose\n\n" +
            "  # Verify with specific trust roots:\n" +
            "    cosesigntool verify signature.cose --trust-roots ca-cert.pem\n\n" +
            "  # Allow self-signed certificates (dev/test):\n" +
            "    cosesigntool verify signature.cose --allow-untrusted\n\n" +
            "  # Verify with certificate constraints:\n" +
            "    cosesigntool verify signature.cose --subject-name \"My Company\"\n\n" +
            "  # Verify from stdin (pipeline):\n" +
            "    cat signature.cose | cosesigntool verify -\n\n" +
            "  # JSON output for scripting:\n" +
            "    cosesigntool verify signature.cose -f json";

        var command = new Command("verify", description);

        // Required signature argument
        var signatureArgument = new Argument<FileInfo>(
            "signature",
            "Path to the COSE signature file");
        command.AddArgument(signatureArgument);

        // Let each verification provider add its options
        foreach (var provider in verificationProviders)
        {
            provider.AddVerificationOptions(command);
        }

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
            var handler = new VerifyCommandHandler(formatter, verificationProviders);
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
        var description = "Inspect and display COSE Sign1 signature details\n\n" +
            "Displays detailed information about a COSE Sign1 message including:\n" +
            "  - Protected and unprotected headers\n" +
            "  - Algorithm and content type\n" +
            "  - Payload size and preview (if embedded)\n" +
            "  - Certificate chain information\n" +
            "  - Signature size\n\n" +
            "EXAMPLES:\n" +
            "  # Inspect a signature file:\n" +
            "    cosesigntool inspect signature.cose\n\n" +
            "  # JSON output for scripting:\n" +
            "    cosesigntool inspect signature.cose -f json\n\n" +
            "  # Inspect and filter with jq:\n" +
            "    cosesigntool inspect signature.cose -f json | jq '.headers'";

        var command = new Command("inspect", description);

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