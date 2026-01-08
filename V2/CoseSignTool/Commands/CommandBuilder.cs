// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.CommandLine.Help;
using System.Diagnostics.CodeAnalysis;
using CoseSign1.Abstractions.Transparency;
using CoseSignTool.Abstractions;
using CoseSignTool.Commands.Builders;
using CoseSignTool.Commands.Handlers;
using CoseSignTool.Output;
using CoseSignTool.Plugins;
using Microsoft.Extensions.Logging;

namespace CoseSignTool.Commands;

/// <summary>
/// Builds the command-line interface structure using System.CommandLine.
/// </summary>
public class CommandBuilder
{
    /// <summary>
    /// String constants specific to this class.
    /// </summary>
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Root command
        public static readonly string RootDescription = string.Concat(
            "Modern CLI tool for COSE Sign1 signing and verification\n\n",
            "PIPELINE SUPPORT:\n",
            "  CoseSignTool supports Unix-style pipelines for flexible workflow integration:\n",
            "  - Read payload from stdin: omit payload argument or use '-'\n",
            "  - Write signature to stdout: use '--output -' or automatic when input is stdin\n",
            "  - Chain commands: output can feed directly into verification or encoding\n\n",
            "QUICK EXAMPLES:\n",
            "  # Sign from stdin to stdout:\n",
            "    echo 'data' | CoseSignTool sign-pfx --pfx cert.pfx > signed.cose\n\n",
            "  # Sign file, verify in pipeline:\n",
            "    CoseSignTool sign-pfx file.txt --pfx cert.pfx -o - | CoseSignTool verify -\n\n",
            "  # JSON output for scripting:\n",
            "    CoseSignTool verify signature.cose --output-format json\n\n",
            "Use 'CoseSignTool [command] --help' for detailed command-specific examples.");

        // Global options
        public static readonly string OptionOutputFormat = "--output-format";
        public static readonly string OptionOutputFormatAlias = "-f";
        public static readonly string OptionOutputFormatDescription = "Output format for command results";
        public static readonly string OutputFormatText = "text";
        public static readonly string OutputFormatJson = "json";
        public static readonly string OutputFormatXml = "xml";
        public static readonly string OutputFormatQuiet = "quiet";
        public static readonly string OptionVerbose = "--verbose";
        public static readonly string OptionVerboseDescription = "Show detailed help including all options and examples";
        public static readonly string OptionVerbosity = "--verbosity";
        public static readonly string OptionVerbosityDescription = "Set logging verbosity level (0=quiet, 1=normal, 2=verbose, 3=debug, 4=trace)";
        public static readonly string OptionVv = "-vv";
        public static readonly string OptionVvDescription = "Enable debug logging (equivalent to --verbosity 3)";
        public static readonly string OptionVvv = "-vvv";
        public static readonly string OptionVvvDescription = "Enable trace logging (equivalent to --verbosity 4)";

        // Verify command
        public static readonly string CommandVerify = "verify";
        public static readonly string VerifyDescription = string.Concat(
            "Verify a COSE Sign1 signature\n\n",
            "EXAMPLES:\n",
            "  # Basic verification (embedded signature):\n",
            "    cosesigntool verify signature.cose\n\n",
            "  # Verify detached signature (payload required):\n",
            "    cosesigntool verify signature.cose --payload document.json\n\n",
            "  # Verify indirect signature (payload required for hash match):\n",
            "    cosesigntool verify indirect.sig --payload large-file.bin\n\n",
            "  # Verify signature only (skip payload hash verification):\n",
            "    cosesigntool verify indirect.sig --signature-only\n\n",
            "  # Verify with specific trust roots:\n",
            "    cosesigntool verify signature.cose --trust-roots ca-cert.pem\n\n",
            "  # Allow self-signed certificates (dev/test):\n",
            "    cosesigntool verify signature.cose --allow-untrusted\n\n",
            "  # JSON output for scripting:\n",
            "    cosesigntool verify signature.cose -f json");
        public static readonly string ArgumentSignature = "signature";
        public static readonly string ArgumentSignatureDescription = string.Concat(
            "Path to the COSE signature file. Use '-' to read from stdin.\n",
            "  Examples:\n",
            "    signature.cose  - Read from file\n",
            "    -               - Read from stdin (for pipeline)");

        // Verify options
        public static readonly string OptionPayload = "--payload";
        public static readonly string OptionPayloadAlias = "-p";
        public static readonly string OptionPayloadDescription = string.Concat(
            "Path to payload file for detached/indirect signature verification.\n",
            "  - Detached signatures: REQUIRED (payload is part of signed data)\n",
            "  - Indirect signatures: Optional (verifies hash match if provided)");
        public static readonly string OptionSignatureOnly = "--signature-only";
        public static readonly string OptionSignatureOnlyDescription = string.Concat(
            "Verify only the cryptographic signature, skip payload verification.\n",
            "  For indirect signatures, this verifies the signature over the hash\n",
            "  envelope without checking if a payload matches the hash.");

        // Inspect command
        public static readonly string CommandInspect = "inspect";
        public static readonly string InspectDescription = string.Concat(
            "Inspect and display COSE Sign1 signature details\n\n",
            "Displays detailed information about a COSE Sign1 message including:\n",
            "  - Protected and unprotected headers\n",
            "  - Algorithm and content type\n",
            "  - Payload size and preview (if embedded)\n",
            "  - Certificate chain information\n",
            "  - Signature size\n\n",
            "EXAMPLES:\n",
            "  # Inspect a signature file:\n",
            "    cosesigntool inspect signature.cose\n\n",
            "  # Extract embedded payload to a file:\n",
            "    cosesigntool inspect signature.cose --extract-payload payload.bin\n\n",
            "  # Extract payload to stdout:\n",
            "    cosesigntool inspect signature.cose --extract-payload - > payload.bin\n\n",
            "  # JSON output for scripting:\n",
            "    cosesigntool inspect signature.cose -f json\n\n",
            "  # Inspect and filter with jq:\n",
            "    cosesigntool inspect signature.cose -f json | jq '.headers'");
        public static readonly string ArgumentFile = "file";
        public static readonly string ArgumentFileDescription = string.Concat(
            "Path to the COSE signature file to inspect. Use '-' to read from stdin.\n",
            "  Examples:\n",
            "    signature.cose  - Read from file\n",
            "    -               - Read from stdin (for pipeline)");
        public static readonly string OptionExtractPayload = "--extract-payload";
        public static readonly string OptionExtractPayloadAlias = "-x";
        public static readonly string OptionExtractPayloadDescription = string.Concat(
            "Extract embedded payload to the specified path. Use '-' for stdout.\n",
            "  Only works if the signature contains an embedded payload.");

        // Plugin loading warnings
        public static readonly string WarningPluginExtensions = "Warning: Failed to get extensions from plugin '{0}': {1}";
        public static readonly string WarningTransparencyProvider = "Warning: Failed to load transparency provider from plugin '{0}': {1}";
        public static readonly string WarningVerificationProvider = "Warning: Failed to load verification provider from plugin '{0}': {1}";
        public static readonly string WarningPluginRegister = "Warning: Failed to register plugin '{0}': {1}";
        public static readonly string WarningPluginLoad = "Warning: Failed to load plugins: {0}";
        public static readonly string WarningStackTrace = "Stack trace: {0}";
        public static readonly string WarningInnerException = "Inner exception: {0}";

        // Option names for handler lookups (without -- prefix)
        public static readonly string OptionNameOutputFormat = "output-format";
        public static readonly string OptionNameExtractPayload = "extract-payload";
        public static readonly string OptionNamePayload = "payload";
        public static readonly string OptionNameSignatureOnly = "signature-only";

        // Other
        public static readonly string PluginsDirectory = "plugins";
    }

    private readonly ILoggerFactory? LoggerFactory;
    private readonly TextWriter StandardOutput;
    private readonly TextWriter StandardError;
    private readonly Func<Stream> StandardInputProvider;

    private readonly Func<Stream> StandardOutputProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="CommandBuilder"/> class.
    /// </summary>
    /// <param name="loggerFactory">Optional logger factory for creating loggers.</param>
    /// <param name="standardOutput">Optional standard output writer (stdout). When null, uses Console.Out.</param>
    /// <param name="standardError">Optional standard error writer (stderr). When null, uses Console.Error.</param>
    /// <param name="standardInputProvider">Optional standard input provider (stdin). When null, uses Console.OpenStandardInput.</param>
    /// <param name="standardOutputProvider">Optional standard output stream provider. When null, uses Console.OpenStandardOutput.</param>
    public CommandBuilder(
        ILoggerFactory? loggerFactory = null,
        TextWriter? standardOutput = null,
        TextWriter? standardError = null,
        Func<Stream>? standardInputProvider = null,
        Func<Stream>? standardOutputProvider = null)
    {
        LoggerFactory = loggerFactory;
        StandardOutput = standardOutput ?? Console.Out;
        StandardError = standardError ?? Console.Error;
        StandardInputProvider = standardInputProvider ?? Console.OpenStandardInput;
        StandardOutputProvider = standardOutputProvider ?? Console.OpenStandardOutput;
    }

    /// <summary>
    /// Builds and returns the root command with all subcommands configured.
    /// </summary>
    /// <param name="additionalPluginDirectories">Additional plugin directories to load from.</param>
    /// <returns>The configured root command.</returns>
    public RootCommand BuildRootCommand(IEnumerable<string>? additionalPluginDirectories = null)
    {
        var rootCommand = new RootCommand(ClassStrings.RootDescription);

        // Add global options
        var outputFormatOption = new Option<OutputFormat>(
            name: ClassStrings.OptionOutputFormat,
            getDefaultValue: () => OutputFormat.Text,
            description: ClassStrings.OptionOutputFormatDescription);
        outputFormatOption.AddAlias(ClassStrings.OptionOutputFormatAlias);
        outputFormatOption.FromAmong(
            ClassStrings.OutputFormatText,
            ClassStrings.OutputFormatJson,
            ClassStrings.OutputFormatXml,
            ClassStrings.OutputFormatQuiet);

        var verboseHelpOption = new Option<bool>(
            name: ClassStrings.OptionVerbose,
            description: ClassStrings.OptionVerboseDescription);

        // Add logging verbosity options (these are parsed/stripped before System.CommandLine,
        // but we add them so they appear in help)
        var verbosityOption = new Option<int>(
            name: ClassStrings.OptionVerbosity,
            getDefaultValue: () => 1,
            description: ClassStrings.OptionVerbosityDescription);

        var vvOption = new Option<bool>(
            name: ClassStrings.OptionVv,
            description: ClassStrings.OptionVvDescription);

        var vvvOption = new Option<bool>(
            name: ClassStrings.OptionVvv,
            description: ClassStrings.OptionVvvDescription);

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
            loggerFactory: LoggerFactory,
            standardInputProvider: StandardInputProvider,
            standardOutputProvider: StandardOutputProvider,
            standardOutput: StandardOutput,
            standardError: StandardError);

        // NOTE: All signing commands (including sign-ephemeral) are provided by plugins.
        // The Local.Plugin provides: sign-pfx, sign-pem, sign-ephemeral, sign-cert-store
        // If no plugins are loaded, only verify and inspect commands will be available.

        // Add built-in verify and inspect commands with verification providers
        rootCommand.AddCommand(BuildVerifyCommand(verificationProviders));
        rootCommand.AddCommand(BuildInspectCommand());

        return rootCommand;
    }

    /// <summary>
    /// Loads plugins and registers their commands.
    /// </summary>
    private void LoadPlugins(
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
            var pluginDir = Path.Combine(executableDir, ClassStrings.PluginsDirectory);

            if (!Directory.Exists(pluginDir) && (additionalPluginDirectories == null || !additionalPluginDirectories.Any()))
            {
                // No plugins directory and no additional directories - silently continue
                return;
            }

            var loader = new PluginLoader();
            loader.StandardError = StandardError;
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
                    StandardError.WriteLine(string.Format(ClassStrings.WarningPluginExtensions, plugin.Name, ex.Message));
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
                    StandardError.WriteLine(string.Format(ClassStrings.WarningTransparencyProvider, plugin.Name, ex.Message));
                }

                // Collect verification providers
                try
                {
                    verificationProvidersList.AddRange(extensions.VerificationProviders);
                }
                catch (Exception ex)
                {
                    StandardError.WriteLine(string.Format(ClassStrings.WarningVerificationProvider, plugin.Name, ex.Message));
                }
            }

            transparencyProviders = transparencyProvidersList;
            verificationProviders = verificationProvidersList.OrderBy(p => p.Priority).ToList();

            // Create signing command builder with transparency providers
            var signingCommandBuilder = new SigningCommandBuilder(
                transparencyProviders: transparencyProviders.Count > 0 ? transparencyProviders : null,
                standardInputProvider: StandardInputProvider,
                standardOutputProvider: StandardOutputProvider,
                standardOutput: StandardOutput,
                standardError: StandardError);

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
                    StandardError.WriteLine(string.Format(ClassStrings.WarningPluginRegister, plugin.Name, ex.Message));
                }
            }
        }
        catch (Exception ex)
        {
            StandardError.WriteLine(string.Format(ClassStrings.WarningPluginLoad, ex.Message));
            StandardError.WriteLine(string.Format(ClassStrings.WarningStackTrace, ex.StackTrace));
            if (ex.InnerException != null)
            {
                StandardError.WriteLine(string.Format(ClassStrings.WarningInnerException, ex.InnerException.Message));
            }
        }
    }

    /// <summary>
    /// Builds the 'verify' command for validating COSE signatures.
    /// </summary>
    private Command BuildVerifyCommand(IReadOnlyList<IVerificationProvider> verificationProviders)
    {
        var command = new Command(ClassStrings.CommandVerify, ClassStrings.VerifyDescription);

        // Signature argument - accepts file path or '-' for stdin
        var signatureArgument = new Argument<string?>(
            name: ClassStrings.ArgumentSignature,
            description: ClassStrings.ArgumentSignatureDescription,
            getDefaultValue: () => null)
        {
            Arity = ArgumentArity.ZeroOrOne
        };
        command.AddArgument(signatureArgument);

        // Payload option for detached/indirect signatures
        var payloadOption = new Option<FileInfo?>(
            name: ClassStrings.OptionPayload,
            description: ClassStrings.OptionPayloadDescription);
        payloadOption.AddAlias(ClassStrings.OptionPayloadAlias);
        command.AddOption(payloadOption);

        // Signature-only option for indirect signatures
        var signatureOnlyOption = new Option<bool>(
            name: ClassStrings.OptionSignatureOnly,
            description: ClassStrings.OptionSignatureOnlyDescription);
        command.AddOption(signatureOnlyOption);

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
                if (option.Name == ClassStrings.OptionNameOutputFormat)
                {
                    var formatValue = context.ParseResult.GetValueForOption(option);
                    if (formatValue != null && Enum.TryParse<OutputFormat>(formatValue.ToString(), true, out var parsed))
                    {
                        outputFormat = parsed;
                    }
                    break;
                }
            }

            // Get payload and signature-only options
            FileInfo? payloadFile = null;
            bool signatureOnly = false;
            foreach (var opt in context.ParseResult.CommandResult.Command.Options)
            {
                if (opt.Name == ClassStrings.OptionNamePayload)
                {
                    payloadFile = context.ParseResult.GetValueForOption(opt) as FileInfo;
                }
                else if (opt.Name == ClassStrings.OptionNameSignatureOnly)
                {
                    var value = context.ParseResult.GetValueForOption(opt);
                    signatureOnly = value is bool b && b;
                }
            }

            var formatter = OutputFormatterFactory.Create(outputFormat, StandardOutput, StandardError);
            var handler = new VerifyCommandHandler(formatter, verificationProviders, StandardInputProvider);
            var exitCode = await handler.HandleAsync(context, payloadFile, signatureOnly);
            context.ExitCode = exitCode;
        });

        return command;
    }

    /// <summary>
    /// Builds the 'inspect' command for examining COSE signatures.
    /// </summary>
    private Command BuildInspectCommand()
    {
        var command = new Command(ClassStrings.CommandInspect, ClassStrings.InspectDescription);

        // File argument - accepts file path or '-' for stdin
        var fileArgument = new Argument<string?>(
            name: ClassStrings.ArgumentFile,
            description: ClassStrings.ArgumentFileDescription,
            getDefaultValue: () => null)
        {
            Arity = ArgumentArity.ZeroOrOne
        };
        command.AddArgument(fileArgument);

        // Extract payload option
        var extractPayloadOption = new Option<string?>(
            name: ClassStrings.OptionExtractPayload,
            description: ClassStrings.OptionExtractPayloadDescription);
        extractPayloadOption.AddAlias(ClassStrings.OptionExtractPayloadAlias);
        command.AddOption(extractPayloadOption);

        // Set handler
        command.SetHandler(async (context) =>
        {
            // Get global output format option
            var outputFormat = OutputFormat.Text; // default
            foreach (var option in context.ParseResult.RootCommandResult.Command.Options)
            {
                if (option.Name == ClassStrings.OptionNameOutputFormat)
                {
                    var formatValue = context.ParseResult.GetValueForOption(option);
                    if (formatValue != null && Enum.TryParse<OutputFormat>(formatValue.ToString(), true, out var parsed))
                    {
                        outputFormat = parsed;
                    }
                    break;
                }
            }

            // Get extract-payload option
            string? extractPayload = null;
            foreach (var opt in context.ParseResult.CommandResult.Command.Options)
            {
                if (opt.Name == ClassStrings.OptionNameExtractPayload)
                {
                    extractPayload = context.ParseResult.GetValueForOption(opt) as string;
                    break;
                }
            }

            var formatter = OutputFormatterFactory.Create(outputFormat, StandardOutput, StandardError);
            var handler = new InspectCommandHandler(formatter, StandardInputProvider);
            var exitCode = await handler.HandleAsync(context, extractPayload);
            context.ExitCode = exitCode;
        });

        return command;
    }
}