// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Commands;

using System.CommandLine;
using System.CommandLine.Invocation;
using System.Diagnostics.CodeAnalysis;
using CoseSign1.Abstractions.Transparency;
using CoseSignTool.Abstractions;
using CoseSignTool.Commands.Builders;
using CoseSignTool.Commands.Handlers;
using CoseSignTool.Output;
using CoseSignTool.Plugins;
using Microsoft.Extensions.Logging;
using IConsole = CoseSignTool.Abstractions.IO.IConsole;

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
        // Common literals
        public const string Space = " ";

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
            "    echo 'data' | CoseSignTool sign x509 pfx --pfx cert.pfx > signed.cose\n\n",
            "  # Sign file, verify in pipeline:\n",
            "    CoseSignTool sign x509 pfx file.txt --pfx cert.pfx -o - | CoseSignTool verify x509 -\n\n",
            "  # JSON output for scripting:\n",
            "    CoseSignTool verify x509 signature.cose --output-format json\n\n",
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
            "    cosesigntool verify x509 signature.cose\n\n",
            "  # Verify detached signature (payload required):\n",
            "    cosesigntool verify x509 signature.cose --payload document.json\n\n",
            "  # Verify indirect signature (payload required for hash match):\n",
            "    cosesigntool verify x509 indirect.sig --payload large-file.bin\n\n",
            "  # Verify signature only (skip payload hash verification):\n",
            "    cosesigntool verify x509 indirect.sig --signature-only\n\n",
            "  # Verify with specific trust roots:\n",
            "    cosesigntool verify x509 signature.cose --trust-roots ca-cert.pem\n\n",
            "  # Allow self-signed certificates (dev/test):\n",
            "    cosesigntool verify x509 signature.cose --allow-untrusted\n\n",
            "  # JSON output for scripting:\n",
            "    cosesigntool verify x509 signature.cose -f json");
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

        // Sign command
        public static readonly string CommandSign = "sign";
        public static readonly string SignDescription = "Sign a payload";
        public static readonly string ArgumentPayload = "payload";
        public static readonly string ArgumentPayloadDescription = "Path to payload file to sign. Use '-' or omit to read from stdin.";

        // Sign command construction
        public const string RootDescriptionFallbackPrefix = "Sign using ";
        public const string RootDescriptionFallbackSuffix = " material";
        public const string ProviderDisplayNameSeparator = ": ";

        public static readonly string SigningMaterialProviderKeySeparator = "::";

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
    private readonly IConsole Console;

    /// <summary>
    /// Initializes a new instance of the <see cref="CommandBuilder"/> class.
    /// </summary>
    /// <param name="console">Console I/O abstraction. Required for stream access.</param>
    /// <param name="loggerFactory">Optional logger factory for creating loggers.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="console"/> is null.</exception>
    public CommandBuilder(
        IConsole console,
        ILoggerFactory? loggerFactory = null)
    {
        Console = console ?? throw new ArgumentNullException(nameof(console));
        LoggerFactory = loggerFactory;
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
            out var verificationProviders,
            out var signingRootProviders,
            out var signingMaterialProviders,
            out var signingCommandProviders);

        // Create signing command builder with transparency providers and logger factory
        var signingCommandBuilder = new SigningCommandBuilder(
            Console,
            transparencyProviders: transparencyProviders,
            loggerFactory: LoggerFactory);

        // Add built-in verify and inspect commands with verification providers
        rootCommand.AddCommand(BuildSignCommand(signingCommandBuilder, signingRootProviders, signingMaterialProviders, signingCommandProviders));
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
        out IReadOnlyList<IVerificationProvider> verificationProviders,
        out IReadOnlyList<ISigningRootProvider> signingRootProviders,
        out IReadOnlyList<ISigningMaterialProvider> signingMaterialProviders,
        out IReadOnlyList<ISigningCommandProvider> signingCommandProviders)
    {
        transparencyProviders = Array.Empty<ITransparencyProvider>();
        verificationProviders = Array.Empty<IVerificationProvider>();
        signingRootProviders = Array.Empty<ISigningRootProvider>();
        signingMaterialProviders = Array.Empty<ISigningMaterialProvider>();
        signingCommandProviders = Array.Empty<ISigningCommandProvider>();

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
            loader.StandardError = Console.StandardError;
            var loadTask = loader.LoadPluginsAsync(pluginDir, additionalPluginDirectories);
            loadTask.Wait(); // Synchronous wait since we can't make BuildRootCommand async

            // Collect providers from all plugins
            var transparencyProvidersList = new List<ITransparencyProvider>();
            var verificationProvidersList = new List<IVerificationProvider>();
            var signingRootProvidersList = new List<ISigningRootProvider>();
            var signingMaterialProvidersList = new List<ISigningMaterialProvider>();
            var signingCommandProvidersList = new List<ISigningCommandProvider>();
            var plugins = loader.Plugins;

            var pluginExtensions = new List<(IPlugin Plugin, PluginExtensions Extensions)>();

            foreach (var plugin in plugins)
            {
                // Get all extensions from this plugin
                PluginExtensions extensions;
                try
                {
                    extensions = plugin.GetExtensions();
                    pluginExtensions.Add((plugin, extensions));
                }
                catch (Exception ex)
                {
                    Console.StandardError.WriteLine(string.Format(ClassStrings.WarningPluginExtensions, plugin.Name, ex.Message));
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
                    Console.StandardError.WriteLine(string.Format(ClassStrings.WarningTransparencyProvider, plugin.Name, ex.Message));
                }

                // Collect verification providers
                try
                {
                    verificationProvidersList.AddRange(extensions.VerificationProviders);
                }
                catch (Exception ex)
                {
                    Console.StandardError.WriteLine(string.Format(ClassStrings.WarningVerificationProvider, plugin.Name, ex.Message));
                }

                // Collect signing root/material providers
                try
                {
                    signingRootProvidersList.AddRange(extensions.SigningRootProviders);
                    signingMaterialProvidersList.AddRange(extensions.SigningMaterialProviders);

                    foreach (var certificateProvider in extensions.CertificateSigningMaterialProviders)
                    {
                        signingMaterialProvidersList.Add(new CertificateSigningMaterialProviderAdapter(certificateProvider));
                    }

                    signingCommandProvidersList.AddRange(extensions.SigningCommandProviders);
                }
                catch (Exception ex)
                {
                    Console.StandardError.WriteLine(string.Format(ClassStrings.WarningPluginExtensions, plugin.Name, ex.Message));
                }
            }

            transparencyProviders = transparencyProvidersList;
            verificationProviders = verificationProvidersList.OrderBy(p => p.Priority).ToList();
            signingRootProviders = signingRootProvidersList
                .GroupBy(r => r.RootId, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First())
                .OrderBy(r => r.RootId, StringComparer.OrdinalIgnoreCase)
                .ToList();
            signingMaterialProviders = signingMaterialProvidersList
                .GroupBy(p => string.Concat(p.RootId, ClassStrings.SigningMaterialProviderKeySeparator, p.ProviderId), StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First())
                .OrderBy(p => p.Priority)
                .ThenBy(p => p.ProviderId, StringComparer.OrdinalIgnoreCase)
                .ToList();

            signingCommandProviders = signingCommandProvidersList
                .GroupBy(p => p.CommandName, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First())
                .OrderBy(p => p.CommandName, StringComparer.OrdinalIgnoreCase)
                .ToList();

            // Register all loaded plugins
            foreach (var (plugin, extensions) in pluginExtensions)
            {
                try
                {
                    // Register other commands directly (verify, utilities, etc.)
                    plugin.RegisterCommands(rootCommand);
                }
                catch (Exception ex)
                {
                    Console.StandardError.WriteLine(string.Format(ClassStrings.WarningPluginRegister, plugin.Name, ex.Message));
                }
            }
        }
        catch (Exception ex)
        {
            Console.StandardError.WriteLine(string.Format(ClassStrings.WarningPluginLoad, ex.Message));
            Console.StandardError.WriteLine(string.Format(ClassStrings.WarningStackTrace, ex.StackTrace));
            if (ex.InnerException != null)
            {
                Console.StandardError.WriteLine(string.Format(ClassStrings.WarningInnerException, ex.InnerException.Message));
            }
        }
    }

    private sealed class CertificateSigningMaterialProviderAdapter : ISigningMaterialProvider, ISigningMaterialProviderWithAliases
    {
        private readonly ICertificateSigningMaterialProvider Inner;

        public CertificateSigningMaterialProviderAdapter(ICertificateSigningMaterialProvider inner)
        {
            Inner = inner ?? throw new ArgumentNullException(nameof(inner));
        }

        public string ProviderId => Inner.ProviderId;

        public string RootId => CertificateSigningRootIds.X509;

        public string ProviderDisplayName => Inner.ProviderDisplayName;

        public string ProviderHelpSummary => Inner.ProviderHelpSummary;

        public string CommandName => Inner.CommandName;

        public int Priority => Inner.Priority;

        public IReadOnlyList<string> Aliases => Inner.Aliases;
    }

    /// <summary>
    /// Builds the unified 'sign' command with <c>sign &lt;root&gt; &lt;provider&gt;</c> subcommands.
    /// </summary>
    private Command BuildSignCommand(
        SigningCommandBuilder signingCommandBuilder,
        IReadOnlyList<ISigningRootProvider> signingRootProviders,
        IReadOnlyList<ISigningMaterialProvider> signingMaterialProviders,
        IReadOnlyList<ISigningCommandProvider> signingCommandProviders)
    {
        ArgumentNullException.ThrowIfNull(signingCommandBuilder);
        ArgumentNullException.ThrowIfNull(signingRootProviders);
        ArgumentNullException.ThrowIfNull(signingMaterialProviders);
        ArgumentNullException.ThrowIfNull(signingCommandProviders);

        var sign = new Command(ClassStrings.CommandSign, ClassStrings.SignDescription);

        // Build a lookup from implementation command name -> provider.
        // This is internal wiring only; we do not surface these names in help output.
        var implByCommandName = signingCommandProviders
            .ToDictionary(p => p.CommandName, p => p, StringComparer.OrdinalIgnoreCase);

        // Root commands: prefer explicit roots from extensions.
        // Also allow implicit roots if a provider extends a root with no root provider.
        var rootIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var root in signingRootProviders)
        {
            rootIds.Add(root.RootId);
        }

        foreach (var provider in signingMaterialProviders)
        {
            rootIds.Add(provider.RootId);
        }

        foreach (var rootId in rootIds.OrderBy(r => r, StringComparer.OrdinalIgnoreCase))
        {
            var rootProvider = signingRootProviders.FirstOrDefault(r => string.Equals(r.RootId, rootId, StringComparison.OrdinalIgnoreCase));
            var rootDescription = rootProvider?.RootHelpSummary ?? string.Concat(ClassStrings.RootDescriptionFallbackPrefix, rootId, ClassStrings.RootDescriptionFallbackSuffix);

            var rootCommand = new Command(rootId, rootDescription);

            var providersForRoot = signingMaterialProviders
                .Where(p => string.Equals(p.RootId, rootId, StringComparison.OrdinalIgnoreCase))
                .OrderBy(p => p.Priority)
                .ThenBy(p => p.ProviderId, StringComparer.OrdinalIgnoreCase)
                .ToList();

            foreach (var materialProvider in providersForRoot)
            {
                if (!implByCommandName.TryGetValue(materialProvider.CommandName, out var implProvider))
                {
                    // Plugin wiring issue. Skip adding a broken command.
                    continue;
                }

                var cliProviderName = materialProvider.ProviderId;
                var displayCommandName = string.Concat(ClassStrings.CommandSign, ClassStrings.Space, rootId, ClassStrings.Space, cliProviderName);

                var providerCommand = signingCommandBuilder.BuildSigningCommand(
                    implProvider,
                    cliCommandName: cliProviderName,
                    displayCommandName: displayCommandName,
                    commandDescriptionPrefix: string.Concat(materialProvider.ProviderDisplayName, ClassStrings.ProviderDisplayNameSeparator, materialProvider.ProviderHelpSummary));

                if (materialProvider is ISigningMaterialProviderWithAliases withAliases)
                {
                    foreach (var alias in withAliases.Aliases)
                    {
                        if (!string.IsNullOrWhiteSpace(alias))
                        {
                            providerCommand.AddAlias(alias);
                        }
                    }
                }

                rootCommand.AddCommand(providerCommand);
            }

            sign.AddCommand(rootCommand);
        }

        return sign;
    }

    /// <summary>
    /// Builds the 'verify' command with <c>verify &lt;root&gt;</c> subcommands.
    /// </summary>
    private Command BuildVerifyCommand(IReadOnlyList<IVerificationProvider> verificationProviders)
    {
        ArgumentNullException.ThrowIfNull(verificationProviders);

        var verify = new Command(ClassStrings.CommandVerify, ClassStrings.VerifyDescription);

        static OutputFormat GetOutputFormat(InvocationContext context)
        {
            var outputFormat = OutputFormat.Text;
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

            return outputFormat;
        }

        void ConfigureVerifyExecution(Command command, IReadOnlyList<IVerificationProvider> providers)
        {
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

            foreach (var provider in providers)
            {
                provider.AddVerificationOptions(command);
            }

            command.SetHandler(async (InvocationContext context) =>
            {
                var payloadFile = context.ParseResult.GetValueForOption(payloadOption);
                var signatureOnly = context.ParseResult.GetValueForOption(signatureOnlyOption);

                var outputFormat = GetOutputFormat(context);
                var formatter = OutputFormatterFactory.Create(outputFormat, Console.StandardOutput, Console.StandardError);
                var handler = new VerifyCommandHandler(Console, formatter, providers, LoggerFactory);
                var exitCode = await handler.HandleAsync(context, payloadFile, signatureOnly);
                context.ExitCode = exitCode;
            });
        }

        Command BuildVerifyRootCommand(string rootId, string description, IReadOnlyList<IVerificationProvider> providers)
        {
            var command = new Command(rootId, description);
            ConfigureVerifyExecution(command, providers);
            return command;
        }

        // Require explicit roots:
        //   verify <root> <signature>

        var rootProviders = verificationProviders
            .OfType<IVerificationRootProvider>()
            .OrderBy(p => p.Priority)
            .ThenBy(p => p.RootId, StringComparer.OrdinalIgnoreCase)
            .ToList();

        // Roots are provided by plugins.
        // Build one verify subcommand per root: `verify <root>`.
        foreach (var rootProvider in rootProviders)
        {
            var rootId = rootProvider.RootId;

            var optionScopeRootIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { rootId };
            if (rootProvider is IVerificationRootOptionScopeProvider scopeProvider)
            {
                foreach (var additional in scopeProvider.AdditionalRootIdsForOptionScope)
                {
                    if (!string.IsNullOrWhiteSpace(additional))
                    {
                        optionScopeRootIds.Add(additional);
                    }
                }
            }

            // Avoid showing other roots' options under this root unless the root explicitly requests them.
            var providersForRoot = verificationProviders
                .Where(p => p is not IVerificationRootProvider rp
                            || optionScopeRootIds.Contains(rp.RootId))
                .ToList();

            verify.AddCommand(BuildVerifyRootCommand(rootId, rootProvider.RootHelpSummary, providersForRoot));
        }

        return verify;
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

            var formatter = OutputFormatterFactory.Create(outputFormat, Console.StandardOutput, Console.StandardError);
            var handler = new InspectCommandHandler(Console, formatter);
            var exitCode = await handler.HandleAsync(context, extractPayload);
            context.ExitCode = exitCode;
        });

        return command;
    }
}