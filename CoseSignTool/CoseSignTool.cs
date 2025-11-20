// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool;
/// <summary>
/// Command line interface for COSE signing and validation operations.
/// </summary>
public class CoseSignTool
{
    private enum Verbs
    {
        Sign, Validate, Get, Unknown
    }

    private static Verbs Verb = Verbs.Unknown;
    private static readonly Dictionary<string, IPluginCommand> PluginCommands = new();
    internal static readonly CertificateProviderPluginManager CertificateProviderManager = new();

    #region public methods
    /// <summary>
    /// The entry point for the CoseSignTool application.
    /// Captures command line input and passes it to the specified command handler.
    /// </summary>
    /// <param name="args">The command line arguments.</param>
    /// <returns>An exit code indicating success or failure.</returns>
    public static int Main(string[] args)
    {
        // Load plugins before processing commands
        LoadPlugins();

        // Make sure we have a verb and at least one argument, and that neither of the first two arguments are help requests.
        if (args.Length == 0 || IsNullOrHelp(args[0]))
        {
            return (int)Usage(GetUsageString());
        }

        // Check if it's a plugin command first
        if (PluginCommands.TryGetValue(args[0].ToLowerInvariant(), out IPluginCommand? pluginCommand))
        {
            return (int)RunPluginCommand(pluginCommand, args.Skip(1).ToArray());
        }

        // Otherwise, try to parse as a built-in verb
        if (!Enum.TryParse(args[0], ignoreCase: true, out Verb))
        {
            return (int)Usage(GetUsageString());
        }

        if (args.Length == 1 || IsNullOrHelp(args[1]))
        {
            string usageString = Verb switch
            {
                Verbs.Sign => SignCommand.Usage,
                Verbs.Validate => ValidateCommand.Usage,
                Verbs.Get => GetCommand.Usage,
                _ => GetUsageString(),
            };

            return (int)Usage(usageString);
        }

        try
        {
            return (int)RunCommand(Verb, args.Skip(1).ToArray());
        }
        catch (Exception ex)
        {
            ExitCode code = ex switch
            {
                ArgumentNullException => ExitCode.MissingRequiredOption,
                ArgumentOutOfRangeException => ExitCode.MissingArgumentValue,
                _ => ExitCode.UnknownError,
            };

            return (int)Fail(code, ex);
        }
    }

    private static bool IsNullOrHelp(string arg) => arg is null || arg.EndsWith('?') || arg.EndsWith("help", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Loads plugins from the plugins directory and registers their commands.
    /// For security reasons, plugins are only loaded from the "plugins" subdirectory.
    /// </summary>
    private static void LoadPlugins()
    {
        try
        {
            string executablePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
            string executableDirectory = Path.GetDirectoryName(executablePath) ?? Directory.GetCurrentDirectory();
            
            // Only load plugins from the authorized "plugins" subdirectory
            string pluginsDirectory = Path.Join(executableDirectory, "plugins");

            // Load command plugins
            IEnumerable<ICoseSignToolPlugin> plugins = PluginLoader.DiscoverPlugins(pluginsDirectory);
            
            foreach (ICoseSignToolPlugin plugin in plugins)
            {
                try
                {
                    plugin.Initialize();
                    
                    foreach (IPluginCommand command in plugin.Commands)
                    {
                        string commandKey = command.Name.ToLowerInvariant();
                        if (!PluginCommands.ContainsKey(commandKey))
                        {
                            PluginCommands[commandKey] = command;
                        }
                        else
                        {
                            Console.Error.WriteLine($"Warning: Command '{command.Name}' from plugin '{plugin.Name}' conflicts with an existing command and will be ignored.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Warning: Failed to initialize plugin '{plugin.Name}': {ex.Message}");
                }
            }

            // Load certificate provider plugins
            CertificateProviderManager.DiscoverAndLoadPlugins(pluginsDirectory);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Warning: Plugin loading failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Creates a SignCommand, ValidateCommand, or GetCommand instance based on raw command line input and then runs the command.
    /// </summary>
    /// <param name="verb">The command to execute.</param>
    /// <param name="args">The command line arguments passed after the verb is specified.</param>
    /// <returns>An exit code indicating success or failure.</returns>
    private static ExitCode RunCommand(Verbs verb, string[] args)
    {
        CommandLineConfigurationProvider? provider;
        string? badArg;

        try
        {
            switch (verb)
            {
                case Verbs.Sign:
                    provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out badArg);
                    return (provider is null) ? Usage(SignCommand.Usage, badArg) : new SignCommand(provider).Run();
                case Verbs.Validate:
                    provider = CoseCommand.LoadCommandLineArgs(args, ValidateCommand.Options, out badArg);
                    return (provider is null) ? Usage(ValidateCommand.Usage, badArg) : new ValidateCommand(provider).Run();
                case Verbs.Get:
                    provider = CoseCommand.LoadCommandLineArgs(args, GetCommand.Options, out badArg);
                    return (provider is null) ? Usage(GetCommand.Usage, badArg) : new GetCommand(provider).Run();
                default:
                    return ExitCode.InvalidArgumentValue;
            }
        }
        catch (FileNotFoundException ex)
        {
            return Fail(ExitCode.UserSpecifiedFileNotFound, ex);
        }
        catch (InvalidOperationException ex)
        {
            return Fail(ExitCode.InvalidArgumentValue, ex);
        }
    }

    /// <summary>
    /// Runs a plugin command with the provided arguments.
    /// </summary>
    /// <param name="command">The plugin command to execute.</param>
    /// <param name="args">The command line arguments.</param>
    /// <returns>An exit code indicating success or failure.</returns>
    private static ExitCode RunPluginCommand(IPluginCommand command, string[] args)
    {
        CommandLineConfigurationProvider? provider;
        string? badArg;

        try
        {
            // Add universal logging options to the command's options
            Dictionary<string, string> commandOptions = new Dictionary<string, string>(command.Options)
            {
                ["--verbose"] = "verbose",
                ["-v"] = "verbose",
                ["--quiet"] = "quiet",
                ["-q"] = "quiet",
                ["--verbosity"] = "verbosity"
            };

            provider = CoseCommand.LoadCommandLineArgs(args, commandOptions, out badArg);
            if (provider is null)
            {
                return Usage(command.Usage, badArg);
            }

            // Build configuration from the provider
            IConfigurationRoot configuration = new ConfigurationBuilder()
                .AddCommandLine(args, commandOptions)
                .Build();

            // Configure logging based on command-line flags
            IPluginLogger logger = CreateLoggerFromConfiguration(configuration);
            command.SetLogger(logger);

            PluginExitCode result = command.ExecuteAsync(configuration).GetAwaiter().GetResult();
            return (ExitCode)(int)result;
        }
        catch (FileNotFoundException ex)
        {
            return Fail(ExitCode.UserSpecifiedFileNotFound, ex);
        }
        catch (Exception ex)
        {
            return Fail(ExitCode.UnknownError, ex);
        }
    }

    /// <summary>
    /// Creates a logger instance based on configuration settings.
    /// </summary>
    /// <param name="configuration">The configuration containing verbosity settings.</param>
    /// <returns>A configured logger instance.</returns>
    private static IPluginLogger CreateLoggerFromConfiguration(IConfiguration configuration)
    {
        string? verbosity = configuration["verbosity"];
        string? quiet = configuration["quiet"];
        string? verbose = configuration["verbose"];

        LogLevel logLevel = LogLevel.Normal;

        if (!string.IsNullOrEmpty(quiet) && (quiet.ToLowerInvariant() == "true" || string.IsNullOrEmpty(quiet)))
        {
            logLevel = LogLevel.Quiet;
        }
        else if (!string.IsNullOrEmpty(verbose) && (verbose.ToLowerInvariant() == "true" || string.IsNullOrEmpty(verbose)))
        {
            logLevel = LogLevel.Verbose;
        }
        else if (verbosity?.ToLowerInvariant() == "verbose")
        {
            logLevel = LogLevel.Verbose;
        }
        else if (verbosity?.ToLowerInvariant() == "quiet")
        {
            logLevel = LogLevel.Quiet;
        }

        return new ConsolePluginLogger(logLevel);
    }

    /// <summary>
    /// Gets the usage string including both built-in commands and plugin commands.
    /// </summary>
    /// <returns>The complete usage string.</returns>
    private static string GetUsageString()
    {
        StringBuilder usageBuilder = new StringBuilder();
        usageBuilder.AppendLine(CoseCommand.Usage);

        if (PluginCommands.Count > 0)
        {
            usageBuilder.AppendLine();
            usageBuilder.AppendLine("Plugin Commands:");
            foreach (KeyValuePair<string, IPluginCommand> kvp in PluginCommands.OrderBy(x => x.Key))
            {
                usageBuilder.AppendLine($"  {kvp.Key,-12} {kvp.Value.Description}");
            }
            usageBuilder.AppendLine();
            usageBuilder.AppendLine("For help with a specific plugin command, use: CoseSignTool <command> --help");
        }

        if (CertificateProviderManager.Providers.Count > 0)
        {
            usageBuilder.AppendLine();
            usageBuilder.AppendLine("Certificate Providers:");
            foreach (KeyValuePair<string, ICertificateProviderPlugin> kvp in CertificateProviderManager.Providers.OrderBy(x => x.Key))
            {
                usageBuilder.AppendLine($"  {kvp.Key,-25} {kvp.Value.Description}");
            }
            usageBuilder.AppendLine();
            usageBuilder.AppendLine("To use a certificate provider with the sign command:");
            usageBuilder.AppendLine("  CoseSignTool sign <payload> --cert-provider <provider-name> [provider-options]");
        }

        return usageBuilder.ToString();
    }

    /// <summary>
    /// Write a message to STDERR and then return an error code.
    /// </summary>
    /// <param name="errorCode">An error code representing the type of error.</param>
    /// <param name="ex">An Exception to surface data from.</param>
    /// <param name="message">An optional error message. If left blank, will print ex.Message.</param>
    /// <returns>The error code.</returns>
    public static ExitCode Fail(ExitCode errorCode, Exception? ex, string? message = null)
    {
        string text = $"COSE {Verb} failed.{Environment.NewLine}" +
            $"{(message is not null ? $"{message}{Environment.NewLine}" : string.Empty)}" +
            $"{(ex is not null ? $"{ex.Message}{Environment.NewLine}" : string.Empty)}" +
            $"{(ex?.InnerException is not null ? $"{ex.InnerException.Message}{Environment.NewLine}" : string.Empty)}";

        Console.Error.WriteLine(text);

        return errorCode;
    }

    /// <summary>
    /// Prints command line usage to the console and returns an exit code.
    /// </summary>
    /// <returns>An exit code indicating that help was requested.</returns>
    public static ExitCode Usage(string content, string? badArg = null)
    {
        string argText = badArg is null ? string.Empty : $"Error: Command line argument {badArg} was not recognized.\r\n\r\n";
        Console.WriteLine(argText + content);
        return badArg is null ? ExitCode.HelpRequested : ExitCode.UnknownArgument;
    }
    #endregion
}
