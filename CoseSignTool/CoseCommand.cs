// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool;

/// <summary>
/// A base class for console commands that handle COSE signatures.
/// </summary>
public abstract partial class CoseCommand
{
    [GeneratedRegex("^/")]
    private static partial Regex PatternStartingSlash();

    // Matches a colon in the OPTION NAME portion (after -/--/) 
    // Only matches if there's a colon followed by a non-path-separator character
    // This allows -Option:Value but not -Option:C:\path (drive letter colon)
    [GeneratedRegex(@"^-{1,2}[^:]+:(?![\\/:])")]
    private static partial Regex PatternColonDelimitedArg();

    /// <summary>
    /// A map of shared command line options to their abbreviated aliases.
    /// All options use -- prefix. Single dash (-) and forward slash (/) are converted to -- for backward compatibility.
    /// </summary>
    protected internal static readonly Dictionary<string, string> Options = new()
    {
        ["--PayloadFile"] = "PayloadFile",
        ["--payload"] = "PayloadFile",
        ["--p"] = "PayloadFile",
        ["--SignatureFile"] = "SignatureFile",
        ["--sig"] = "SignatureFile",
        ["--sf"] = "SignatureFile",
        ["--UseAdvancedStreamHandling"] = "UseAdvancedStreamHandling",
        ["--adv"] = "UseAdvancedStreamHandling",
        ["--MaxWaitTime"] = "MaxWaitTime",
        ["--wait"] = "MaxWaitTime",
        ["--FailFast"] = "FailFast",
        ["--ff"] = "FailFast",
    };

    #region Public properties
    /// <summary>
    /// Gets or sets the file whose content was or will be signed.
    /// </summary>
    public FileInfo? PayloadFile { get; set; }

    /// <summary>
    /// Specifies a file that contains or will contain a COSE X509 signature.
    /// Detach signed signature files contain the hash of the original payload file to match against.
    /// Embed signed signature files include an encoded copy of the entire payload.
    /// Default filename when signing is [Payload].cose.
    /// </summary>
    public FileInfo? SignatureFile { get; set; }

    /// <summary>
    /// If set, uses experimental stream validation techniques before loading file streams.
    /// May exceed MaxWaitTime if it detects a large file being written to.
    /// </summary>
    public bool UseAdvancedStreamHandling { get; set; } = false;

    /// <summary>
    /// The maximum number of seconds to wait for a payload or signature file to be available
    /// and not empty before loading it.
    /// </summary>
    public int MaxWaitTime { get; set; } = 30;

    /// <summary>
    /// If set, do not wait more than 100ms when checking for null or empty files and streams.
    /// </summary>
    public bool FailFast { get; set; } = false;
    #endregion

    /// <summary>
    /// Runs the main logic of the derived command.
    /// </summary>
    /// <returns>An exit code indicating success or failure.</returns>
    public abstract ExitCode Run();

    /// <summary>
    /// Sets properties based on command line option values.
    /// </summary>
    /// <param name="provider">A loaded CommandLineConfigurationProvider.</param>
    protected internal virtual void ApplyOptions(CommandLineConfigurationProvider provider)
    {
        PayloadFile = GetOptionFile(provider, nameof(PayloadFile));
        SignatureFile = GetOptionFile(provider, nameof(SignatureFile));
        UseAdvancedStreamHandling = GetOptionBool(provider, nameof(UseAdvancedStreamHandling));
        MaxWaitTime = GetOptionInt(provider, nameof(MaxWaitTime), $"{MaxWaitTime}");
        FailFast = GetOptionBool(provider, nameof(FailFast));
    }

    /// <summary>
    /// Writes the content of a ReadOnlyMemory block of bytes to the STDOUT channel.
    /// </summary>
    /// <param name="content"></param>
    protected static void WriteToStdOut(ReadOnlyMemory<byte> content)
    {
        Stream output = Console.OpenStandardOutput();
        output.Write(content.Span);
    }

    #region Helper methods
    /// <summary>
    /// Loads a CommandLineConfigurationProvider with the command line options.
    /// </summary>
    /// <param name="args">The command line arguments</param>
    /// <param name="options">A dictionary of command line options to their abbreviated aliases, not including shared options.</param>
    /// <param name="badArg">The first unrecognized argument, if any.</param>
    /// <returns>A CommandLineConfigurationProvider with the command line arguments and aliases loaded.</returns>
    protected internal static CommandLineConfigurationProvider? LoadCommandLineArgs(string[] args, Dictionary<string, string> options, out string? badArg)
    {
        badArg = null;

        // We have to copy 'options' to a StringDictionary here so we can reliably do case-insensitive comparison on user inputs.
        StringDictionary dict = [];
        options.Keys.ToList().ForEach(k => dict[k] = options[k]);

        string[] fixedArgs = CleanArgs(args, dict);
        if (HasInvalidArgument(fixedArgs, dict, out badArg))
        {
            return null;
        }

        try
        {
            CommandLineConfigurationProvider provider = new(fixedArgs, options);
            provider.Load();
            return provider;
        }
        catch (FormatException)
        {
            return null;
        }        
    }

    /// <summary>
    /// Checks the Standard Input stream for content, and if empty, reads from a file or throws an exception.
    /// </summary>
    /// <param name="file">The file to read from if the Standard Input stream is empty/</param>
    /// <param name="optionName">The name of the command line option that specifies a file to read from.</param>
    /// <param name="content">The content of the file or input stream if any.</param>
    /// <returns>An ExitCode indocating success or failure type.</returns>
    protected ExitCode TryGetStreamFromPipeOrFile(FileInfo? file, string optionName, out Stream? content)
    {
        content = null;
        int nullCheckTimeout = FailFast ? 100 : 10000;
        if (file is not null)
        {
            try
            {
                content = UseAdvancedStreamHandling ? file.GetStreamResilient(MaxWaitTime) : file.GetStreamBasic(MaxWaitTime);
                return
                    content.IsNullOrEmpty(nullCheckTimeout) ?
                        CoseSignTool.Fail(ExitCode.EmptySourceFile, null, $"The file specified in /{optionName} was empty: {file.FullName}")
                    : ExitCode.Success;
            }
            catch (FileNotFoundException ex)
            {
                return CoseSignTool.Fail(ExitCode.UserSpecifiedFileNotFound, ex, $"The file specified in /{optionName} was not found: {file.FullName}");
            }
            catch (IOException ex)
            {
                return
                    ex.Message.Contains("is empty") ? CoseSignTool.Fail(ExitCode.EmptySourceFile, ex, $"The file specified in /{optionName} was empty: {file.FullName}") :
                    ex.Message.Contains("another process") ? CoseSignTool.Fail(ExitCode.FileLocked, ex, $"The file specified in /{optionName} was in use by another process: {file.FullName}") :
                    CoseSignTool.Fail(ExitCode.FileUnreadable, ex, $"The file specified in /{optionName} could not be read: {file.FullName}");
            }
            catch (Exception ex)
            {
                return CoseSignTool.Fail(ExitCode.FileUnreadable, ex, $"The file specified in /{optionName} could not be read: {file.FullName}");
            }
        }

        content = Console.OpenStandardInput();
        string inputName = optionName == nameof(PayloadFile) ? "payload" : "signature";
        return
            content.IsNullOrEmpty(nullCheckTimeout) ? CoseSignTool.Fail(ExitCode.MissingRequiredOption, null,
                $"You must either specify a {inputName} file or pass the {inputName} content in as a Stream.")                    
            : ExitCode.Success;
    }

    /// <summary>
    /// Checks whether a boolean command line option has been set.
    /// </summary>
    /// <param name="provider">A CommandLineConfigurationProvider object to make the check.</param>
    /// <param name="name">The name of the command line option.</param>
    /// <returns>True if the option was set to "true" or to no value; false if the option was not set or was set to "false".</returns>
    protected static bool GetOptionBool(CommandLineConfigurationProvider provider, string name) =>
        provider.TryGet(name, out string? s) && bool.TryParse(s, out _);

    /// <summary>
    /// Checks whether a command line option has been set.
    /// </summary>
    /// <param name="provider">A CommandLineConfigurationProvider object to make the check.</param>
    /// <param name="name">The name of the command line option.</param>
    /// <param name="defaultValue">Optional. A default value to use if the option was not set. Defaults to null.</param>
    /// <returns>The value the option was set to on the command line, if any, or the default value otherwise.</returns>
    [return: NotNullIfNotNull(nameof(defaultValue))]
    protected static string? GetOptionString(CommandLineConfigurationProvider provider, string name, string? defaultValue = null)
    {
        bool optionFound = provider.TryGet(name, out string? s);
        return optionFound ? s : defaultValue;
    }

    /// <summary>
    /// Checks whether a command line option has been set.
    /// </summary>
    /// <param name="provider">A CommandLineConfigurationProvider object to make the check.</param>
    /// <param name="name">The name of the command line option.</param>
    /// <param name="defaultValue">A default value to use if the option was not set.</param>
    /// <returns>The value the option was set to on the command line, if any, or the default value otherwise.</returns>
    [return: NotNullIfNotNull(nameof(defaultValue))]
    protected static int GetOptionInt(CommandLineConfigurationProvider provider, string name, string defaultValue)
    {
        string value = GetOptionString(provider, name, defaultValue) ?? defaultValue;
        return int.Parse(value);
    }

    /// <summary>
    /// Checks whether a command line option has been set.
    /// </summary>
    /// <param name="provider">A CommandLineConfigurationProvider object to make the check.</param>
    /// <param name="name">The name of the command line option.</param>
    /// <param name="defaultValue">Optional. A default value to use if the option was not set. Defaults to null.</param>
    /// <returns>The value the option was set to on the command line, if any, or the default value otherwise.</returns>
    [return: NotNullIfNotNull(nameof(defaultValue))]
    protected static FileInfo? GetOptionFile(CommandLineConfigurationProvider provider, string name, string? defaultValue = null)
    {
        string? path = GetOptionString(provider, name, defaultValue);
        return string.IsNullOrEmpty(path) ? null : new FileInfo(path);
    }

    /// <summary>
    /// Checks whether an array type command line option has been set.
    /// </summary>
    /// <param name="provider">A CommandLineConfigurationProvider object to make the check.</param>
    /// <param name="name">The name of the command line option.</param>
    /// <param name="defaultValue">Optional. A default value to use if the option was not set. Defaults to null.</param>
    /// <returns>The comma-separated list the option was set to on the command line, split into an array, or the default value otherwise.</returns>
    [return: NotNullIfNotNull(nameof(defaultValue))]
    protected static string[] GetOptionArray(CommandLineConfigurationProvider provider, string name, string[]? defaultValue = null)
    {
        if (provider is null)
        {
            throw new ArgumentNullException(nameof(provider));
        }
        else
        {
            _ = provider.TryGet(name, out string? text);
            return
                text?.Split(",")
                    .Select(x => x.Trim().Trim('"', '(', ')', '[', ']', '{', '}'))
                    .Where(x => !string.IsNullOrEmpty(x))
                    .ToArray() ??
                defaultValue ??
                [];
        }
    }

    /// <summary>
    /// Checks whether a header type command line option has been set.
    /// </summary>
    /// <param name="provider">A CommandLineConfigurationProvider object to make the check.</param>
    /// <param name="name">The name of the command line option.</param>
    /// <param name="defaultValue">Optional. A default value to use if the option was not set. Defaults to null.</param>
    /// <exception cref="FileNotFoundException">The file associated with the commadn line option could not be found.</exception>
    /// <exception cref="ArgumentException">The file content could not be parsed into option headers.</exception>
    /// <returns>The comma-separated list the option was set to on the command line, split into an array, or the default value otherwise.</returns>
    [return: NotNullIfNotNull(nameof(defaultValue))]
    protected static List<CoseHeader<TypeV>>? GetOptionHeadersFromFile<TypeV>(
        CommandLineConfigurationProvider provider,
        string name,
        List<CoseHeader<TypeV>>? defaultValue = null,
        JsonConverter<string>? converter = null)
    {
        FileInfo? file = GetOptionFile(provider, name, null);

        if (file == null)
        {
            return defaultValue;
        }

        try
        {
            using StreamReader reader = new(file.FullName);
            string json = reader.ReadToEnd();
            
            JsonSerializerOptions options = new();
            if (converter != null && typeof(TypeV) == typeof(string))
            {
                options.Converters.Add(converter);
            }
            
            List<CoseHeader<TypeV>>? headers = JsonSerializer.Deserialize<List<CoseHeaderDto<TypeV>>>(json, options).ToCoseHeaders();
            return headers ?? defaultValue;
        }
        catch (Exception ex) when (ex is not FileNotFoundException && ex is not ArgumentException)
        {
            throw new InvalidOperationException($"Input file '{file.FullName}' could not be parsed. {ex.Message}");
        }
    }

    /// <summary>
    /// Checks whether a header type command line option has been set.
    /// </summary>
    /// <param name="provider">A CommandLineConfigurationProvider object to make the check.</param>
    /// <param name="name">The name of the command line option.</param>
    /// <param name="isProtected">A flag to indicate if the header is protected.</param>
    /// <param name="converter">A method to convert the header value to the required type.</param>
    /// <param name="headers">A collection of headers.</param>
    /// <returns>The comma-separated list the option was set to on the command line, split into an array, or the default value otherwise.</returns>
    protected static void GetOptionHeadersFromCommandLine<TypeV>(CommandLineConfigurationProvider provider, string name, bool isProtected, Func<string[], TypeV>? converter = null, List<CoseHeader<TypeV>>? headers = null)
    {
        string[] inputs = GetOptionArray(provider, name);

        if (inputs.Length == 0)
        {
            return;
        }

        if (headers == null)
        {
            throw new ArgumentException("Headers collection cannot be null");
        }
      
        inputs.ToList().ForEach(header => {
            string[] labelValue = header.Split("=");
            headers.Add(new CoseHeader<TypeV>(labelValue[0], converter(labelValue), isProtected));
        });
    }

    // One liner for file existence checks
    protected static void ThrowIfMissing(string file, string message)
    {
        if (!File.Exists(file))
        {
            throw new FileNotFoundException(message, file);
        }
    }

    // Normalize boolean command line options from "--argname" to "--argname true"
    // Normalize option prefixes: 
    //   /arg becomes --arg
    //   -arg becomes --arg
    //   --arg stays as --arg
    // Handle colon-delimited args like --option:value
    private static string[] CleanArgs(string[] args, StringDictionary options)
    {
        List<string> argsOut = [];
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            
            // First normalize prefix: convert / or - to --
            if (arg.StartsWith('/') || (arg.StartsWith('-') && !arg.StartsWith("--")))
            {
                arg = $"--{arg.AsSpan(1)}";
            }
            
            if (arg.StartsWith('-'))
            {
                // arg is an option name (possibly with colon-delimited value)
                // Check for colon-delimited format: -option:value or --option:value
                // But NOT for paths like -p:c:\path (where colon is followed by \)
                string withoutDashes = arg.StartsWith("--") ? arg.Substring(2) : arg.Substring(1);
                int colonIdx = withoutDashes.IndexOf(':');
                
                if (colonIdx > 0)
                {
                    // Check if the character AFTER the colon is a path separator or another colon
                    // If so, this is likely a Windows path, not a delimiter
                    int colonPosInArg = arg.IndexOf(':', arg.StartsWith("--") ? 2 : 1);
                    bool isPathColon = colonPosInArg + 1 < arg.Length && 
                                       (arg[colonPosInArg + 1] == '\\' || arg[colonPosInArg + 1] == '/' || arg[colonPosInArg + 1] == ':');
                    
                    if (!isPathColon)
                    {
                        // Split colon-delimited arg into name/value pair
                        string optName = arg.Substring(0, colonPosInArg);
                        string optValue = arg.Substring(colonPosInArg + 1);
                        argsOut.Add(optName);
                        argsOut.Add(optValue);
                        continue;
                    }
                }

                argsOut.Add(arg);
                // If the next arg is also an option name, or if this is the last, it must be a boolean flag.
                if (i + 1 == args.Length || IsSwitch(args[i + 1], options))
                {
                    argsOut.Add("true");
                }
                else
                {
                    argsOut.Add(args[i + 1]);
                    i++;
                }
            }
            else
            {
                // arg is a value
                argsOut.Add(arg);
            }
        }

        return [.. argsOut];
    }

    /// <summary>
    /// Normalizes an option name to the internal format.
    /// Converts /option and -option to --option for consistency.
    /// </summary>
    private static string NormalizeOptionName(string option)
    {
        if (option.StartsWith("--"))
        {
            return option;
        }
        else if (option.StartsWith('/') || option.StartsWith('-'))
        {
            // Convert /arg or -arg to --arg
            return $"--{option.AsSpan(1)}";
        }
        return option;
    }

    /// <summary>
    /// Determines if a string represents a short option name (1-2 letters).
    /// </summary>
    private static bool IsShortOption(string name)
    {
        return name.Length <= 2 && name.All(char.IsLetter);
    }

    private static bool IsSwitch(string s, StringDictionary options)
    {
        // Normalize and check if it's a recognized switch
        string normalized = NormalizeOptionName(s);
        return options.ContainsKey(normalized.Split(":")[0]);
    }


    // Returns true if the command line contains any unrecognized arguments and outputs the first one if found.
    private static bool HasInvalidArgument(string[] args, StringDictionary options, out string? badArg)
    {
        badArg = null;
        for (int i = 0; i < args.Length; i ++)
        {
            string arg = args[i];
            if (arg.StartsWith('-'))
            {
                // Extract just the option name (before any colon delimiter, handling Windows paths)
                string optionName = arg;
                int dashOffset = arg.StartsWith("--") ? 2 : 1;
                int colonIdx = arg.IndexOf(':', dashOffset);
                if (colonIdx > dashOffset)
                {
                    // Check if this colon is a delimiter (not part of a Windows path)
                    // A Windows path colon is followed by \ or / or another :
                    bool isDelimiter = colonIdx + 1 >= arg.Length || 
                                       (arg[colonIdx + 1] != '\\' && arg[colonIdx + 1] != '/' && arg[colonIdx + 1] != ':');
                    if (isDelimiter)
                    {
                        optionName = arg.Substring(0, colonIdx);
                    }
                }
                
                if (!options.ContainsKey(optionName))
                {
                    badArg = arg;
                    return true;
                }
            }
        }

        return false;
    }
    #endregion

    #region Usage

    /// <summary>
    /// Gets the help text for the command and merges it with the general help text for CoseSignTool.
    /// </summary>
    /// <returns>The merged help text.</returns>
    public static string Usage => $"{BaseUsageString}{UsageString}";

    /// <summary>
    /// The first section of the command line usage. Content is generic to CoseSignTool.
    /// Each line should have no more than 120 characters to avoid wrapping. Break is here:                            *V*
    /// </summary>
    protected const string BaseUsageString = @$"
*** CoseSignTool ***
A tool for signing, validating, and getting payload from Cose signatures.

Usage:
    CoseSignTool.exe [sign | validate | get] [options]
    -- OR --
    [source program] | CoseSignTool.exe [sign | validate | get] [options]
    where [source program] pipes the first required option to CoseSignTool.

Option format: All options use double-dash prefix (--option), including short aliases (--p, --sf, etc.).
    Forward slash (/option) and single-dash (-option) are also accepted for backward compatibility.
    Examples: --PayloadFile, --payload, --p, /p, -p are all equivalent.
";

    /// <summary>
    /// The end of the usage string for when no command was specified.
    /// </summary>
    protected const string UsageString = @"
Sign: Signs the specified file or piped content with a detached or embedded signature.
Validate: Validates that the specified COSE signature file or piped signature content matches the original payload and
    is signed with a valid certificate chain.
Get: Retrieves and decodes the original payload from a COSE embed signed file or piped signature, writes it to a file or
    to the console, and writes any validation errors to Standard Error.

To see the options for a specific command, type 'CoseSignTool [sign | validate | get] --help'";
    #endregion
}
