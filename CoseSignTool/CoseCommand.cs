// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool;

using System;
using System.Text.RegularExpressions;

/// <summary>
/// A base class for console commands that handle COSE signatures.
/// </summary>
public abstract partial class CoseCommand
{
    [GeneratedRegex(":[^\\/]")]
    private static partial Regex PatternColonNotUri();

    /// <summary>
    /// A map of shared command line options to their abbreviated aliases.
    /// </summary>
    protected internal static readonly Dictionary<string, string> Options = new()
    {
        ["-PayloadFile"] = "PayloadFile",
        ["-payload"] = "PayloadFile",
        ["-p"] = "PayloadFile",
        ["-SignatureFile"] = "SignatureFile",
        ["-sig"] = "SignatureFile",
        ["-sf"] = "SignatureFile",
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
    /// Default filename when signing is [Payload].cose for detached or [Payload].csm for embedded.
    /// </summary>
    public FileInfo? SignatureFile { get; set; }
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
    protected static ExitCode TryGetStreamFromPipeOrFile(FileInfo? file, string optionName, out Stream? content)
    {
        content = null;
        if (file is not null)
        {
            if (!file.Exists)
            {
                return CoseSignTool.Fail(
                    ExitCode.UserSpecifiedFileNotFound, null, $"The file specified in /{optionName} was not found: {file.FullName}");
            }

            try
            {
                content = file.OpenRead();
                return content.IsNullOrEmpty()
                    ? CoseSignTool.Fail(
                    ExitCode.EmptySourceFile, null, $"The file specified in /{optionName} was empty: {file.FullName}")
                    : ExitCode.Success;
            }
            catch (Exception ex)
            {
                return CoseSignTool.Fail(
                    ExitCode.FileUnreadable, ex, $"The file specified in /{optionName} could not be read: {file.FullName}");
            }
        }

        content = Console.OpenStandardInput();
        string errorText =
            optionName == nameof(PayloadFile) ? "You must either specify a payload file or pass the payload in as a Stream."
            : "You must either specify a signature file to validate or pass the signature content in as a Stream.";
        return content.IsNullOrEmpty()
            ? CoseSignTool.Fail(ExitCode.MissingRequiredOption, null, errorText)
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
                text?.Split(",").Select(x => x.Trim().Trim('"', '(', ')', '[', ']', '{', '}')).ToArray() ??
                defaultValue ??
                [];
        }
    }

    // One liner for file existence checks
    protected static void ThrowIfMissing(string file, string message)
    {
        if (!File.Exists(file))
        {
            throw new FileNotFoundException(message, file);
        }
    }

    // Resolve boolean command line options from "-argname" to "-argname true"
    // replace /arg with -arg
    // replace "-arg:" with "-arg "
    private static string[] CleanArgs(string[] args, StringDictionary options)
    {
        List<string> argsOut = [];
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (arg.StartsWith('/'))
            {
                // Standardize on -arg
                arg = $"-{arg.AsSpan(1)}";
            }

            if (arg.StartsWith('-'))
            {
                // arg is an option name
                if (PatternColonNotUri().IsMatch(arg))  // Match if arg contains a colon not followed by a \ or / character
                {
                    // Split colon-delimited arg into name/value pair, but only on first colon in case the 
                    // value is a file path
                    argsOut.AddRange(arg.Split(':', 2, StringSplitOptions.RemoveEmptyEntries));
                    continue;
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

    private static bool IsSwitch(string s, StringDictionary options)
    {
        // replace '/' with '-', and remove ':*' for easy dict lookup
        return options.ContainsKey(Regex.Replace(s,"^/", "-").Split(":")[0]);
    }


    // Returns true if the command line contains any unrecognized arguments and outputs the first one if found.
    private static bool HasInvalidArgument(string[] args, StringDictionary options, out string? badArg)
    {
        badArg = null;
        for (int i = 0; i < args.Length; i ++)
        {
            if (args[i].StartsWith('-') && !options.ContainsKey(args[i]))
            {
                badArg = args[i];
                return true;
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

To see the options for a specific command, type 'CoseSignTool [sign | validate | get] /?'";
    #endregion
}
