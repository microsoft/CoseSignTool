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

    #region public methods
    /// <summary>
    /// The entry point for the CoseSignTool application.
    /// Captures command line input and passes it to the specified command handler.
    /// </summary>
    /// <param name="args">The command line arguments.</param>
    /// <returns>An exit code indicating success or failure.</returns>
    public static int Main(string[] args)
    {
        var firstArg = args[0] ?? "help";

        try
        {
            return Enum.TryParse(firstArg, ignoreCase: true, out Verb)
                ? (int)RunCommand(Verb, args.Skip(1).ToArray())
                : (int)Usage(CoseCommand.UsageString);
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
                    return (provider is null) ? Usage(SignCommand.UsageString, badArg) : new SignCommand(provider).Run();
                case Verbs.Validate:
                    provider = CoseCommand.LoadCommandLineArgs(args, ValidateCommand.Options, out badArg);
                    return (provider is null) ? Usage(ValidateCommand.UsageString, badArg) : new ValidateCommand(provider).Run();
                case Verbs.Get:
                    provider = CoseCommand.LoadCommandLineArgs(args, GetCommand.Options, out badArg);
                    return (provider is null) ? Usage(GetCommand.UsageString, badArg) : new GetCommand(provider).Run();
                default:
                    return ExitCode.InvalidArgumentValue;
            }
        }
        catch (FileNotFoundException ex)
        {
            return Fail(ExitCode.UserSpecifiedFileNotFound, ex);
        }
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
