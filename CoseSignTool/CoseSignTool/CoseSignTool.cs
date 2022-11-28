// ----------------------------------------------------------------------------------------
// <copyright file="CoseSignTool.cs" company="Microsoft">
//      Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ----------------------------------------------------------------------------------------

namespace CoseSignTool
{
    using CoseX509;
    using Microsoft.Extensions.Configuration.CommandLine;
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;

    /// <summary>
    /// Command line interface for COSE signing and validation operations.
    /// </summary>
    class CoseSignTool
    {
        #region public methods
        /// <summary>
        /// The entry point for the CoseSignTool application.
        /// Captures command line input and passes it to the specified command handler.
        /// </summary>
        /// <param name="args">The command line arguments.</param>
        /// <returns>An exit code indicating success or failure.</returns>
        public static int Main(string[] args)
        {
            args = args.Length > 0 ? args : new string[] {"-?"};
            string verb = args[0];
            string[] argsOut = args.Skip(1).ToArray();

            try
            {
                return verb.ToLowerInvariant() switch
                {
                    null => Usage(CoseCommand.UsageString),
                    "sign" => RunCommand(argsOut, true),
                    "validate" => RunCommand(argsOut, false),
                    _ => Usage(CoseCommand.UsageString)
                };
            }
            catch (ArgumentNullException ex)
            {
                return (int)Fail(ExitCode.MissingRequiredOption, ex);
            }
            catch (ArgumentOutOfRangeException ex)
            {
                return (int)Fail(ExitCode.InvalidArgumentValue, ex);
            }
            catch (FileNotFoundException ex)
            {
                return (int)Fail(ExitCode.FileNotFound, ex);
            }
        }

        /// <summary>
        /// Creates a SignCommand or CoseCommand instance based on raw command line input and then runs the command.
        /// </summary>
        /// <param name="args">The command line arguments after the command is specified.</param>
        /// <returns>An exit code indicating success or failure.</returns>
        public static int RunCommand(string[] args, bool isSign)
        {
            var options = isSign ? SignCommand.Options : ValidateCommand.Options;
            CommandLineConfigurationProvider provider = CoseCommand.LoadCommandLineArgs(args, options, out string badArg);
            if (provider == null)
            {
                string usage = isSign ? SignCommand.UsageString : ValidateCommand.UsageString;
                return Usage(usage, badArg);
            }

            CoseCommand command = isSign ? new SignCommand(provider) : new ValidateCommand(provider);
            return (int)command.Run();
        }

        /// <summary>
        /// Write a message to STDERR and then return an error code.
        /// </summary>
        /// <param name="errorCode">An error code representing the type of error.</param>
        /// <param name="ex">An Exception to surface data from.</param>
        /// <param name="message">An optional error message. If left blank, will print ex.Message.</param>
        /// <returns>The error code.</returns>
        public static ExitCode Fail(ExitCode errorCode, Exception ex, string message = null)
        {
            List<string> parts = new();
            var cosEx = ex as ICoseException;
            parts.Add(message);
            parts.Add(ex?.Message);
            parts.Add(cosEx?.Status?.GetJoinedStatusString());
            parts.Add(ex?.InnerException?.Message);
            parts.RemoveAll(string.IsNullOrEmpty);

            Console.Error.WriteLine(string.Join(": ", parts));

            return errorCode;
        }

        /// <summary>
        /// Prints command line usage to the console and returns an exit code.
        /// </summary>
        /// <returns>An exit code indicating that help was requested.</returns>
        public static int Usage(string content, string badArg=null)
        {
            string argText = badArg is null ? string.Empty : $"Error: Command line argument {badArg} was not recognized.\r\n\r\n";
            Console.WriteLine(argText + content);
            return (int)(badArg is null ? ExitCode.HelpRequested : ExitCode.UnknownArgument);
        }
        #endregion
    }
}
