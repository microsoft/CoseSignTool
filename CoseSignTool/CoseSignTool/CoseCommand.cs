// ----------------------------------------------------------------------------------------
// <copyright file="CoseCommand.cs" company="Microsoft">
//      Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ----------------------------------------------------------------------------------------

namespace CoseSignTool
{
    using Microsoft.Extensions.Configuration.CommandLine;
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// A base class for console commands that handle COSE signatures.
    /// </summary>
    public abstract class CoseCommand
    {
        // Inherited default values
        protected const string DefaultStoreName = "My";
        protected const string DefaultStoreLocation = "CurrentUser";

        /// <summary>
        /// A map of shared command line options to their abbreviated aliases.
        /// </summary>
        protected internal static Dictionary<string, string> BaseOptions = new()
        {
            ["-Payload"] = "Payload",
            ["-SignatureFile"] = "SignatureFile",
            ["-StoreName"] = "StoreName",
            ["-StoreLocation"] = "StoreLocation",
            ["-p"] = "Payload",
            ["-sf"] = "SignatureFile",
            ["-sn"] = "StoreName",
            ["-sl"] = "StoreLocation",
        };

        #region Public properties
        /// <summary>
        /// Path to the file whose content was or will be signed.
        /// </summary>
        public string Payload { get; set; }

        /// <summary>
        /// A file containing a COSE X509 signature.
        /// Detach signed signature files contain the hash of the original payload file to match against.
        /// Embed signed signature files include an encoded copy of the entire payload.
        /// Default filename when signing is [Payload].cose for detached or [Payload].csm for embedded.
        /// </summary>
        public string SignatureFile { get; set; }

        /// <summary>
        /// Optional. The name of the Windows local certificate store to look for certificates in.
        /// Default value is 'My'.
        /// Setting StoreName to a non-standard value will create or access a custom store.
        /// For standard values, see https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.storename?view=net-6.0
        /// </summary>
        public string StoreName { get; set; }

        /// <summary>
        /// Optional. The location of the Windows local certificate store to look for certificates in.
        /// Default value is StoreLocation.CurrentUser.
        /// </summary>
        public StoreLocation StoreLocation { get; set; }
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
            Payload = GetOptionString(provider, "Payload");
            SignatureFile = GetOptionString(provider, "SignatureFile");
            StoreName = GetOptionString(provider, "StoreName", DefaultStoreName);
            StoreLocation = Enum.Parse<StoreLocation>(GetOptionString(provider, "StoreLocation", DefaultStoreLocation));
        }

        #region Helper methods
        /// <summary>
        /// Loads a CommandLineConfigurationProvider with the command line options.
        /// </summary>
        /// <param name="args">The command line arguments</param>
        /// <param name="options">A dictionary of command line options to their abbreviated aliases, not including shared options.</param>
        /// <returns>A CommandLineConfigurationProvider with the command line arguments and aliases loaded.</returns>
        internal static CommandLineConfigurationProvider LoadCommandLineArgs(string[] args, Dictionary<string, string> options, out string badArg)
        {
            badArg = null;
            var mergedOptions = options.Union(BaseOptions).ToDictionary(x => x.Key, x => x.Value, StringComparer.OrdinalIgnoreCase);
            string[] fixedArgs = CleanArgs(args);
            if (fixedArgs.Length == 0 || HasInvalidArgument(fixedArgs, mergedOptions, out badArg))
            {
                return null;
            }

            CommandLineConfigurationProvider provider = new(fixedArgs, mergedOptions);
            provider.Load();
            return provider;
        }

        /// <summary>
        /// Checks whether a boolean command line option has been set.
        /// </summary>
        /// <param name="provider">A CommandLineConfigurationProvider object to make the check.</param>
        /// <param name="name">The name of the command line option.</param>
        /// <returns>True if the option was set to "true" or to no value; false if the option was not set or was set to "false".</returns>
        protected static bool GetOptionBool(CommandLineConfigurationProvider provider, string name)
        {
            if (!provider.TryGet(name, out string s))
            {
                return false;
            }
            return bool.Parse(s);
        }

        /// <summary>
        /// Checks whether a command line option has been set.
        /// </summary>
        /// <param name="provider">A CommandLineConfigurationProvider object to make the check.</param>
        /// <param name="name">The name of the command line option.</param>
        /// <param name="defaultValue">Optional. A default value to use if the option was not set. Defaults to null.</param>
        /// <returns>The value the option was set to on the command line, if any, or the default value otherwise.</returns>
        protected static string GetOptionString(CommandLineConfigurationProvider provider, string name, string defaultValue = null)
        {
            if (!provider.TryGet(name, out string s))
            {
                return defaultValue;
            }
            return s;
        }

        /// <summary>
        /// Checks whether an array type command line option has been set.
        /// </summary>
        /// <param name="provider">A CommandLineConfigurationProvider object to make the check.</param>
        /// <param name="name">The name of the command line option.</param>
        /// <param name="defaultValue">Optional. A default value to use if the option was not set. Defaults to null.</param>
        /// <returns>The comma-separated list the option was set to on the command line, split into an array, or the default value otherwise.</returns>
        protected static string[] GetOptionArray(CommandLineConfigurationProvider provider, string name, string[] defaultValue = null)
        {
            if (!provider.TryGet(name, out string s))
            {
                return defaultValue ?? Array.Empty<string>();
            }
            return s.Split(",").Select(x => x.Trim()).ToArray();
        }

        // One liner for file existence checks
        protected static void ThrowIfMissing(string file, string message)
        {
            if (!File.Exists(file))
            {
                throw new FileNotFoundException(message, file);
            }
        }

        // One liner for file existence checks
        protected static void ThrowIfNullOrEmpty(string arg, string argName)
        {
            if (string.IsNullOrEmpty(arg))
            {
                throw new ArgumentNullException($"You must specify a value for {argName}");
            }
        }

        // Resolve boolean command line options from "-argname" to "-argname true" and replace / with -.
        private static string[] CleanArgs(string[] args)
        {
            var argsOut = new List<string>();
            for (int i = 0; i < args.Length; i++)
            {
                argsOut.Add(args[i].Replace('/', '-'));
                if (IsSwitch(args[i]))
                {
                    if (i + 1 == args.Length || IsSwitch(args[i + 1]))
                    {
                        argsOut.Add("true");
                    }
                }
            }

            return argsOut.ToArray();
        }

        private static bool IsSwitch(string s) => s.StartsWith("/") || s.StartsWith("-");

        // Returns true if the command line contains any unrecognized arguments and outputs the first one if found.
        private static bool HasInvalidArgument(string[] args, Dictionary<string, string> options, out string badArg)
        {
            badArg = null;
            for (int i = 0; i < args.Length; i+=2)
            {
                if (!options.ContainsKey(args[i]))
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
        /// The first section of the command line usage. Content is generic to CoseSignTool.
        /// </summary>
        protected internal const string BaseUsageString = @$"
*** CoseSignTool ***
A tool for signing and validating Cose signatures.

Usage:
    CoseSignTool.exe [sign | validate] [options]
";

        /// <summary>
        /// The end of the usage string for when no command was specified.
        /// </summary>
        public static readonly string UsageString = $"{BaseUsageString}To see the options for a specific command, type 'CoseSignTool sign /?' or 'CoseSignTool Validate /?'";

        /// <summary>
        /// Usage string for referring to the local Certificate Store on Windows machines.
        /// </summary>
        protected internal static readonly string StoreUsageString = @"

    StoreName / sn: Optional. The name of the Windows local certificate store to look for certificates in.
        Default value is 'My'.

    StoreLocation / sl: Optional. The location of the Windows local certificate store to look for certificates in.
        Default value is 'CurrentUser'.";
        #endregion
    }
}
