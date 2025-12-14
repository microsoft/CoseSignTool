// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.Extensions.Logging;

namespace CoseSignTool.Configuration;

/// <summary>
/// Configures logging for the CoseSignTool CLI application.
/// </summary>
public static class LoggingConfiguration
{
    internal static class ClassStrings
    {
        // Console formatter
        public static readonly string FormatterNameSimple = "simple";

        // Log filter namespaces
        public static readonly string FilterSystem = "System";
        public static readonly string FilterMicrosoft = "Microsoft";

        // Verbosity arguments
        public static readonly string ArgQuietShort = "-q";
        public static readonly string ArgQuietLong = "--quiet";
        public static readonly string ArgVerboseDouble = "-vv";
        public static readonly string ArgVerboseTriple = "-vvv";
        public static readonly string ArgVerbosityLong = "--verbosity";
    }

    /// <summary>
    /// Creates and configures a logger factory based on verbosity level.
    /// </summary>
    /// <param name="verbosity">The verbosity level (0=quiet, 1=normal, 2=verbose, 3=debug).</param>
    /// <returns>A configured ILoggerFactory instance.</returns>
    public static ILoggerFactory CreateLoggerFactory(int verbosity = 1)
    {
        var minLevel = verbosity switch
        {
            0 => LogLevel.None,
            1 => LogLevel.Warning,
            2 => LogLevel.Information,
            3 => LogLevel.Debug,
            _ when verbosity >= 4 => LogLevel.Trace,
            _ => LogLevel.Warning
        };

        return LoggerFactory.Create(builder =>
        {
            builder
                .SetMinimumLevel(minLevel)
                .AddConsole(options =>
                {
                    options.FormatterName = ClassStrings.FormatterNameSimple;
                });

            // Filter out noise from System and Microsoft namespaces unless debug level
            if (minLevel > LogLevel.Debug)
            {
                builder.AddFilter(ClassStrings.FilterSystem, LogLevel.Warning);
                builder.AddFilter(ClassStrings.FilterMicrosoft, LogLevel.Warning);
            }
        });
    }

    /// <summary>
    /// Creates a logger of the specified type using the configured factory.
    /// </summary>
    /// <typeparam name="T">The type to create the logger for.</typeparam>
    /// <param name="factory">The logger factory.</param>
    /// <returns>A logger instance.</returns>
    public static ILogger<T> CreateLogger<T>(ILoggerFactory factory)
    {
        return factory.CreateLogger<T>();
    }

    /// <summary>
    /// Parses verbosity from command line arguments and removes verbosity args from the array.
    /// Supports -v, --verbose, -vv, -vvv, --verbosity N patterns.
    /// Note: -q/--quiet is kept in args so command handlers can also see it.
    /// </summary>
    /// <param name="args">Command line arguments (will be modified to remove verbosity args).</param>
    /// <returns>The verbosity level.</returns>
    public static int ParseVerbosity(ref string[] args)
    {
        int verbosity = 1; // Default: normal
        var remainingArgs = new List<string>();

        for (int i = 0; i < args.Length; i++)
        {
            var arg = args[i];

            if (arg == ClassStrings.ArgQuietShort || arg == ClassStrings.ArgQuietLong)
            {
                verbosity = 0;
                // Keep -q/--quiet in remainingArgs so command handlers can also see it
                remainingArgs.Add(arg);
            }
            else if (arg == ClassStrings.ArgVerboseDouble)
            {
                verbosity = Math.Max(verbosity, 3);
                // Don't add to remainingArgs - strip this arg
            }
            else if (arg == ClassStrings.ArgVerboseTriple)
            {
                verbosity = Math.Max(verbosity, 4);
                // Don't add to remainingArgs - strip this arg
            }
            else if (arg == ClassStrings.ArgVerbosityLong && i + 1 < args.Length)
            {
                if (int.TryParse(args[i + 1], out int level))
                {
                    verbosity = level;
                }
                i++; // Skip next arg (the level value)
                // Don't add either arg to remainingArgs
            }
            else
            {
                // Keep all other args including -v/--verbose which System.CommandLine handles
                remainingArgs.Add(arg);
            }
        }

        args = remainingArgs.ToArray();
        return verbosity;
    }
}