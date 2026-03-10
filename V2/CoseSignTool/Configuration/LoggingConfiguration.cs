// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Configuration;

using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Xml;
using CoseSignTool.Abstractions.IO;
using CoseSignTool.Output;
using Microsoft.Extensions.Logging;

/// <summary>
/// Configures logging for the CoseSignTool CLI application.
/// </summary>
public static class LoggingConfiguration
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Log filter namespaces
        public static readonly string FilterSystem = "System";
        public static readonly string FilterMicrosoft = "Microsoft";

        // Verbosity arguments
        public static readonly string ArgQuietShort = "-q";
        public static readonly string ArgQuietLong = "--quiet";
        public static readonly string ArgVerboseDouble = "-vv";
        public static readonly string ArgVerboseTriple = "-vvv";
        public static readonly string ArgVerbosityLong = "--verbosity";

        // TextWriter logger formatting
        public static readonly string LogPrefixCloseBracketSpace = "] ";
        public static readonly string LogCategorySeparator = ": ";
        public static readonly string LogTimestampFormat = "yyyy-MM-dd HH:mm:ss.fff";

        // JSON log entry property names
        public static readonly string JsonTimestamp = "timestamp";
        public static readonly string JsonLevel = "level";
        public static readonly string JsonCategory = "category";
        public static readonly string JsonMessage = "message";
        public static readonly string JsonException = "exception";

        // XML log element names
        public static readonly string XmlLogEntry = "LogEntry";
        public static readonly string XmlTimestamp = "Timestamp";
        public static readonly string XmlLevel = "Level";
        public static readonly string XmlCategory = "Category";
        public static readonly string XmlMessage = "Message";
        public static readonly string XmlException = "Exception";

        // ISO timestamp format
        public static readonly string IsoTimestampFormat = "o";
    }

    /// <summary>
    /// Creates and configures a logger factory that writes to the console's StandardError.
    /// </summary>
    /// <param name="verbosity">The verbosity level (0=quiet, 1=normal, 2=verbose, 3=debug, 4=trace).</param>
    /// <param name="console">The console to write log output to (uses StandardError).</param>
    /// <returns>A configured ILoggerFactory instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="console"/> is null.</exception>
    public static ILoggerFactory CreateLoggerFactory(int verbosity, IConsole console)
    {
        return CreateLoggerFactory(verbosity, console, logFileOptions: null);
    }

    /// <summary>
    /// Creates and configures a logger factory that writes to the console's StandardError
    /// and optionally to a log file.
    /// </summary>
    /// <param name="verbosity">The verbosity level (0=quiet, 1=normal, 2=verbose, 3=debug, 4=trace).</param>
    /// <param name="console">The console to write log output to (uses StandardError).</param>
    /// <param name="logFileOptions">Optional log file configuration. When provided and enabled, logs will also be written to the specified file.</param>
    /// <returns>A configured ILoggerFactory instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="console"/> is null.</exception>
    public static ILoggerFactory CreateLoggerFactory(int verbosity, IConsole console, LogFileOptions? logFileOptions)
    {
        ArgumentNullException.ThrowIfNull(console);

        var consoleMinLevel = verbosity switch
        {
            0 => LogLevel.None,
            1 => LogLevel.Warning,
            2 => LogLevel.Information,
            3 => LogLevel.Debug,
            _ when verbosity >= 4 => LogLevel.Trace,
            _ => LogLevel.Warning
        };

        // File logger always uses Debug level for full diagnostics
        var fileMinLevel = LogLevel.Debug;

        // Global minimum is the lower of the two (more permissive)
        var globalMinLevel = logFileOptions?.IsEnabled == true
            ? (LogLevel)Math.Min((int)consoleMinLevel, (int)fileMinLevel)
            : consoleMinLevel;

        // Ensure thread-safe output across parallel operations.
        var synchronized = TextWriter.Synchronized(console.StandardError);

        return LoggerFactory.Create(builder =>
        {
            builder.SetMinimumLevel(globalMinLevel);

            // Add console provider with console-specific minimum level
            builder.AddProvider(new TextWriterLoggerProvider(synchronized, includeTimestamp: false, ownsWriter: false, minimumLevel: consoleMinLevel));

            // Add file provider if configured (always at Debug level)
            if (logFileOptions?.IsEnabled == true)
            {
                var fileWriter = logFileOptions.OpenLogFile();
                if (fileWriter != null)
                {
                    var synchronizedFile = TextWriter.Synchronized(fileWriter);
                    builder.AddProvider(new FormattedLoggerProvider(synchronizedFile, logFileOptions.EffectiveFormat, ownsWriter: true, minimumLevel: fileMinLevel));
                }
            }

            // Filter out noise from System and Microsoft namespaces unless debug level
            if (consoleMinLevel > LogLevel.Debug)
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

    [ExcludeFromCodeCoverage]
    private sealed class TextWriterLoggerProvider : ILoggerProvider
    {
        private readonly TextWriter Writer;
        private readonly bool IncludeTimestamp;
        private readonly bool OwnsWriter;
        private readonly LogLevel MinimumLevel;

        public TextWriterLoggerProvider(TextWriter writer, bool includeTimestamp = false, bool ownsWriter = false, LogLevel minimumLevel = LogLevel.Trace)
        {
            Writer = writer;
            IncludeTimestamp = includeTimestamp;
            OwnsWriter = ownsWriter;
            MinimumLevel = minimumLevel;
        }

        public ILogger CreateLogger(string categoryName)
        {
            return new TextWriterLogger(Writer, categoryName, IncludeTimestamp, MinimumLevel);
        }

        public void Dispose()
        {
            if (OwnsWriter)
            {
                Writer.Dispose();
            }
        }
    }

    [ExcludeFromCodeCoverage]
    private sealed class TextWriterLogger : ILogger
    {
        private readonly TextWriter Writer;
        private readonly string CategoryName;
        private readonly bool IncludeTimestamp;
        private readonly LogLevel MinimumLevel;

        public TextWriterLogger(TextWriter writer, string categoryName, bool includeTimestamp = false, LogLevel minimumLevel = LogLevel.Trace)
        {
            Writer = writer;
            CategoryName = categoryName;
            IncludeTimestamp = includeTimestamp;
            MinimumLevel = minimumLevel;
        }

        public IDisposable BeginScope<TState>(TState state) where TState : notnull
        {
            return NullScope.Instance;
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return logLevel != LogLevel.None && logLevel >= MinimumLevel;
        }

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            var message = formatter(state, exception);
            if (string.IsNullOrWhiteSpace(message) && exception is null)
            {
                return;
            }

            if (IncludeTimestamp)
            {
                Writer.Write(DateTime.UtcNow.ToString(ClassStrings.LogTimestampFormat));
                Writer.Write(' ');
            }

            Writer.Write('[');
            Writer.Write(logLevel);
            Writer.Write(ClassStrings.LogPrefixCloseBracketSpace);
            Writer.Write(CategoryName);
            Writer.Write(ClassStrings.LogCategorySeparator);
            Writer.WriteLine(message);

            if (exception is not null)
            {
                Writer.WriteLine(exception);
            }
        }

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();

            public void Dispose()
            {
            }
        }
    }

    /// <summary>
    /// Logger provider that formats log entries according to the specified output format.
    /// </summary>
    [ExcludeFromCodeCoverage]
    private sealed class FormattedLoggerProvider : ILoggerProvider
    {
        private readonly TextWriter Writer;
        private readonly OutputFormat Format;
        private readonly bool OwnsWriter;
        private readonly LogLevel MinimumLevel;

        public FormattedLoggerProvider(TextWriter writer, OutputFormat format, bool ownsWriter = false, LogLevel minimumLevel = LogLevel.Trace)
        {
            Writer = writer;
            Format = format;
            OwnsWriter = ownsWriter;
            MinimumLevel = minimumLevel;
        }

        public ILogger CreateLogger(string categoryName)
        {
            return new FormattedLogger(Writer, categoryName, Format, MinimumLevel);
        }

        public void Dispose()
        {
            if (OwnsWriter)
            {
                Writer.Dispose();
            }
        }
    }

    /// <summary>
    /// Logger that formats log entries according to the specified output format.
    /// </summary>
    [ExcludeFromCodeCoverage]
    private sealed class FormattedLogger : ILogger
    {
        private readonly TextWriter Writer;
        private readonly string CategoryName;
        private readonly OutputFormat Format;
        private readonly LogLevel MinimumLevel;

        public FormattedLogger(TextWriter writer, string categoryName, OutputFormat format, LogLevel minimumLevel = LogLevel.Trace)
        {
            Writer = writer;
            CategoryName = categoryName;
            Format = format;
            MinimumLevel = minimumLevel;
        }

        public IDisposable BeginScope<TState>(TState state) where TState : notnull
        {
            return NullScope.Instance;
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return logLevel != LogLevel.None && logLevel >= MinimumLevel && Format != OutputFormat.Quiet;
        }

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            var message = formatter(state, exception);
            if (string.IsNullOrWhiteSpace(message) && exception is null)
            {
                return;
            }

            switch (Format)
            {
                case OutputFormat.Json:
                    WriteJsonEntry(logLevel, message, exception);
                    break;
                case OutputFormat.Xml:
                    WriteXmlEntry(logLevel, message, exception);
                    break;
                default:
                    WriteTextEntry(logLevel, message, exception);
                    break;
            }
        }

        private void WriteTextEntry(LogLevel logLevel, string message, Exception? exception)
        {
            Writer.Write(DateTime.UtcNow.ToString(ClassStrings.LogTimestampFormat));
            Writer.Write(' ');
            Writer.Write('[');
            Writer.Write(logLevel);
            Writer.Write(ClassStrings.LogPrefixCloseBracketSpace);
            Writer.Write(CategoryName);
            Writer.Write(ClassStrings.LogCategorySeparator);
            Writer.WriteLine(message);

            if (exception is not null)
            {
                Writer.WriteLine(exception);
            }
        }

        private void WriteJsonEntry(LogLevel logLevel, string message, Exception? exception)
        {
            using var stream = new MemoryStream();
            using var jsonWriter = new Utf8JsonWriter(stream);

            jsonWriter.WriteStartObject();
            jsonWriter.WriteString(ClassStrings.JsonTimestamp, DateTime.UtcNow.ToString(ClassStrings.IsoTimestampFormat));
            jsonWriter.WriteString(ClassStrings.JsonLevel, logLevel.ToString());
            jsonWriter.WriteString(ClassStrings.JsonCategory, CategoryName);
            jsonWriter.WriteString(ClassStrings.JsonMessage, message);
            if (exception is not null)
            {
                jsonWriter.WriteString(ClassStrings.JsonException, exception.ToString());
            }
            jsonWriter.WriteEndObject();
            jsonWriter.Flush();

            stream.Position = 0;
            using var reader = new StreamReader(stream);
            Writer.WriteLine(reader.ReadToEnd());
        }

        private void WriteXmlEntry(LogLevel logLevel, string message, Exception? exception)
        {
            using var stream = new MemoryStream();
            using var xmlWriter = XmlWriter.Create(stream, new XmlWriterSettings { OmitXmlDeclaration = true, Indent = false });

            xmlWriter.WriteStartElement(ClassStrings.XmlLogEntry);
            xmlWriter.WriteElementString(ClassStrings.XmlTimestamp, DateTime.UtcNow.ToString(ClassStrings.IsoTimestampFormat));
            xmlWriter.WriteElementString(ClassStrings.XmlLevel, logLevel.ToString());
            xmlWriter.WriteElementString(ClassStrings.XmlCategory, CategoryName);
            xmlWriter.WriteElementString(ClassStrings.XmlMessage, message);
            if (exception is not null)
            {
                xmlWriter.WriteElementString(ClassStrings.XmlException, exception.ToString());
            }
            xmlWriter.WriteEndElement();
            xmlWriter.Flush();

            stream.Position = 0;
            using var reader = new StreamReader(stream);
            Writer.WriteLine(reader.ReadToEnd());
        }

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();

            public void Dispose()
            {
            }
        }
    }
}