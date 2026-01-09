// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Tests.Common.IO;

using System.Diagnostics.CodeAnalysis;
using System.Text;
using CoseSignTool.Abstractions.IO;
using Microsoft.Extensions.Logging;

/// <summary>
/// Test implementation of <see cref="IConsole"/> that captures console I/O in memory streams
/// and provides controllable responses for interactive operations.
/// Each test should create its own instance to ensure complete isolation.
/// </summary>
/// <remarks>
/// This class provides:
/// - Stream-based I/O capture for stdin, stdout, stderr
/// - Configurable responses for ReadKey and ReadLine operations
/// - Logger factory creation that routes to captured stderr
/// - Assertion helpers for verifying output
/// </remarks>
public sealed class TestConsole : IConsole
{
    /// <summary>
    /// String constants specific to this class.
    /// </summary>
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ExpectedOutputContain = "Expected stdout to contain '{0}' but got:\n{1}";
        public const string ExpectedErrorContain = "Expected stderr to contain '{0}' but got:\n{1}";
        public const string ExpectedOutputEmpty = "Expected stdout to be empty but got:\n{0}";
        public const string ExpectedErrorEmpty = "Expected stderr to be empty but got:\n{0}";
        public const string ExpectedLogContain = "Expected log to contain '{0}' but got:\n{1}";
        public const string LogPrefixCloseBracketSpace = "] ";
        public const string LogCategorySeparator = ": ";
        public const string FilterSystem = "System";
        public const string FilterMicrosoft = "Microsoft";
        public const string ErrorNoKeysProgrammed = "No keys programmed. Use SetKeySequence() to configure ReadKey responses.";
        public const string ErrorNoLinesProgrammed = "No lines programmed. Use SetLineSequence() to configure ReadLine responses.";
    }

    private readonly MemoryStream _stdinStream;
    private readonly MemoryStream _stdoutStream;
    private readonly MemoryStream _stderrStream;
    private readonly StreamWriter _stdoutWriter;
    private readonly StreamWriter _stderrWriter;
    private readonly Queue<ConsoleKeyInfo> _keySequence = new();
    private readonly Queue<string?> _lineSequence = new();
    private ILoggerFactory? _loggerFactory;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="TestConsole"/> class.
    /// </summary>
    public TestConsole()
    {
        _stdinStream = new MemoryStream();
        _stdoutStream = new MemoryStream();
        _stderrStream = new MemoryStream();
        _stdoutWriter = new StreamWriter(_stdoutStream, Encoding.UTF8, leaveOpen: true) { AutoFlush = true };
        _stderrWriter = new StreamWriter(_stderrStream, Encoding.UTF8, leaveOpen: true) { AutoFlush = true };
    }

    #region Stream-based I/O

    /// <inheritdoc/>
    public Stream StandardInput => _stdinStream;

    /// <inheritdoc/>
    public TextWriter StandardOutput => _stdoutWriter;

    /// <inheritdoc/>
    public TextWriter StandardError => _stderrWriter;

    /// <inheritdoc/>
    public Func<Stream> StandardOutputStreamProvider => () => new WriteThroughStream(_stdoutStream);

    /// <inheritdoc/>
    public Func<Stream> StandardErrorStreamProvider => () => new WriteThroughStream(_stderrStream);

    #endregion

    #region Interactive Console Operations

    /// <inheritdoc/>
    public void Write(string? value) => _stdoutWriter.Write(value);

    /// <inheritdoc/>
    public void WriteLine() => _stdoutWriter.WriteLine();

    /// <inheritdoc/>
    public void WriteLine(string? value) => _stdoutWriter.WriteLine(value);

    /// <inheritdoc/>
    /// <exception cref="InvalidOperationException">No keys have been programmed. Use <see cref="SetKeySequence"/> first.</exception>
    public ConsoleKeyInfo ReadKey(bool intercept)
    {
        if (_keySequence.Count == 0)
        {
            throw new InvalidOperationException(ClassStrings.ErrorNoKeysProgrammed);
        }
        return _keySequence.Dequeue();
    }

    /// <inheritdoc/>
    /// <exception cref="InvalidOperationException">No lines have been programmed. Use <see cref="SetLineSequence"/> first.</exception>
    public string? ReadLine()
    {
        if (_lineSequence.Count == 0)
        {
            throw new InvalidOperationException(ClassStrings.ErrorNoLinesProgrammed);
        }
        return _lineSequence.Dequeue();
    }

    #endregion

    #region Console State

    /// <summary>
    /// Gets or sets a value indicating whether input is redirected.
    /// Default is true (tests typically simulate redirected input).
    /// </summary>
    public bool IsInputRedirected { get; set; } = true;

    /// <summary>
    /// Gets or sets a value indicating whether the console is user interactive.
    /// Default is false (tests typically simulate non-interactive environment).
    /// </summary>
    public bool IsUserInteractive { get; set; } = false;

    #endregion

    #region Test Setup Methods

    /// <summary>
    /// Programs a sequence of key presses for ReadKey to return.
    /// </summary>
    /// <param name="keys">The keys to return in sequence.</param>
    public void SetKeySequence(params ConsoleKeyInfo[] keys)
    {
        _keySequence.Clear();
        foreach (var key in keys)
        {
            _keySequence.Enqueue(key);
        }
    }

    /// <summary>
    /// Programs a sequence of keys from characters (convenience method).
    /// </summary>
    /// <param name="characters">Characters to return, ending with Enter.</param>
    public void SetKeySequenceFromString(string characters)
    {
        _keySequence.Clear();
        foreach (var c in characters)
        {
            _keySequence.Enqueue(new ConsoleKeyInfo(c, ConsoleKey.None, false, false, false));
        }
        _keySequence.Enqueue(new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false));
    }

    /// <summary>
    /// Programs a sequence of lines for ReadLine to return.
    /// </summary>
    /// <param name="lines">The lines to return in sequence.</param>
    public void SetLineSequence(params string?[] lines)
    {
        _lineSequence.Clear();
        foreach (var line in lines)
        {
            _lineSequence.Enqueue(line);
        }
    }

    #endregion

    #region Raw Stream Access

    /// <summary>
    /// Gets the raw stdout stream for reading binary output.
    /// </summary>
    public MemoryStream StandardOutputRaw => _stdoutStream;

    /// <summary>
    /// Gets the raw stderr stream for reading binary output.
    /// </summary>
    public MemoryStream StandardErrorRaw => _stderrStream;

    #endregion

    #region Logger Factory

    /// <summary>
    /// Creates an <see cref="ILoggerFactory"/> that routes log output to this console's stderr.
    /// </summary>
    /// <param name="minimumLevel">The minimum log level to output.</param>
    /// <returns>A logger factory configured to write to the captured stderr stream.</returns>
    public ILoggerFactory CreateLoggerFactory(LogLevel minimumLevel = LogLevel.Warning)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        // Dispose any previous logger factory
        _loggerFactory?.Dispose();

        // Create a logger factory that writes to our stderr stream (thread-safe)
        var synchronized = TextWriter.Synchronized(_stderrWriter);
        _loggerFactory = LoggerFactory.Create(builder =>
        {
            builder
                .SetMinimumLevel(minimumLevel)
                .AddProvider(new TextWriterLoggerProvider(synchronized));

            // Filter out noise from System and Microsoft namespaces unless debug level
            if (minimumLevel > LogLevel.Debug)
            {
                builder.AddFilter(ClassStrings.FilterSystem, LogLevel.Warning);
                builder.AddFilter(ClassStrings.FilterMicrosoft, LogLevel.Warning);
            }
        });

        return _loggerFactory;
    }

    /// <summary>
    /// Creates a typed logger that routes output to this console's stderr.
    /// </summary>
    /// <typeparam name="T">The type to associate with the logger category.</typeparam>
    /// <param name="minimumLevel">The minimum log level to output.</param>
    /// <returns>A logger instance for the specified type.</returns>
    public ILogger<T> CreateLogger<T>(LogLevel minimumLevel = LogLevel.Warning)
    {
        var factory = CreateLoggerFactory(minimumLevel);
        return factory.CreateLogger<T>();
    }

    #endregion

    #region Input/Output Methods

    /// <summary>
    /// Sets the stdin input from a byte array.
    /// </summary>
    /// <param name="data">The input data.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="data"/> is null.</exception>
    public void SetInput(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        ObjectDisposedException.ThrowIf(_disposed, this);

        _stdinStream.SetLength(0);
        _stdinStream.Write(data, 0, data.Length);
        _stdinStream.Position = 0;
    }

    /// <summary>
    /// Sets the stdin input from a string (UTF-8 encoded).
    /// </summary>
    /// <param name="text">The input text.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="text"/> is null.</exception>
    public void SetInput(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        SetInput(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>
    /// Gets the stdout content as a string.
    /// </summary>
    /// <returns>The stdout content.</returns>
    public string GetOutput()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _stdoutWriter.Flush();
        return Encoding.UTF8.GetString(_stdoutStream.ToArray());
    }

    /// <summary>
    /// Gets the stdout content as a byte array.
    /// Useful for testing binary output like COSE signatures.
    /// </summary>
    /// <returns>The stdout content as bytes.</returns>
    public byte[] GetOutputBytes()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _stdoutWriter.Flush();
        return _stdoutStream.ToArray();
    }

    /// <summary>
    /// Gets the stderr content as a string.
    /// This includes any log output if <see cref="CreateLoggerFactory"/> was used.
    /// </summary>
    /// <returns>The stderr content.</returns>
    public string GetError()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _stderrWriter.Flush();
        return Encoding.UTF8.GetString(_stderrStream.ToArray());
    }

    /// <summary>
    /// Gets the stderr content as a byte array.
    /// </summary>
    /// <returns>The stderr content as bytes.</returns>
    public byte[] GetErrorBytes()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _stderrWriter.Flush();
        return _stderrStream.ToArray();
    }

    /// <summary>
    /// Clears all captured output and input.
    /// </summary>
    public void Clear()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _stdinStream.SetLength(0);
        _stdinStream.Position = 0;
        _stdoutStream.SetLength(0);
        _stdoutStream.Position = 0;
        _stderrStream.SetLength(0);
        _stderrStream.Position = 0;
    }

    #endregion

    #region Assertion Methods

    /// <summary>
    /// Asserts that stdout contains the specified substring.
    /// </summary>
    /// <param name="expected">The expected substring.</param>
    /// <param name="message">Optional assertion message.</param>
    /// <exception cref="TestAssertionException">Thrown when stdout does not contain the expected substring.</exception>
    public void AssertOutputContains(string expected, string? message = null)
    {
        var output = GetOutput();
        if (!output.Contains(expected, StringComparison.Ordinal))
        {
            throw new TestAssertionException(
                message ?? string.Format(ClassStrings.ExpectedOutputContain, expected, output));
        }
    }

    /// <summary>
    /// Asserts that stderr contains the specified substring.
    /// This also checks log output if logging was configured via <see cref="CreateLoggerFactory"/>.
    /// </summary>
    /// <param name="expected">The expected substring.</param>
    /// <param name="message">Optional assertion message.</param>
    /// <exception cref="TestAssertionException">Thrown when stderr does not contain the expected substring.</exception>
    public void AssertErrorContains(string expected, string? message = null)
    {
        var error = GetError();
        if (!error.Contains(expected, StringComparison.Ordinal))
        {
            throw new TestAssertionException(
                message ?? string.Format(ClassStrings.ExpectedErrorContain, expected, error));
        }
    }

    /// <summary>
    /// Asserts that stdout is empty.
    /// </summary>
    /// <param name="message">Optional assertion message.</param>
    /// <exception cref="TestAssertionException">Thrown when stdout is not empty.</exception>
    public void AssertOutputEmpty(string? message = null)
    {
        var output = GetOutput();
        if (!string.IsNullOrEmpty(output))
        {
            throw new TestAssertionException(
                message ?? string.Format(ClassStrings.ExpectedOutputEmpty, output));
        }
    }

    /// <summary>
    /// Asserts that stderr is empty.
    /// </summary>
    /// <param name="message">Optional assertion message.</param>
    /// <exception cref="TestAssertionException">Thrown when stderr is not empty.</exception>
    public void AssertErrorEmpty(string? message = null)
    {
        var error = GetError();
        if (!string.IsNullOrEmpty(error))
        {
            throw new TestAssertionException(
                message ?? string.Format(ClassStrings.ExpectedErrorEmpty, error));
        }
    }

    /// <summary>
    /// Asserts that the log output (stderr) contains the specified substring.
    /// </summary>
    /// <param name="expected">The expected substring.</param>
    /// <param name="message">Optional assertion message.</param>
    /// <exception cref="TestAssertionException">Thrown when log output does not contain the expected substring.</exception>
    public void AssertLogContains(string expected, string? message = null)
    {
        var error = GetError();
        if (!error.Contains(expected, StringComparison.Ordinal))
        {
            throw new TestAssertionException(
                message ?? string.Format(ClassStrings.ExpectedLogContain, expected, error));
        }
    }

    #endregion

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        _loggerFactory?.Dispose();
        _stdoutWriter.Dispose();
        _stderrWriter.Dispose();
        _stdinStream.Dispose();
        _stdoutStream.Dispose();
        _stderrStream.Dispose();
    }

    /// <summary>
    /// A stream that writes through to an underlying stream without closing it.
    /// </summary>
    private sealed class WriteThroughStream : Stream
    {
        private readonly MemoryStream _inner;

        public WriteThroughStream(MemoryStream inner)
        {
            _inner = inner;
        }

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => _inner.Length;
        public override long Position
        {
            get => _inner.Position;
            set => _inner.Position = value;
        }

        public override void Flush() => _inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);

        protected override void Dispose(bool disposing)
        {
            // Don't dispose the inner stream - it's owned by TestConsoleIO
            base.Dispose(disposing);
        }
    }

    [ExcludeFromCodeCoverage]
    private sealed class TextWriterLoggerProvider : ILoggerProvider
    {
        private readonly TextWriter _writer;

        public TextWriterLoggerProvider(TextWriter writer)
        {
            _writer = writer;
        }

        public ILogger CreateLogger(string categoryName)
        {
            return new TextWriterLogger(_writer, categoryName);
        }

        public void Dispose()
        {
            // Do not dispose the underlying writer; caller owns it.
        }
    }

    [ExcludeFromCodeCoverage]
    private sealed class TextWriterLogger : ILogger
    {
        private readonly TextWriter _writer;
        private readonly string _categoryName;

        public TextWriterLogger(TextWriter writer, string categoryName)
        {
            _writer = writer;
            _categoryName = categoryName;
        }

        public IDisposable BeginScope<TState>(TState state) where TState : notnull
        {
            return NullScope.Instance;
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return logLevel != LogLevel.None;
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

            _writer.Write('[');
            _writer.Write(logLevel);
            _writer.Write(ClassStrings.LogPrefixCloseBracketSpace);
            _writer.Write(_categoryName);
            _writer.Write(ClassStrings.LogCategorySeparator);
            _writer.WriteLine(message);

            if (exception is not null)
            {
                _writer.WriteLine(exception);
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
}

/// <summary>
/// Exception thrown when a test console assertion fails.
/// </summary>
public sealed class TestAssertionException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TestAssertionException"/> class.
    /// </summary>
    /// <param name="message">The assertion failure message.</param>
    public TestAssertionException(string message) : base(message)
    {
    }
}
