// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests;

using CoseSignTool.Abstractions;
using CoseSignTool.Abstractions.IO;
using CoseSignTool.Commands;
using CoseSignTool.Commands.Builders;
using CoseSignTool.Commands.Handlers;
using CoseSignTool.Output;

/// <summary>
/// Test implementation of IConsole that uses MemoryStreams and StringWriters.
/// Provides a fully isolated console for unit testing without stdin blocking.
/// </summary>
public sealed class TestConsole : IConsole
{
    private readonly MemoryStream _stdin;
    private readonly StringWriter _stdout;
    private readonly StringWriter _stderr;
    private bool _disposed;

    /// <summary>
    /// Creates a TestConsole with empty stdin.
    /// </summary>
    public TestConsole() : this(Array.Empty<byte>())
    {
    }

    /// <summary>
    /// Creates a TestConsole with the specified stdin content.
    /// </summary>
    /// <param name="stdinContent">Content to provide on stdin.</param>
    public TestConsole(byte[] stdinContent)
    {
        _stdin = new MemoryStream(stdinContent);
        _stdout = new StringWriter();
        _stderr = new StringWriter();
    }

    /// <inheritdoc />
    public Stream StandardInput => _stdin;

    /// <inheritdoc />
    public TextWriter StandardOutput => _stdout;

    /// <inheritdoc />
    public TextWriter StandardError => _stderr;

    /// <inheritdoc />
    public Func<Stream> StandardOutputStreamProvider => () => new MemoryStream();

    /// <inheritdoc />
    public Func<Stream> StandardErrorStreamProvider => () => new MemoryStream();

    /// <inheritdoc />
    public bool IsInputRedirected => true;

    /// <inheritdoc />
    public bool IsUserInteractive => false;

    /// <inheritdoc />
    public ConsoleKeyInfo ReadKey(bool intercept) => default;

    /// <inheritdoc />
    public string? ReadLine() => null;

    /// <inheritdoc />
    public void Write(string? value) => _stdout.Write(value);

    /// <inheritdoc />
    public void WriteLine() => _stdout.WriteLine();

    /// <inheritdoc />
    public void WriteLine(string? value) => _stdout.WriteLine(value);

    /// <inheritdoc />
    public void WriteError(string? value) => _stderr.Write(value);

    /// <inheritdoc />
    public void WriteErrorLine(string? value = null) => _stderr.WriteLine(value);

    /// <summary>
    /// Gets the captured stdout content.
    /// </summary>
    public string GetStdout() => _stdout.ToString();

    /// <summary>
    /// Gets the captured stderr content.
    /// </summary>
    public string GetStderr() => _stderr.ToString();

    /// <inheritdoc />
    public void Dispose()
    {
        if (!_disposed)
        {
            _stdin.Dispose();
            _stdout.Dispose();
            _stderr.Dispose();
            _disposed = true;
        }
    }

    #region Factory Methods for Common Test Scenarios

    /// <summary>
    /// Creates a new CommandBuilder with a TestConsole.
    /// </summary>
    public static CommandBuilder CreateCommandBuilder() => new(new TestConsole());

    /// <summary>
    /// Creates a new SigningCommandBuilder with a TestConsole.
    /// </summary>
    public static SigningCommandBuilder CreateSigningCommandBuilder() => new(new TestConsole());

    /// <summary>
    /// Creates a new VerifyCommandHandler with a TestConsole.
    /// </summary>
    public static VerifyCommandHandler CreateVerifyCommandHandler(
        IOutputFormatter? formatter = null,
        IReadOnlyList<IVerificationProvider>? verificationProviders = null)
        => new(new TestConsole(), formatter, verificationProviders);

    /// <summary>
    /// Creates a new InspectCommandHandler with a TestConsole.
    /// </summary>
    public static InspectCommandHandler CreateInspectCommandHandler(IOutputFormatter? formatter = null)
        => new(new TestConsole(), formatter);

    #endregion
}
