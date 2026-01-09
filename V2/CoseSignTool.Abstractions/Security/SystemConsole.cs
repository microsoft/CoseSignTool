// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions.Security;

using System.Diagnostics.CodeAnalysis;
using CoseSignTool.Abstractions.IO;

/// <summary>
/// Default implementation of <see cref="IConsole"/> that wraps the system Console.
/// </summary>
/// <remarks>
/// This is a thin wrapper with no logic - all methods delegate directly to System.Console.
/// The stdin stream is wrapped with a timeout to prevent hanging indefinitely when no
/// input is piped. It is excluded from code coverage because it cannot be meaningfully
/// tested without actual console interaction.
/// </remarks>
[ExcludeFromCodeCoverage]
public sealed class SystemConsole : IConsole
{
    /// <summary>
    /// Default timeout for stdin reads when no data is available.
    /// </summary>
    public static readonly TimeSpan DefaultStdinTimeout = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Gets the singleton instance of SystemConsole.
    /// </summary>
    public static SystemConsole Instance { get; } = new();

    private readonly Lazy<Stream> _standardInputLazy;
    private bool _disposed;

    private SystemConsole()
    {
        _standardInputLazy = new Lazy<Stream>(() =>
            new TimeoutReadStream(Console.OpenStandardInput(), DefaultStdinTimeout));
    }

    #region Stream-based I/O

    /// <inheritdoc/>
    public Stream StandardInput => _standardInputLazy.Value;

    /// <inheritdoc/>
    public TextWriter StandardOutput => Console.Out;

    /// <inheritdoc/>
    public TextWriter StandardError => Console.Error;

    /// <inheritdoc/>
    public Func<Stream> StandardOutputStreamProvider => Console.OpenStandardOutput;

    /// <inheritdoc/>
    public Func<Stream> StandardErrorStreamProvider => Console.OpenStandardError;

    #endregion

    #region Interactive Console Operations

    /// <inheritdoc/>
    public void Write(string? value) => Console.Write(value);

    /// <inheritdoc/>
    public void WriteLine() => Console.WriteLine();

    /// <inheritdoc/>
    public void WriteLine(string? value) => Console.WriteLine(value);

    /// <inheritdoc/>
    public ConsoleKeyInfo ReadKey(bool intercept) => Console.ReadKey(intercept);

    /// <inheritdoc/>
    public string? ReadLine() => Console.ReadLine();

    #endregion

    #region Console State

    /// <inheritdoc/>
    public bool IsInputRedirected => Console.IsInputRedirected;

    /// <inheritdoc/>
    public bool IsUserInteractive => Environment.UserInteractive;

    #endregion

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        if (_standardInputLazy.IsValueCreated)
        {
            _standardInputLazy.Value.Dispose();
        }
    }
}
