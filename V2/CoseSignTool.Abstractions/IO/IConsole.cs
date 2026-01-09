// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions.IO;

/// <summary>
/// Unified interface for console I/O operations including streams (stdin, stdout, stderr)
/// and interactive console operations (ReadKey, ReadLine, Write).
/// Enables dependency injection for testability while providing thin wrappers
/// around System.Console by default.
/// </summary>
/// <remarks>
/// This interface combines stream-based I/O for binary data and interactive console
/// operations for user prompts. Implementations should route log output to 
/// <see cref="StandardError"/> to keep <see cref="StandardOutput"/> available for
/// program output (signatures, verification results).
/// </remarks>
public interface IConsole : IDisposable
{
    #region Stream-based I/O

    /// <summary>
    /// Gets the standard input stream.
    /// </summary>
    Stream StandardInput { get; }

    /// <summary>
    /// Gets the standard output writer.
    /// </summary>
    TextWriter StandardOutput { get; }

    /// <summary>
    /// Gets the standard error writer.
    /// </summary>
    TextWriter StandardError { get; }

    /// <summary>
    /// Gets a function that provides the standard output stream.
    /// Useful when code needs to write binary data directly to stdout.
    /// </summary>
    Func<Stream> StandardOutputStreamProvider { get; }

    /// <summary>
    /// Gets a function that provides the standard error stream.
    /// Useful when code needs to write binary data directly to stderr.
    /// </summary>
    Func<Stream> StandardErrorStreamProvider { get; }

    #endregion

    #region Interactive Console Operations

    /// <summary>
    /// Writes a string to the standard output stream.
    /// </summary>
    /// <param name="value">The value to write.</param>
    void Write(string? value);

    /// <summary>
    /// Writes a line terminator to the standard output stream.
    /// </summary>
    void WriteLine();

    /// <summary>
    /// Writes a string followed by a line terminator to the standard output stream.
    /// </summary>
    /// <param name="value">The value to write.</param>
    void WriteLine(string? value);

    /// <summary>
    /// Reads a key from the console without displaying it.
    /// </summary>
    /// <param name="intercept">True to not display the pressed key.</param>
    /// <returns>Information about the pressed key.</returns>
    ConsoleKeyInfo ReadKey(bool intercept);

    /// <summary>
    /// Reads a line from the console.
    /// </summary>
    /// <returns>The line read, or null if no more lines available.</returns>
    string? ReadLine();

    #endregion

    #region Console State

    /// <summary>
    /// Gets a value indicating whether input has been redirected from the standard input stream.
    /// </summary>
    bool IsInputRedirected { get; }

    /// <summary>
    /// Gets a value indicating whether the current process is running in user interactive mode.
    /// </summary>
    bool IsUserInteractive { get; }

    #endregion
}
