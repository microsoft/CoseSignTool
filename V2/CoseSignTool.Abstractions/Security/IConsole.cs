// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions.Security;

/// <summary>
/// Interface for console operations, enabling testability of console-interactive code.
/// </summary>
public interface IConsole
{
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

    /// <summary>
    /// Gets a value indicating whether input has been redirected from the standard input stream.
    /// </summary>
    bool IsInputRedirected { get; }

    /// <summary>
    /// Gets a value indicating whether the current process is running in user interactive mode.
    /// </summary>
    bool IsUserInteractive { get; }
}
