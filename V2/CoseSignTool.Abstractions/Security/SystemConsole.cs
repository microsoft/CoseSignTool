// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;

namespace CoseSignTool.Abstractions.Security;

/// <summary>
/// Default implementation of <see cref="IConsole"/> that wraps the system Console.
/// </summary>
/// <remarks>
/// This is a thin wrapper with no logic - all methods delegate directly to System.Console.
/// It is excluded from code coverage because it cannot be meaningfully tested without
/// actual console interaction.
/// </remarks>
public sealed class SystemConsole : IConsole
{
    /// <summary>
    /// Gets the singleton instance of SystemConsole.
    /// </summary>
    public static SystemConsole Instance { get; } = new();

    private SystemConsole() { }

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

    /// <inheritdoc/>
    public bool IsInputRedirected => Console.IsInputRedirected;

    /// <inheritdoc/>
    public bool IsUserInteractive => Environment.UserInteractive;
}
