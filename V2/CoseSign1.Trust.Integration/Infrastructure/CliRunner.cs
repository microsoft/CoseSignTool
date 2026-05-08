// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Trust.Integration.Infrastructure;

using System;
using System.IO;
using System.Threading;
using CoseSignTool;
using CoseSignTool.Abstractions.IO;

/// <summary>
/// Result of an in-process CLI invocation. Captures the exit code plus the textual stdout and
/// stderr streams so tests can assert on diagnostic codes (TPX*) and trust-failure reasons.
/// </summary>
public sealed class CliResult
{
    public CliResult(int exitCode, string stdout, string stderr)
    {
        ExitCode = exitCode;
        Stdout = stdout ?? string.Empty;
        Stderr = stderr ?? string.Empty;
    }

    /// <summary>
    /// Process exit code returned by <c>CoseSignTool.Program.Run</c>. Non-zero indicates failure.
    /// </summary>
    public int ExitCode { get; }

    /// <summary>
    /// All bytes captured on the test console's stdout TextWriter.
    /// </summary>
    public string Stdout { get; }

    /// <summary>
    /// All bytes captured on the test console's stderr TextWriter.
    /// </summary>
    public string Stderr { get; }
}

/// <summary>
/// Invokes the real <see cref="Program.Run"/> entry point in-process so each integration test
/// exercises the full plugin-loaded production verify pipeline (option parsing, plugin
/// discovery, trust-policy translation, fact production, plan evaluation). The runner captures
/// stdout, stderr, and the exit code into a <see cref="CliResult"/> for inspection.
///
/// The runner serializes invocations because <see cref="Program.Run"/> mutates ambient state
/// (System.CommandLine help registration, plugin AssemblyLoadContext); concurrent runs from
/// different test fixtures could otherwise collide.
/// </summary>
public static class CliRunner
{
    private static readonly SemaphoreSlim Gate = new(initialCount: 1, maxCount: 1);

    /// <summary>
    /// Runs <c>cosesigntool verify ...</c> with the supplied argument vector and returns the
    /// captured exit code + console output.
    /// </summary>
    /// <param name="args">Argument vector (excluding the executable name).</param>
    /// <returns>The captured result. Never <see langword="null"/>.</returns>
    public static CliResult Run(params string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        Gate.Wait();
        try
        {
            using var console = new InMemoryCliConsole();
            int exit = Program.Run(args, console);
            return new CliResult(exit, console.GetStdout(), console.GetStderr());
        }
        finally
        {
            Gate.Release();
        }
    }
}

/// <summary>
/// Minimal <see cref="IConsole"/> implementation backed by <see cref="StringWriter"/> instances.
/// Provides empty stdin (this phase's tests pass signature paths positionally, never via stdin)
/// and captures all writes so the test can assert on the exact diagnostic surface that ships
/// to a real terminal user.
/// </summary>
public sealed class InMemoryCliConsole : IConsole, IDisposable
{
    private readonly MemoryStream _stdin = new(Array.Empty<byte>());
    private readonly StringWriter _stdout = new();
    private readonly StringWriter _stderr = new();
    private readonly MemoryStream _stdoutBinary = new();
    private readonly MemoryStream _stderrBinary = new();
    private bool _disposed;

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = "IConsole interface plumbing — required member, no behaviour to validate.")]
    public Stream StandardInput => _stdin;

    public TextWriter StandardOutput => _stdout;

    public TextWriter StandardError => _stderr;

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = "IConsole interface plumbing — required member, exposed for binary stream consumers we do not exercise from these tests.")]
    public Func<Stream> StandardOutputStreamProvider => () => _stdoutBinary;

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = "IConsole interface plumbing — required member, exposed for binary stream consumers we do not exercise from these tests.")]
    public Func<Stream> StandardErrorStreamProvider => () => _stderrBinary;

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = "IConsole interface plumbing — required member, no behaviour to validate.")]
    public bool IsInputRedirected => true;

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = "IConsole interface plumbing — required member, no behaviour to validate.")]
    public bool IsUserInteractive => false;

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = "IConsole interface plumbing — interactive-mode only; not reachable from non-interactive CLI invocations.")]
    public ConsoleKeyInfo ReadKey(bool intercept) => default;

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = "IConsole interface plumbing — interactive-mode only; not reachable from non-interactive CLI invocations.")]
    public string? ReadLine() => null;

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = "IConsole interface plumbing — the verify pipeline writes via StandardOutput / StandardError TextWriters, not these convenience methods.")]
    public void Write(string? value) => _stdout.Write(value);

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = "IConsole interface plumbing — the verify pipeline writes via StandardOutput / StandardError TextWriters, not these convenience methods.")]
    public void WriteLine() => _stdout.WriteLine();

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = "IConsole interface plumbing — the verify pipeline writes via StandardOutput / StandardError TextWriters, not these convenience methods.")]
    public void WriteLine(string? value) => _stdout.WriteLine(value);

    public string GetStdout() => _stdout.ToString();

    public string GetStderr() => _stderr.ToString();

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _stdin.Dispose();
        _stdout.Dispose();
        _stderr.Dispose();
        _stdoutBinary.Dispose();
        _stderrBinary.Dispose();
        _disposed = true;
    }
}
