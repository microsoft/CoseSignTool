// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;

/// <summary>
/// Context information for verification that isn't available from command-line parsing alone.
/// Includes runtime options such as logger factory and console for diagnostics.
/// </summary>
public sealed class VerificationContext
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string KeyLoggerFactory = "__loggerFactory";
        public const string KeyConsole = "__console";
        public const string KeyPreferCounterSignatureTrust = "__preferCounterSignatureTrust";
    }

    /// <summary>
    /// Dictionary key for <see cref="ILoggerFactory"/> in <see cref="Options"/>.
    /// </summary>
    public const string KeyLoggerFactory = ClassStrings.KeyLoggerFactory;

    /// <summary>
    /// Dictionary key for <see cref="CoseSignTool.Abstractions.IO.IConsole"/> in <see cref="Options"/>.
    /// </summary>
    public const string KeyConsole = ClassStrings.KeyConsole;

    /// <summary>
    /// Dictionary key indicating that verification should prefer counter-signature / receipt trust over primary signing-key trust.
    /// </summary>
    /// <remarks>
    /// This is used by the CLI host to coordinate providers (for example, to make a transparency receipt the trust anchor).
    /// Providers that normally impose primary signing-key trust requirements may choose to suppress those requirements when this flag is set.
    /// </remarks>
    public const string KeyPreferCounterSignatureTrust = ClassStrings.KeyPreferCounterSignatureTrust;

    /// <summary>
    /// Initializes a new instance of the <see cref="VerificationContext"/> class.
    /// </summary>
    /// <param name="detachedPayload">
    /// Detached payload bytes. For embedded signatures this is typically null.
    /// For detached signatures this is required to verify the signature.
    /// </param>
    /// <param name="options">
    /// Runtime options dictionary. May contain:
    /// <list type="bullet">
    ///   <item><description><see cref="KeyLoggerFactory"/>: An <see cref="ILoggerFactory"/> for diagnostic logging.</description></item>
    ///   <item><description><see cref="KeyConsole"/>: An <see cref="CoseSignTool.Abstractions.IO.IConsole"/> for console I/O.</description></item>
    /// </list>
    /// </param>
    public VerificationContext(ReadOnlyMemory<byte>? detachedPayload, IDictionary<string, object?>? options = null)
    {
        DetachedPayload = detachedPayload;
        Options = options ?? new Dictionary<string, object?>();
    }

    /// <summary>
    /// Gets the detached payload bytes, if present.
    /// </summary>
    public ReadOnlyMemory<byte>? DetachedPayload { get; }

    /// <summary>
    /// Gets the runtime options dictionary containing services like <see cref="ILoggerFactory"/> and <see cref="IO.IConsole"/>.
    /// </summary>
    public IDictionary<string, object?> Options { get; }

    /// <summary>
    /// Gets the <see cref="ILoggerFactory"/> from <see cref="Options"/>, if present.
    /// </summary>
    public ILoggerFactory? LoggerFactory => Options.TryGetValue(KeyLoggerFactory, out var value) ? value as ILoggerFactory : null;

    /// <summary>
    /// Gets a value indicating whether the host prefers counter-signature / receipt trust.
    /// </summary>
    public bool PreferCounterSignatureTrust => Options.TryGetValue(KeyPreferCounterSignatureTrust, out var value) && value is true;
}
