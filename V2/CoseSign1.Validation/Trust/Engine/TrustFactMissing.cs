// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Engine;

using CoseSign1.Abstractions;

/// <summary>
/// Represents why a fact could not be produced.
/// </summary>
public sealed class TrustFactMissing
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TrustFactMissing"/> class.
    /// </summary>
    /// <param name="code">A stable missing reason code.</param>
    /// <param name="message">A human-readable description.</param>
    /// <param name="exception">An optional exception captured for diagnostics.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="code"/> or <paramref name="message"/> is null.</exception>
    public TrustFactMissing(string code, string message, Exception? exception = null)
    {
        Guard.ThrowIfNull(code);
        Guard.ThrowIfNull(message);

        Code = code;
        Message = message;
        Exception = exception;
    }

    /// <summary>
    /// Gets a stable missing reason code.
    /// </summary>
    public string Code { get; }

    /// <summary>
    /// Gets a human-readable description.
    /// </summary>
    public string Message { get; }

    /// <summary>
    /// Gets an optional exception captured for diagnostics.
    /// </summary>
    public Exception? Exception { get; }
}
