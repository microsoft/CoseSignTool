// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Interfaces;

using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;

/// <summary>
/// Resolves counter-signatures from a COSE Sign1 message.
/// </summary>
/// <remarks>
/// Counter-signatures may be present in protected or unprotected headers.
/// Implementations should discover counter-signature structures and return a resolved
/// <see cref="ICounterSignature"/> that carries both the counter-signature and its signing key.
/// </remarks>
public interface ICounterSignatureResolver
{
    /// <summary>
    /// Discovers counter-signature structures from the message.
    /// </summary>
    /// <param name="message">The COSE Sign1 message.</param>
    /// <returns>One or more counter-signature discovery results.</returns>
    IReadOnlyList<CounterSignatureResolutionResult> Resolve(CoseSign1Message message);

    /// <summary>
    /// Asynchronously discovers counter-signature structures from the message.
    /// </summary>
    /// <param name="message">The COSE Sign1 message.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task containing one or more counter-signature discovery results.</returns>
    Task<IReadOnlyList<CounterSignatureResolutionResult>> ResolveAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Result of counter-signature discovery.
/// </summary>
public sealed class CounterSignatureResolutionResult
{
    /// <summary>
    /// Gets a value indicating whether discovery succeeded.
    /// </summary>
    public bool IsSuccess { get; init; }

    /// <summary>
    /// Gets the resolved counter-signature, if available.
    /// </summary>
    public ICounterSignature? CounterSignature { get; init; }

    /// <summary>
    /// Gets optional diagnostics.
    /// </summary>
    public IReadOnlyList<string> Diagnostics { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Gets an error code when discovery fails.
    /// </summary>
    public string? ErrorCode { get; init; }

    /// <summary>
    /// Gets an error message when discovery fails.
    /// </summary>
    public string? ErrorMessage { get; init; }

    /// <summary>
    /// Creates a successful discovery result.
    /// </summary>
    /// <param name="counterSignature">The resolved counter-signature.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="counterSignature"/> is null.</exception>
    /// <returns>A successful discovery result.</returns>
    public static CounterSignatureResolutionResult Success(ICounterSignature counterSignature)
    {
        Guard.ThrowIfNull(counterSignature);

        return new CounterSignatureResolutionResult
        {
            IsSuccess = true,
            CounterSignature = counterSignature
        };
    }

    /// <summary>
    /// Creates a failed discovery result.
    /// </summary>
    /// <param name="errorMessage">A human-readable error message.</param>
    /// <param name="errorCode">Optional error code.</param>
    /// <param name="diagnostics">Optional diagnostics.</param>
    /// <returns>A failed discovery result.</returns>
    public static CounterSignatureResolutionResult Failure(string errorMessage, string? errorCode = null, IReadOnlyList<string>? diagnostics = null)
    {
        return new CounterSignatureResolutionResult
        {
            IsSuccess = false,
            ErrorMessage = errorMessage,
            ErrorCode = errorCode,
            Diagnostics = diagnostics ?? Array.Empty<string>()
        };
    }
}
