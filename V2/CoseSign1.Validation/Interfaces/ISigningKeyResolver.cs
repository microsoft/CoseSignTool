// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Interfaces;

using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;

/// <summary>
/// Resolves signing key material from a COSE Sign1 message.
/// </summary>
/// <remarks>
/// <para>
/// This is the first step in the validation pipeline: extract the signing key
/// from the message headers (x5chain, kid, etc.) so it can be used for
/// trust evaluation and signature verification.
/// </para>
/// <para>
/// Implementations should:
/// <list type="bullet">
/// <item><description>Parse relevant headers (x5t, x5chain, kid, etc.)</description></item>
/// <item><description>Construct an <see cref="ISigningKey"/> from the extracted key material</description></item>
/// <item><description>Return diagnostics about the resolution process</description></item>
/// </list>
/// </para>
/// </remarks>
public interface ISigningKeyResolver
{
    /// <summary>
    /// Resolves signing key material from the message.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to extract key material from.</param>
    /// <returns>A result containing the resolved key or diagnostics.</returns>
    SigningKeyResolutionResult Resolve(CoseSign1Message message);

    /// <summary>
    /// Asynchronously resolves signing key material from the message.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to extract key material from.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task containing the resolution result.</returns>
    Task<SigningKeyResolutionResult> ResolveAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Result of signing key resolution.
/// </summary>
public class SigningKeyResolutionResult
{
    /// <summary>
    /// Gets a value indicating whether key resolution succeeded.
    /// </summary>
    public bool IsSuccess { get; init; }

    /// <summary>
    /// Gets the resolved signing key, or null if resolution failed.
    /// </summary>
    /// <remarks>
    /// This is the minimal <see cref="ISigningKey"/> interface. If the resolver
    /// produced an <see cref="ISigningServiceKey"/>, cast to access metadata.
    /// </remarks>
    public ISigningKey? SigningKey { get; init; }

    /// <summary>
    /// Gets candidate keys when multiple keys could match (e.g., multiple x5chain entries).
    /// </summary>
    public IReadOnlyList<ISigningKey>? CandidateKeys { get; init; }

    /// <summary>
    /// Gets the key identifier (kid) if present.
    /// </summary>
    public string? KeyId { get; init; }

    /// <summary>
    /// Gets the thumbprint (x5t) if present.
    /// </summary>
    public byte[]? Thumbprint { get; init; }

    /// <summary>
    /// Gets diagnostic messages from the resolution process.
    /// </summary>
    public IReadOnlyList<string> Diagnostics { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Gets the error message if resolution failed.
    /// </summary>
    public string? ErrorMessage { get; init; }

    /// <summary>
    /// Gets the error code if resolution failed.
    /// </summary>
    public string? ErrorCode { get; init; }

    /// <summary>
    /// Creates a successful resolution result.
    /// </summary>
    /// <param name="signingKey">The resolved signing key.</param>
    /// <param name="keyId">Optional key identifier.</param>
    /// <param name="thumbprint">Optional thumbprint.</param>
    /// <param name="diagnostics">Optional diagnostics.</param>
    /// <returns>A successful result.</returns>
    public static SigningKeyResolutionResult Success(
        ISigningKey signingKey,
        string? keyId = null,
        byte[]? thumbprint = null,
        IReadOnlyList<string>? diagnostics = null)
    {
        return new SigningKeyResolutionResult
        {
            IsSuccess = true,
            SigningKey = signingKey,
            KeyId = keyId,
            Thumbprint = thumbprint,
            Diagnostics = diagnostics ?? Array.Empty<string>()
        };
    }

    /// <summary>
    /// Creates a failed resolution result.
    /// </summary>
    /// <param name="errorMessage">The error message.</param>
    /// <param name="errorCode">The error code.</param>
    /// <param name="diagnostics">Optional diagnostics.</param>
    /// <returns>A failed result.</returns>
    public static SigningKeyResolutionResult Failure(
        string errorMessage,
        string? errorCode = null,
        IReadOnlyList<string>? diagnostics = null)
    {
        return new SigningKeyResolutionResult
        {
            IsSuccess = false,
            ErrorMessage = errorMessage,
            ErrorCode = errorCode,
            Diagnostics = diagnostics ?? Array.Empty<string>()
        };
    }
}
