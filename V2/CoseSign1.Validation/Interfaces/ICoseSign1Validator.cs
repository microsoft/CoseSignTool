// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Interfaces;

using System.Security.Cryptography.Cose;
using CoseSign1.Validation;

/// <summary>
/// Validates COSE Sign1 messages using a configured staged validation policy.
/// Intended for DI-friendly usage.
/// </summary>
public interface ICoseSign1Validator
{
    /// <summary>
    /// Gets the trust policy evaluated against trust assertions.
    /// </summary>
    TrustPolicy TrustPolicy { get; }

    /// <summary>
    /// Gets all validation components.
    /// </summary>
    /// <remarks>
    /// Components are filtered by type internally:
    /// <list type="bullet">
    /// <item><description><see cref="ISigningKeyResolver"/> for key resolution</description></item>
    /// <item><description><see cref="ISigningKeyAssertionProvider"/> for trust assertions</description></item>
    /// <item><description><see cref="IPostSignatureValidator"/> for post-signature policy</description></item>
    /// </list>
    /// Signature verification is performed directly using the resolved signing key.
    /// </remarks>
    IReadOnlyList<IValidationComponent> Components { get; }

    /// <summary>
    /// Validates the specified COSE Sign1 message.
    /// </summary>
    /// <param name="message">The message to validate.</param>
    /// <returns>A validation result.</returns>
    CoseSign1ValidationResult Validate(CoseSign1Message message);

    /// <summary>
    /// Asynchronously validates the specified COSE Sign1 message.
    /// Use this when any component may require network I/O (OCSP checks, CRL fetch, external services).
    /// </summary>
    /// <param name="message">The message to validate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task containing the validation result.</returns>
    Task<CoseSign1ValidationResult> ValidateAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default);
}
