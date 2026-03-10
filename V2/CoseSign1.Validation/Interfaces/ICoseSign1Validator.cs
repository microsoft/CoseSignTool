// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Interfaces;

using System.Security.Cryptography.Cose;
using CoseSign1.Validation;
using CoseSign1.Validation.Trust.Plan;

/// <summary>
/// Validates COSE Sign1 messages using a configured staged validation policy.
/// Intended for DI-friendly usage.
/// </summary>
public interface ICoseSign1Validator
{
    /// <summary>
    /// Gets the compiled trust plan evaluated during the trust stage.
    /// </summary>
    CompiledTrustPlan TrustPlan { get; }

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
