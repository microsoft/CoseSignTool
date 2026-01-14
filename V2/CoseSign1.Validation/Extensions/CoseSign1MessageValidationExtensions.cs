// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace System.Security.Cryptography.Cose;

using CoseSign1.Abstractions;
using CoseSign1.Validation;
using CoseSign1.Validation.Interfaces;

/// <summary>
/// Extension methods for validating <see cref="CoseSign1Message"/> instances.
/// </summary>
/// <example>
/// Validation with a pre-built validator:
/// <code>
/// var message = CoseMessage.DecodeSign1(signatureBytes);
/// var result = message.Validate(validator);
/// 
/// if (result.Overall.IsValid)
/// {
///     Console.WriteLine("Signature is valid!");
/// }
/// </code>
/// </example>
public static class CoseSign1MessageValidationExtensions
{
    /// <summary>
    /// Validates the COSE Sign1 message using a pre-built validator.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to validate.</param>
    /// <param name="validator">The validator to use for validation.</param>
    /// <returns>A validation result containing results for each validation stage.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="message"/> or <paramref name="validator"/> is null.</exception>
    public static CoseSign1ValidationResult Validate(
        this CoseSign1Message message,
        ICoseSign1Validator validator)
    {
        Guard.ThrowIfNull(message);
        Guard.ThrowIfNull(validator);

        return validator.Validate(message);
    }

    /// <summary>
    /// Asynchronously validates the COSE Sign1 message using a pre-built validator.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to validate.</param>
    /// <param name="validator">The validator to use for validation.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task containing the validation result.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="message"/> or <paramref name="validator"/> is null.</exception>
    /// <remarks>
    /// Use this overload when validation components may require network I/O
    /// (e.g., OCSP checks, CRL fetching, external trust services).
    /// </remarks>
    public static Task<CoseSign1ValidationResult> ValidateAsync(
        this CoseSign1Message message,
        ICoseSign1Validator validator,
        CancellationToken cancellationToken = default)
    {
        Guard.ThrowIfNull(message);
        Guard.ThrowIfNull(validator);

        return validator.ValidateAsync(message, cancellationToken);
    }

}
