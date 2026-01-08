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
    /// Gets the validators for all stages.
    /// </summary>
    IReadOnlyList<IValidator> Validators { get; }

    /// <summary>
    /// Validates the specified COSE Sign1 message.
    /// </summary>
    /// <param name="message">The message to validate.</param>
    /// <returns>A staged validation result.</returns>
    CoseSign1ValidationResult Validate(CoseSign1Message message);
}
