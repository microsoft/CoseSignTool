// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Security.Cryptography.Cose;
using System.Threading;
using System.Threading.Tasks;

namespace CoseSign1.Abstractions.Transparency;

/// <summary>
/// Extension methods for working with transparent COSE Sign1 messages.
/// </summary>
public static class TransparencyExtensions
{
    /// <summary>
    /// Verifies the transparency proof in a COSE Sign1 message using the specified provider.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to verify.</param>
    /// <param name="provider">The transparency provider to use for verification.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validation result.</returns>
    public static Task<TransparencyValidationResult> VerifyTransparencyAsync(
        this CoseSign1Message message,
        ITransparencyProvider provider,
        CancellationToken cancellationToken = default)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        if (provider == null)
        {
            throw new ArgumentNullException(nameof(provider));
        }

        return provider.VerifyTransparencyProofAsync(message, cancellationToken);
    }

    /// <summary>
    /// Checks if a COSE Sign1 message has a transparency proof.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to check.</param>
    /// <param name="providerName">Optional provider name to check for specific transparency type.</param>
    /// <returns>True if the message appears to have a transparency proof; otherwise, false.</returns>
    /// <remarks>
    /// This is a heuristic check based on common header patterns. For definitive verification,
    /// use <see cref="VerifyTransparencyAsync"/>.
    /// </remarks>
    public static bool HasTransparencyProof(this CoseSign1Message message, string? providerName = null)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        // Check for common transparency headers in unprotected headers
        // Most transparency services add receipts/proofs to unprotected headers
        
        // Common header labels for transparency:
        // - Custom labels for CTS, SCT, etc.
        // - Look for "receipt", "proof", "transparency" in header keys
        
        // Implementation note: Specific header checks depend on the transparency service
        // This is a placeholder for common patterns
        return message.UnprotectedHeaders?.Count > 0;
    }
}
