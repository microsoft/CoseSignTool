// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.Cose;
using System.Threading;
using System.Threading.Tasks;

namespace CoseSign1.Abstractions.Transparency;

/// <summary>
/// Defines a provider for transparency services that can augment COSE Sign1 messages
/// with verifiable transparency proofs (receipts, countersignatures, etc.).
/// </summary>
/// <remarks>
/// Transparency providers enable integration with various transparency services like:
/// - Azure Code Transparency Service (CTS)
/// - Certificate Transparency (CT) / Signed Certificate Timestamps (SCT)
/// - Microsoft's Signing Transparency (MST)
/// - Custom transparency implementations
/// 
/// The provider is called automatically by the factory after signing,
/// allowing transparent messages to be created in a single operation.
/// </remarks>
public interface ITransparencyProvider
{
    /// <summary>
    /// Gets the name of this transparency provider (e.g., "AzureCTS", "CertificateTransparency").
    /// Used for logging and diagnostics.
    /// </summary>
    string ProviderName { get; }

    /// <summary>
    /// Augments a signed COSE Sign1 message with transparency proof(s).
    /// This is called automatically by the factory after signing is complete.
    /// </summary>
    /// <param name="message">The signed COSE Sign1 message to augment.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// A new COSE Sign1 message with transparency proof(s) added.
    /// The original message is not modified.
    /// </returns>
    /// <remarks>
    /// Implementations typically:
    /// 1. Submit the signed message to a transparency service
    /// 2. Receive a receipt/proof from the service
    /// 3. Embed the proof into the message's unprotected headers
    /// 4. Return the augmented message
    /// 
    /// If transparency submission fails, implementations should throw with details.
    /// </remarks>
    Task<CoseSign1Message> AddTransparencyProofAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies the transparency proof(s) in a COSE Sign1 message.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to verify.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// A validation result indicating whether the transparency proof is valid.
    /// </returns>
    Task<TransparencyValidationResult> VerifyTransparencyProofAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default);
}