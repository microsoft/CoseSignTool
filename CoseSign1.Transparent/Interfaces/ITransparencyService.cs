// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.Interfaces;

using System.Security.Cryptography.Cose;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Defines a service for creating and verifying transparent COSE Sign1 messages.
/// Transparency in this context refers to embedding additional metadata or headers
/// into COSE Sign1 messages to ensure traceability and auditability.
/// </summary>
public interface ITransparencyService
{
    /// <summary>
    /// Creates a new transparent COSE Sign1 message by embedding additional metadata or headers
    /// into the provided COSE Sign1 message.
    /// </summary>
    /// <param name="message">The original <see cref="CoseSign1Message"/> to be transformed into a transparent message.</param>
    /// <param name="cancellationToken">
    /// A <see cref="CancellationToken"/> to observe while waiting for the task to complete.
    /// </param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result contains a new 
    /// <see cref="CoseSign1Message"/> with the transparency metadata or headers applied.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="message"/> is <c>null</c>.</exception>
    Task<CoseSign1Message> MakeTransparentAsync(CoseSign1Message message, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies the transparency of a given COSE Sign1 message by checking its metadata or headers
    /// against the expected transparency rules.
    /// </summary>
    /// <param name="message">The <see cref="CoseSign1Message"/> to verify for transparency.</param>
    /// <param name="cancellationToken">
    /// A <see cref="CancellationToken"/> to observe while waiting for the task to complete.
    /// </param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result is a boolean value indicating
    /// whether the message meets the transparency requirements (true if valid, false otherwise).
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="message"/> is <c>null</c>.</exception>
    Task<bool> VerifyTransparencyAsync(CoseSign1Message message, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies the transparency of a given COSE Sign1 message using a specific receipt.
    /// </summary>
    /// <param name="message">The <see cref="CoseSign1Message"/> to verify for transparency.</param>
    /// <param name="receipt">The receipt to use for verification.</param>
    /// <param name="cancellationToken">
    /// A <see cref="CancellationToken"/> to observe while waiting for the task to complete.
    /// </param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result is a boolean value indicating
    /// whether the message meets the transparency requirements when verified with the provided receipt (true if valid, false otherwise).
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="message"/> or <paramref name="receipt"/> is <c>null</c>.
    /// </exception>
    Task<bool> VerifyTransparencyAsync(CoseSign1Message message, byte[] receipt, CancellationToken cancellationToken = default);
}
