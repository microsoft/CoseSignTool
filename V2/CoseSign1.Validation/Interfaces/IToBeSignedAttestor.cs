// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Interfaces;

using System.Security.Cryptography.Cose;

/// <summary>
/// Provides an attestation that the <c>Sig_structure</c> / ToBeSigned construction of a COSE Sign1 message
/// has already been validated by an alternative mechanism (for example, a verified counter-signature / receipt).
/// </summary>
/// <remarks>
/// <para>
/// This abstraction enables a secure optimization: if a counter-signature has already validated the exact
/// <c>Sig_structure</c> that the primary signing key would validate, staged validation may be able to skip
/// primary signing key resolution and signature verification.
/// </para>
/// <para>
/// Implementations must be conservative: return <see cref="ToBeSignedAttestationResult.NotAttested"/> when
/// attestation cannot be established.
/// </para>
/// </remarks>
public interface IToBeSignedAttestor
{
    /// <summary>
    /// Attempts to attest that the provided message's ToBeSigned construction has been validated.
    /// </summary>
    /// <param name="message">The message to attest.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>An attestation result.</returns>
    ValueTask<ToBeSignedAttestationResult> AttestAsync(CoseSign1Message message, CancellationToken cancellationToken = default);
}

/// <summary>
/// Result of a ToBeSigned attestation attempt.
/// </summary>
public readonly record struct ToBeSignedAttestationResult(
    bool IsAttested,
    string Provider,
    string? Details = null)
{
    /// <summary>
    /// Gets a sentinel result indicating no attestation is available.
    /// </summary>
    /// <param name="provider">The provider name producing the result.</param>
    /// <param name="details">Optional details about why the message was not attested.</param>
    /// <returns>A not-attested result.</returns>
    public static ToBeSignedAttestationResult NotAttested(string provider, string? details = null)
        => new(IsAttested: false, Provider: provider, Details: details);

    /// <summary>
    /// Gets a result indicating that ToBeSigned was validated by the attestor.
    /// </summary>
    /// <param name="provider">The provider name producing the result.</param>
    /// <param name="details">Optional details about the attestation.</param>
    /// <returns>An attested result.</returns>
    public static ToBeSignedAttestationResult Attested(string provider, string? details = null)
        => new(IsAttested: true, Provider: provider, Details: details);
}
