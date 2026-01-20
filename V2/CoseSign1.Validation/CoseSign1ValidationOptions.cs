// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation;

using CoseSign1.Abstractions;
using System.Security.Cryptography.Cose;

/// <summary>
/// Options for configuring COSE Sign1 message validation.
/// </summary>
/// <remarks>
/// This class encapsulates all optional configuration for validation:
/// <list type="bullet">
/// <item><description>Detached payload content (for messages with detached signatures)</description></item>
/// <item><description>Associated data for signature verification</description></item>
/// <item><description>Cancellation token for async operations</description></item>
/// </list>
/// Use <see cref="CoseSign1ValidationOptionsExtensions"/> for fluent configuration.
/// </remarks>
public sealed class CoseSign1ValidationOptions
{
    /// <summary>
    /// Gets or sets the detached payload stream for signature verification.
    /// Required when validating messages with detached content.
    /// </summary>
    /// <remarks>
    /// The caller is responsible for the stream's lifetime. The stream should remain
    /// open and positioned at the start during validation. For seekable streams,
    /// the validator will reset the position as needed.
    /// </remarks>
    public Stream? DetachedPayload { get; set; }

    /// <summary>
    /// Gets or sets the associated data for signature verification.
    /// </summary>
    /// <remarks>
    /// Associated data is additional authenticated data that was included in the
    /// signature computation but is not part of the payload. If the message was
    /// signed with associated data, the same data must be provided for verification.
    /// </remarks>
    public ReadOnlyMemory<byte>? AssociatedData { get; set; }

    /// <summary>
    /// Gets or sets the cancellation token for validation operations.
    /// </summary>
    public CancellationToken CancellationToken { get; set; }

    /// <summary>
    /// Gets or sets a value indicating where certificate data may be read from.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When <see cref="CoseHeaderLocation.Protected"/> (default), certificate chains (x5chain) are only read from protected headers.
    /// When <see cref="CoseHeaderLocation.Any"/>, certificate chains may also be read from unprotected headers.
    /// </para>
    /// <para>
    /// <b>Security Note:</b> Unprotected headers are not covered by the signature and could be
    /// modified by an attacker. Only enable unprotected header access if you understand the security implications.
    /// </para>
    /// </remarks>
    public CoseHeaderLocation CertificateHeaderLocation { get; set; } = CoseHeaderLocation.Protected;

    /// <summary>
    /// Gets or sets a value indicating whether post-signature validation should be skipped.
    /// </summary>
    /// <remarks>
    /// This is primarily used for signature-only verification flows where the caller wants to validate
    /// cryptographic correctness (and optionally trust) but intentionally avoids post-signature policy checks
    /// such as indirect payload hash validation.
    /// </remarks>
    public bool SkipPostSignatureValidation { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether a verified ToBeSigned attestation may satisfy primary signature validation.
    /// </summary>
    /// <remarks>
    /// When true (default), staged validation may skip primary signing key resolution and signature verification if an
    /// <see cref="Interfaces.IToBeSignedAttestor"/> attests that it has already validated the message's ToBeSigned construction.
    /// This is intended for counter-signature / receipt scenarios where the receipt validates the same Sig_structure.
    /// </remarks>
    public bool AllowToBeSignedAttestationToSkipPrimarySignature { get; set; } = true;

    /// <summary>
    /// Creates a new instance of <see cref="CoseSign1ValidationOptions"/> with default values.
    /// </summary>
    public CoseSign1ValidationOptions()
    {
    }

    /// <summary>
    /// Creates a copy of the options.
    /// </summary>
    /// <returns>A new instance with the same values.</returns>
    public CoseSign1ValidationOptions Clone()
    {
        return new CoseSign1ValidationOptions
        {
            DetachedPayload = DetachedPayload,
            AssociatedData = AssociatedData,
            CancellationToken = CancellationToken,
            CertificateHeaderLocation = CertificateHeaderLocation,
            SkipPostSignatureValidation = SkipPostSignatureValidation,
            AllowToBeSignedAttestationToSkipPrimarySignature = AllowToBeSignedAttestationToSkipPrimarySignature
        };
    }
}

/// <summary>
/// Extension methods for fluent configuration of <see cref="CoseSign1ValidationOptions"/>.
/// </summary>
public static class CoseSign1ValidationOptionsExtensions
{
    /// <summary>
    /// Sets the detached payload from a stream.
    /// </summary>
    /// <param name="options">The options to configure.</param>
    /// <param name="payload">The stream containing the detached payload.</param>
    /// <returns>The same options instance for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> is null.</exception>
    public static CoseSign1ValidationOptions WithDetachedPayload(this CoseSign1ValidationOptions options, Stream payload)
    {
        Guard.ThrowIfNull(options);

        options.DetachedPayload = payload;
        return options;
    }

    /// <summary>
    /// Sets the detached payload from a byte array.
    /// </summary>
    /// <param name="options">The options to configure.</param>
    /// <param name="payload">The detached payload bytes.</param>
    /// <returns>The same options instance for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> or <paramref name="payload"/> is null.</exception>
    public static CoseSign1ValidationOptions WithDetachedPayload(this CoseSign1ValidationOptions options, byte[] payload)
    {
        Guard.ThrowIfNull(options);
        Guard.ThrowIfNull(payload);

        options.DetachedPayload = new MemoryStream(payload, writable: false);
        return options;
    }

    /// <summary>
    /// Sets the detached payload from a ReadOnlyMemory.
    /// </summary>
    /// <param name="options">The options to configure.</param>
    /// <param name="payload">The detached payload bytes.</param>
    /// <returns>The same options instance for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> is null.</exception>
    public static CoseSign1ValidationOptions WithDetachedPayload(this CoseSign1ValidationOptions options, ReadOnlyMemory<byte> payload)
    {
        Guard.ThrowIfNull(options);

        options.DetachedPayload = new MemoryStream(payload.ToArray(), writable: false);
        return options;
    }

    /// <summary>
    /// Sets the associated data for signature verification.
    /// </summary>
    /// <param name="options">The options to configure.</param>
    /// <param name="associatedData">The associated data bytes.</param>
    /// <returns>The same options instance for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> is null.</exception>
    public static CoseSign1ValidationOptions WithAssociatedData(this CoseSign1ValidationOptions options, ReadOnlyMemory<byte> associatedData)
    {
        Guard.ThrowIfNull(options);

        options.AssociatedData = associatedData;
        return options;
    }

    /// <summary>
    /// Sets the associated data for signature verification from a byte array.
    /// </summary>
    /// <param name="options">The options to configure.</param>
    /// <param name="associatedData">The associated data bytes.</param>
    /// <returns>The same options instance for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> or <paramref name="associatedData"/> is null.</exception>
    public static CoseSign1ValidationOptions WithAssociatedData(this CoseSign1ValidationOptions options, byte[] associatedData)
    {
        Guard.ThrowIfNull(options);
        Guard.ThrowIfNull(associatedData);

        options.AssociatedData = associatedData;
        return options;
    }

    /// <summary>
    /// Sets the cancellation token for validation operations.
    /// </summary>
    /// <param name="options">The options to configure.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The same options instance for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> is null.</exception>
    public static CoseSign1ValidationOptions WithCancellationToken(this CoseSign1ValidationOptions options, CancellationToken cancellationToken)
    {
        Guard.ThrowIfNull(options);

        options.CancellationToken = cancellationToken;
        return options;
    }

    /// <summary>
    /// Configures the options using an action delegate.
    /// </summary>
    /// <param name="options">The options to configure.</param>
    /// <param name="configure">The configuration action.</param>
    /// <returns>The same options instance for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> or <paramref name="configure"/> is null.</exception>
    public static CoseSign1ValidationOptions Configure(this CoseSign1ValidationOptions options, Action<CoseSign1ValidationOptions> configure)
    {
        Guard.ThrowIfNull(options);
        Guard.ThrowIfNull(configure);

        configure(options);
        return options;
    }
}
