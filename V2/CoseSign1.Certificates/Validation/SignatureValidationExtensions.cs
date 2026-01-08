// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Extension methods for adding signature validation to the builder.
/// </summary>
public static class SignatureValidationExtensions
{
    /// <summary>
    /// Validates the signature using the certificate in x5t header.
    /// For embedded signatures, uses the embedded content.
    /// For detached signatures, requires the payload parameter.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <returns>The builder for method chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> is null.</exception>
    public static ICoseSign1ValidationBuilder ValidateCertificateSignature(
        this ICoseSign1ValidationBuilder builder,
        bool allowUnprotectedHeaders = false)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        return builder.AddValidator(new CertificateSignatureValidator(allowUnprotectedHeaders));
    }

    /// <summary>
    /// Validates the signature with a detached payload using the certificate in x5t header.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="detachedPayload">The detached payload to verify against.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <returns>The builder for method chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> is null.</exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="detachedPayload"/> is null.</exception>
    public static ICoseSign1ValidationBuilder ValidateCertificateSignature(
        this ICoseSign1ValidationBuilder builder,
        byte[] detachedPayload,
        bool allowUnprotectedHeaders = false)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        if (detachedPayload is null)
        {
            throw new ArgumentNullException(nameof(detachedPayload));
        }

        return builder.AddValidator(new CertificateDetachedSignatureValidator(detachedPayload, allowUnprotectedHeaders));
    }

    /// <summary>
    /// Validates the signature with a detached payload using the certificate in x5t header.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="detachedPayload">The detached payload to verify against.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <returns>The builder for method chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="builder"/> is null.</exception>
    public static ICoseSign1ValidationBuilder ValidateCertificateSignature(
        this ICoseSign1ValidationBuilder builder,
        ReadOnlyMemory<byte> detachedPayload,
        bool allowUnprotectedHeaders = false)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        return builder.AddValidator(new CertificateDetachedSignatureValidator(detachedPayload, allowUnprotectedHeaders));
    }
}