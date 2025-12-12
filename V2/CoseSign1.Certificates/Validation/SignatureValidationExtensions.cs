// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Validation;

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
    public static ICoseMessageValidationBuilder ValidateCertificateSignature(
        this ICoseMessageValidationBuilder builder,
        bool allowUnprotectedHeaders = false)
    {
        return builder.AddValidator(new CertificateSignatureValidator(allowUnprotectedHeaders));
    }

    /// <summary>
    /// Validates the signature with a detached payload using the certificate in x5t header.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="detachedPayload">The detached payload to verify against.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <returns>The builder for method chaining.</returns>
    public static ICoseMessageValidationBuilder ValidateCertificateSignature(
        this ICoseMessageValidationBuilder builder,
        byte[] detachedPayload,
        bool allowUnprotectedHeaders = false)
    {
        return builder.AddValidator(new CertificateDetachedSignatureValidator(detachedPayload, allowUnprotectedHeaders));
    }

    /// <summary>
    /// Validates the signature with a detached payload using the certificate in x5t header.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="detachedPayload">The detached payload to verify against.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <returns>The builder for method chaining.</returns>
    public static ICoseMessageValidationBuilder ValidateCertificateSignature(
        this ICoseMessageValidationBuilder builder,
        ReadOnlyMemory<byte> detachedPayload,
        bool allowUnprotectedHeaders = false)
    {
        return builder.AddValidator(new CertificateDetachedSignatureValidator(detachedPayload, allowUnprotectedHeaders));
    }
}