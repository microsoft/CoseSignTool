// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Abstractions;

namespace CoseSign1.Certificates.Extensions;

/// <summary>
/// Extension methods for working with CertificateSigningOptions in the signing pipeline.
/// </summary>
internal static class CertificateSigningOptionsExtensions
{
    /// <summary>
    /// Key used to store CertificateSigningOptions in SigningContext.AdditionalContext.
    /// </summary>
    internal const string CertificateSigningOptionsKey = nameof(CertificateSigningOptions);

    /// <summary>
    /// Attempts to retrieve CertificateSigningOptions from the signing context.
    /// </summary>
    /// <param name="context">The signing context.</param>
    /// <param name="certificateOptions">The certificate options if found; otherwise null.</param>
    /// <returns>True if certificate options were found; otherwise false.</returns>
    internal static bool TryGetCertificateOptions(this SigningContext context, out CertificateSigningOptions? certificateOptions)
    {
        certificateOptions = null;

        if (context?.AdditionalContext == null)
        {
            return false;
        }

        if (context.AdditionalContext.TryGetValue(CertificateSigningOptionsKey, out var value) &&
            value is CertificateSigningOptions certOptions)
        {
            certificateOptions = certOptions;
            return true;
        }

        return false;
    }
}