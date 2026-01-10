// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Validation;

using System.Security.Cryptography.Cose;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation;
using CoseSign1.Validation.Abstractions;

/// <summary>
/// Abstract base class for certificate-based validation components.
/// </summary>
/// <remarks>
/// <para>
/// Extends <see cref="ValidationComponentBase"/> with certificate-specific helpers.
/// Provides a default implementation of <see cref="ComputeApplicability"/> that checks for
/// the presence of an x5chain header in the message.
/// </para>
/// <para>
/// The <see cref="CoseSign1ValidationOptions.CertificateHeaderLocation"/> option
/// controls where certificate data is searched for in headers.
/// </para>
/// </remarks>
public abstract class CertificateValidationComponentBase : ValidationComponentBase
{
    /// <inheritdoc/>
    /// <remarks>
    /// Default implementation checks for the presence of an x5chain header.
    /// Uses <see cref="CoseSign1ValidationOptions.CertificateHeaderLocation"/> to determine
    /// where to search for the certificate chain.
    /// </remarks>
    protected override bool ComputeApplicability(CoseSign1Message message, CoseSign1ValidationOptions? options = null)
    {
        CoseHeaderLocation headerLocation = options?.CertificateHeaderLocation ?? CoseHeaderLocation.Protected;
        return HasCertificateChain(message, headerLocation);
    }

    /// <summary>
    /// Checks if the message has a certificate chain in its headers.
    /// </summary>
    /// <param name="message">The message to check.</param>
    /// <param name="headerLocation">Specifies which headers to search for certificate data.</param>
    /// <returns><c>true</c> if the message has an x5chain header with at least one certificate.</returns>
    protected static bool HasCertificateChain(CoseSign1Message? message, CoseHeaderLocation headerLocation = CoseHeaderLocation.Protected)
    {
        if (message == null)
        {
            return false;
        }

        return message.TryGetCertificateChain(out var chain, headerLocation)
               && chain != null
               && chain.Count > 0;
    }
}
