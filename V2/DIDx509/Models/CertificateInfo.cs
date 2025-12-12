// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Models;

using System;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Represents a certificate in the DID:X509 JSON data model.
/// </summary>
public sealed class CertificateInfo
{
    /// <summary>
    /// Gets the certificate fingerprints.
    /// </summary>
    public CertificateFingerprints Fingerprints { get; }

    /// <summary>
    /// Gets the certificate issuer name.
    /// </summary>
    public X509Name Issuer { get; }

    /// <summary>
    /// Gets the certificate subject name.
    /// </summary>
    public X509Name Subject { get; }

    /// <summary>
    /// Gets the certificate extensions.
    /// </summary>
    public CertificateExtensions Extensions { get; }

    /// <summary>
    /// Gets the original X.509 certificate.
    /// </summary>
    public X509Certificate2 Certificate { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateInfo"/> class.
    /// </summary>
    public CertificateInfo(
        CertificateFingerprints fingerprints,
        X509Name issuer,
        X509Name subject,
        CertificateExtensions extensions,
        X509Certificate2 certificate)
    {
        Fingerprints = fingerprints ?? throw new ArgumentNullException(nameof(fingerprints));
        Issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
        Subject = subject ?? throw new ArgumentNullException(nameof(subject));
        Extensions = extensions ?? throw new ArgumentNullException(nameof(extensions));
        Certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
    }
}