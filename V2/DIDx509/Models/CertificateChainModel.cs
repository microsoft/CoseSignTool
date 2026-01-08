// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Models;

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

/// <summary>
/// Represents a certificate chain in the DID:X509 JSON data model.
/// The first certificate is the leaf (end-entity) certificate.
/// </summary>
public sealed class CertificateChainModel
{
    /// <summary>
    /// Gets the certificate chain (leaf first).
    /// </summary>
    public IReadOnlyList<CertificateInfo> Chain { get; }

    /// <summary>
    /// Gets the leaf certificate (first in chain).
    /// </summary>
    public CertificateInfo LeafCertificate => Chain[0];

    /// <summary>
    /// Gets the CA certificates (all certificates except the leaf).
    /// </summary>
    public IEnumerable<CertificateInfo> CaCertificates => Chain.Skip(1);

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateChainModel"/> class.
    /// </summary>
    /// <param name="chain">The certificate chain (leaf first).</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="chain"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="chain"/> contains fewer than two certificates.</exception>
    public CertificateChainModel(IReadOnlyList<CertificateInfo> chain)
    {
        if (chain == null)
        {
            throw new ArgumentNullException(nameof(chain));
        }

        if (chain.Count < 2)
        {
            throw new ArgumentException(ClassStrings.ErrorCertificateChainMustContainAtLeastTwoCertificatesLeafAndCa, nameof(chain));
        }

        Chain = chain;
    }

    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ErrorCertificateChainMustContainAtLeastTwoCertificatesLeafAndCa = "Certificate chain must contain at least 2 certificates (leaf + CA)";
    }

    /// <summary>
    /// Finds a CA certificate with a matching fingerprint.
    /// </summary>
    /// <param name="algorithm">The hash algorithm used for the fingerprint.</param>
    /// <param name="fingerprint">The fingerprint to match.</param>
    /// <returns>The matching CA certificate, or <see langword="null"/> if no match is found.</returns>
    public CertificateInfo? FindCaByFingerprint(string algorithm, string fingerprint)
    {
        foreach (var ca in CaCertificates)
        {
            if (ca.Fingerprints.Matches(algorithm, fingerprint))
            {
                return ca;
            }
        }

        return null;
    }
}