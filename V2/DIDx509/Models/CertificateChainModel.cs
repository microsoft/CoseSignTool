// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Models;

using System;
using System.Collections.Generic;
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
    public CertificateChainModel(IReadOnlyList<CertificateInfo> chain)
    {
        if (chain == null)
        {
            throw new ArgumentNullException(nameof(chain));
        }

        if (chain.Count < 2)
        {
            throw new ArgumentException("Certificate chain must contain at least 2 certificates (leaf + CA)", nameof(chain));
        }

        Chain = chain;
    }

    /// <summary>
    /// Finds a CA certificate with a matching fingerprint.
    /// </summary>
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