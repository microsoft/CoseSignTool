// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Models;

using System;
using System.Collections.Generic;

/// <summary>
/// Represents X.509 certificate extensions according to the DID:X509 JSON data model.
/// </summary>
public sealed class CertificateExtensions
{
    /// <summary>
    /// Gets the Extended Key Usage (EKU) OIDs, if present.
    /// </summary>
    public IReadOnlyList<string>? Eku { get; }

    /// <summary>
    /// Gets the Subject Alternative Names (SAN), if present.
    /// </summary>
    public IReadOnlyList<SubjectAlternativeName>? San { get; }

    /// <summary>
    /// Gets the Fulcio issuer URL, if present (Sigstore-specific extension).
    /// </summary>
    public string? FulcioIssuer { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateExtensions"/> class.
    /// </summary>
    /// <param name="eku">The Extended Key Usage (EKU) OIDs.</param>
    /// <param name="san">The Subject Alternative Names (SAN).</param>
    /// <param name="fulcioIssuer">The Fulcio issuer URL.</param>
    public CertificateExtensions(
        IReadOnlyList<string>? eku = null,
        IReadOnlyList<SubjectAlternativeName>? san = null,
        string? fulcioIssuer = null)
    {
        Eku = eku;
        San = san;
        FulcioIssuer = fulcioIssuer;
    }

    /// <summary>
    /// Checks if the certificate has a specific EKU OID.
    /// </summary>
    /// <param name="oid">The EKU OID to check for.</param>
    /// <returns><see langword="true"/> if the EKU is present; otherwise, <see langword="false"/>.</returns>
    public bool HasEku(string oid)
    {
        if (Eku == null || string.IsNullOrEmpty(oid))
        {
            return false;
        }

        foreach (var ekuOid in Eku)
        {
            if (string.Equals(ekuOid, oid, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Checks if the certificate has a specific SAN.
    /// </summary>
    /// <param name="type">The SAN type.</param>
    /// <param name="value">The SAN value.</param>
    /// <returns><see langword="true"/> if the SAN is present; otherwise, <see langword="false"/>.</returns>
    public bool HasSan(string type, string value)
    {
        if (San == null || string.IsNullOrEmpty(type) || string.IsNullOrEmpty(value))
        {
            return false;
        }

        foreach (var san in San)
        {
            if (string.Equals(san.Type, type, StringComparison.OrdinalIgnoreCase) &&
                san.ValueAsString != null &&
                string.Equals(san.ValueAsString, value, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}