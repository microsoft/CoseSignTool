// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Headers.Extensions;

using System;
using System.Security.Cryptography.Cose;

/// <summary>
/// Extension methods for working with CWT Claims in COSE headers.
/// </summary>
public static class CoseHeaderMapCwtClaimsExtensions
{
    /// <summary>
    /// Tries to get CWT Claims from a COSE header map.
    /// </summary>
    /// <param name="headerMap">The header map to read from.</param>
    /// <param name="claims">The parsed CWT claims if found.</param>
    /// <param name="headerLabel">Optional custom header label. Defaults to label 15 (CWT Claims).</param>
    /// <returns>True if CWT claims were found and parsed successfully; otherwise, false.</returns>
    public static bool TryGetCwtClaims(
        this CoseHeaderMap headerMap,
        out CwtClaims? claims,
        CoseHeaderLabel? headerLabel = null)
    {
        claims = null;

        if (headerMap == null)
        {
            return false;
        }

        CoseHeaderLabel label = headerLabel ?? CWTClaimsHeaderLabels.CWTClaims;

        if (!headerMap.TryGetValue(label, out CoseHeaderValue cwtClaimsValue))
        {
            return false;
        }

        try
        {
            byte[] claimsBytes = cwtClaimsValue.EncodedValue.ToArray();
            claims = CwtClaims.FromCborBytes(claimsBytes);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Sets CWT Claims in a COSE header map.
    /// </summary>
    /// <param name="headerMap">The header map to write to.</param>
    /// <param name="claims">The CWT claims to set.</param>
    /// <param name="headerLabel">Optional custom header label. Defaults to label 15 (CWT Claims).</param>
    public static void SetCwtClaims(
        this CoseHeaderMap headerMap,
        CwtClaims claims,
        CoseHeaderLabel? headerLabel = null)
    {
        if (headerMap == null)
        {
            throw new ArgumentNullException(nameof(headerMap));
        }

        if (claims == null)
        {
            throw new ArgumentNullException(nameof(claims));
        }

        CoseHeaderLabel label = headerLabel ?? CWTClaimsHeaderLabels.CWTClaims;
        byte[] cborBytes = claims.ToCborBytes();
        CoseHeaderValue value = CoseHeaderValue.FromEncodedValue(cborBytes);

        headerMap[label] = value;
    }

    /// <summary>
    /// Removes CWT Claims from a COSE header map.
    /// </summary>
    /// <param name="headerMap">The header map to modify.</param>
    /// <param name="headerLabel">Optional custom header label. Defaults to label 15 (CWT Claims).</param>
    /// <returns>True if claims were removed; false if they were not present.</returns>
    public static bool RemoveCwtClaims(
        this CoseHeaderMap headerMap,
        CoseHeaderLabel? headerLabel = null)
    {
        if (headerMap == null)
        {
            return false;
        }

        CoseHeaderLabel label = headerLabel ?? CWTClaimsHeaderLabels.CWTClaims;
        return headerMap.Remove(label);
    }
}