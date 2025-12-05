// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Headers.Extensions;

using System.Security.Cryptography.Cose;

/// <summary>
/// Extension methods for accessing CWT Claims from CoseSign1Message objects.
/// </summary>
public static class CoseSign1MessageCwtClaimsExtensions
{
    /// <summary>
    /// Attempts to extract CWT Claims from a CoseSign1Message.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to extract claims from.</param>
    /// <param name="claims">When this method returns, contains the extracted CWT claims if successful; otherwise, null.</param>
    /// <param name="useUnprotectedHeaders">If true, extracts claims from unprotected headers; otherwise, from protected headers (default).</param>
    /// <param name="headerLabel">Optional custom header label to use instead of the default CWT Claims label (15). If not specified, uses CWTClaimsHeaderLabels.CWTClaims.</param>
    /// <returns>true if CWT claims were found and successfully parsed; otherwise, false.</returns>
    public static bool TryGetCwtClaims(this CoseSign1Message message, out CwtClaims? claims, bool useUnprotectedHeaders = false, CoseHeaderLabel? headerLabel = null)
    {
        claims = null;

        if (message == null)
        {
            return false;
        }

        // Get CWT Claims from the specified headers (protected by default, unprotected if flag is set)
        CoseHeaderMap headers = useUnprotectedHeaders ? message.UnprotectedHeaders : message.ProtectedHeaders;
        return headers.TryGetCwtClaims(out claims, headerLabel);
    }
}
