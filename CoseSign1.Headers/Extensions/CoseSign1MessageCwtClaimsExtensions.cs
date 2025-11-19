// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.Cose;

namespace CoseSign1.Headers.Extensions;

/// <summary>
/// Extension methods for accessing CWT Claims from CoseSign1Message objects.
/// </summary>
public static class CoseSign1MessageCwtClaimsExtensions
{
    /// <summary>
    /// Attempts to extract CWT Claims from the protected headers of a CoseSign1Message.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to extract claims from.</param>
    /// <param name="claims">When this method returns, contains the extracted CWT claims if successful; otherwise, null.</param>
    /// <returns>true if CWT claims were found and successfully parsed; otherwise, false.</returns>
    public static bool TryGetCwtClaims(this CoseSign1Message message, out CwtClaims? claims)
    {
        claims = null;

        if (message == null)
        {
            return false;
        }

        // Try to get CWT Claims from protected headers (label 13)
        if (!message.ProtectedHeaders.TryGetValue(
            CWTClaimsHeaderLabels.CWTClaims,
            out CoseHeaderValue cwtClaimsValue))
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
}
