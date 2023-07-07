// ---------------------------------------------------------------------------
// <copyright file="ICertificateChainBuilderExtensions.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ---------------------------------------------------------------------------

namespace CoseSign1.Certificates.Extensions;

/// <summary>
/// Extension methods for ICertificateChainBuilder.
/// </summary>
public static class ICertificateChainBuilderExtensions
{
    /// <summary>
    /// Builds an X.509 chain using the policy specified in the chain policy, but ignoring one or more failure conditions.
    /// </summary>
    /// <param name="builder">The current chain builder.</param>
    /// <param name="certificate">The certificate to build a chain for.</param>
    /// <param name="flagsToFilter">A set of chain status flags to ignore when evaluating success or failure.</param>
    /// <returns>True if the cert chain builds successfully; false otherwise.</returns>
    public static bool Build(this ICertificateChainBuilder builder, X509Certificate2 certificate, X509ChainStatusFlags flagsToFilter)
    {
        // Get the base result and generate status.
        bool result = builder.Build(certificate);

        // Return true if the unfiltered result is success, or if none of the ChainStatus elements contain status flags that are not in the filter set.
        return result || builder.ChainStatus.Any(st => (st.Status & ~flagsToFilter) == 0);
    }

    // Note: This extension method is needed because the .NetStandard 2.0 implementation of X509ChainBuilder does not
    // honor some ChainPolicy.VerificationFlags values.
}
