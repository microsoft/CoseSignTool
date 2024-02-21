// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
namespace CoseSign1.AzureCodeSigning;

using Azure.CodeSigning.Client.CryptoProvider;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates;
using CoseSign1.Certificates.Local;
using System.Linq;

/// <summary>
/// A class that provides a CoseSigningKeyProvider for Azure Code Signing.
/// </summary>
public class AzureCodeSigningCoseSigningKeyProvider : CertificateCoseSigningKeyProvider
{
    private readonly AzCodeSignContext AzCodeSignContext;

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureCodeSigningCoseSigningKeyProvider"/> class with the specified <see cref="Azure.CodeSigning.CertificateProfileClient"/>.
    /// </summary>
    /// <param name="azCodeSignContext"></param>
    public AzureCodeSigningCoseSigningKeyProvider(AzCodeSignContext azCodeSignContext)
    {
        AzCodeSignContext = azCodeSignContext;
    }

    /// <inheritdoc/>
    protected override IEnumerable<X509Certificate2> GetCertificateChain(X509ChainSortOrder sortOrder)
    {
        // first ensure the chain is initialized.
        if(!AzCodeSignContext.IsChainInitialized)
        {
            AzCodeSignContext.InitializeChain();
        }

        // fetch the chain from the context.
        List<X509Certificate2> chain = AzCodeSignContext.Chain;
        if(chain == null || chain.Count == 0)
        {
            throw new InvalidOperationException("The certificate chain is not available.");
        }

        if(sortOrder == X509ChainSortOrder.RootFirst)
        {
            // Self-Signed (root) certificates have the same issuer and subject
            if (chain[0].Issuer == chain[0].Subject)
            {
                // it's already root first, so return the chain as is.
                return chain;
            }
        }
        else
        {
            // leaf certificates have different issuer and subject and > 1 certificate in the chain.
            if (chain[0].Issuer != chain[0].Subject && chain.Count > 1)
            {
                // it's already leaf first, so return the chain as is.
                return chain;
            }
        }

        // reverse the chain list to match the requested order.
        chain.Reverse();

        // return the chain.
        return chain;
    }

    /// <inheritdoc/>
    protected override X509Certificate2 GetSigningCertificate() => GetCertificateChain(X509ChainSortOrder.LeafFirst).First();

    /// <inheritdoc/>
    protected override ECDsa? ProvideECDsaKey(bool publicKey = false)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc/>
    protected override RSA? ProvideRSAKey(bool publicKey = false) => new RSAAzCodeSign(AzCodeSignContext);
}
