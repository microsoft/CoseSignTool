﻿// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Interfaces;

/// <summary>
/// An interface for building certificate chains for a given certificate.
/// </summary>
public interface ICertificateChainBuilder
{
    /// <summary>
    /// Gets the certificates in the chain.
    /// </summary>
    /// <returns>
    /// The certificates as an IReadOnlyCollection of X509Certificate2 objects.
    /// </returns>
    public IReadOnlyCollection<X509Certificate2> ChainElements { get; }

    /// <summary>
    /// Gets or sets the <see cref="X509ChainPolicy"/> to use when building an X.509 certificate chain.
    /// </summary>
    /// <returns>
    /// The <see cref="X509ChainPolicy"/> object associated with this X.509 chain.
    /// </returns>
    public X509ChainPolicy ChainPolicy { get; set; }

    /// <summary>
    /// Gets the status of each element in an <see cref="X509Chain"/> object.
    /// </summary>
    /// <returns>
    /// An array of <see cref="X509ChainStatus"/> objects.
    /// </returns>
    public X509ChainStatus[] ChainStatus { get; }

    /// <summary>
    /// Builds an X.509 chain using the policy specified in the <see cref="X509ChainPolicy"/>.
    /// </summary>
    /// <param name="certificate">An <see cref="X509Certificate2"/> object</param>
    /// <returns>true if the X.509 certificate is valid; otherwise, false.</returns>
    public bool Build(X509Certificate2 certificate);
}

