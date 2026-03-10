// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Trust.Facts;

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Validation.Trust.Facts;

/// <summary>
/// Fact summarizing X.509 chain trust evaluation for the primary signing key certificate.
/// </summary>
public sealed class X509ChainTrustedFact : ISigningKeyFact
{
    /// <inheritdoc />
    public TrustFactScope Scope => TrustFactScope.SigningKey;

    /// <summary>
    /// Initializes a new instance of the <see cref="X509ChainTrustedFact"/> class.
    /// </summary>
    /// <param name="chainBuilt">True if a chain could be built; otherwise, false.</param>
    /// <param name="isTrusted">True if the chain is considered trusted; otherwise, false.</param>
    /// <param name="statusFlags">Combined chain status flags.</param>
    /// <param name="statusSummary">Optional human-readable status summary.</param>
    /// <param name="elementCount">Number of elements observed in the chain.</param>
    public X509ChainTrustedFact(
        bool chainBuilt,
        bool isTrusted,
        X509ChainStatusFlags statusFlags,
        string? statusSummary,
        int elementCount)
    {
        ChainBuilt = chainBuilt;
        IsTrusted = isTrusted;
        StatusFlags = statusFlags;
        StatusSummary = statusSummary;
        ElementCount = elementCount;
    }

    /// <summary>
    /// Gets a value indicating whether a chain could be built.
    /// </summary>
    public bool ChainBuilt { get; }

    /// <summary>
    /// Gets a value indicating whether the chain is considered trusted.
    /// </summary>
    public bool IsTrusted { get; }

    /// <summary>
    /// Gets combined chain status flags.
    /// </summary>
    public X509ChainStatusFlags StatusFlags { get; }

    /// <summary>
    /// Gets a human-readable status summary (optional).
    /// </summary>
    public string? StatusSummary { get; }

    /// <summary>
    /// Gets the number of elements observed in the evaluated chain.
    /// </summary>
    public int ElementCount { get; }
}
