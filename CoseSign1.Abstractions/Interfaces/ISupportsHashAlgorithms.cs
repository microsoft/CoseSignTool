// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions.Interfaces;

/// <summary>
/// Exposes the hash algorithms supported by a signing key provider.
/// </summary>
public interface ISupportsHashAlgorithms
{
    /// <summary>
    /// Gets the hash algorithms supported by the signing key provider.
    /// </summary>
    public IReadOnlyCollection<HashAlgorithmName> SupportedHashAlgorithms { get; }
}
