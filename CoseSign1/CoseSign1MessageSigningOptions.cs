// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1;

/// <summary>
/// Options applied to a single COSE signing operation.
/// </summary>
public sealed class CoseSign1MessageSigningOptions
{
    /// <summary>
    /// Gets or sets the hash algorithm used for signing.
    /// When not specified, the factory or signing key provider default is used.
    /// </summary>
    public HashAlgorithmName? HashAlgorithm { get; set; }

    /// <summary>
    /// Gets or sets the RSA signature padding used for signing.
    /// This option is ignored for non-RSA signing keys.
    /// </summary>
    public RSASignaturePadding RsaSignaturePadding { get; set; } = RSASignaturePadding.Pss;
}
