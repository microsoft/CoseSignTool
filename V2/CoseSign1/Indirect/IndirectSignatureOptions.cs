// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;

namespace CoseSign1.Indirect;

/// <summary>
/// Options specific to indirect signature operations.
/// Indirect signatures sign a hash of the payload rather than the payload itself.
/// </summary>
public class IndirectSignatureOptions : SigningOptions
{
    /// <summary>
    /// Gets or sets the hash algorithm to use for the payload.
    /// Default is SHA256.
    /// </summary>
    public HashAlgorithmName HashAlgorithm { get; set; } = HashAlgorithmName.SHA256;

    /// <summary>
    /// Gets or sets the location of the payload (optional).
    /// This can be used to store a URL or reference to where the actual payload can be retrieved.
    /// </summary>
    public string? PayloadLocation { get; set; }
}