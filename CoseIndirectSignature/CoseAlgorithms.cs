// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Ignore Spelling: Cose

namespace CoseIndirectSignature;

/// <summary>
/// COSE HashAlgorithm values from the IANA COSE Algorithms registry found at https://www.iana.org/assignments/cose/cose.xhtml#algorithms
/// </summary>
public enum CoseHashAlgorithm : long
{
    /// <summary>
    /// Reserved
    /// </summary>
    [Browsable(false)]
    Reserved = 0,
    /// <summary>
    /// SHA-1 Hash Algorithm
    /// </summary>
    /// <remarks>SHA1 is not recommended for new data.</remarks>
    [Obsolete("Use CoseAlgorithm.SHA256 instead")]
    SHA1 = -14,
    /// <summary>
    /// SHA-256 Truncated to 64 bits Hash Algorithm
    /// </summary>
    /// <remarks>SHA256 truncated to 64 bits is not recommended for new data.</remarks>
    [Obsolete("Use CoseAlgorithm.SHA256 instead")]
    SHA256Trunc64 = -15,
    /// <summary>
    /// SHA-256 Hash Algorithm
    /// </summary>
    SHA256 = -16,
    /// <summary>
    /// SHA-512 Truncated to 256 bits Hash Algorithm
    /// </summary>
    SHA512Truc256 = -17,
    /// <summary>
    /// SHAKE128 Hash Algorithm
    /// </summary>
    SHAKE128 = -18,
    /// <summary>
    /// SHA384 Hash Algorithm
    /// </summary>
    SHA384 = -43,
    /// <summary>
    /// SHA512 Hash Algorithm
    /// </summary>
    SHA512 = -44,
    /// <summary>
    /// SHAKE256 Hash Algorithm
    /// </summary>
    SHAKE256 = -45,
}
