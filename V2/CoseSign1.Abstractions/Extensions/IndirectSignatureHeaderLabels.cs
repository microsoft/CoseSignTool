// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace System.Security.Cryptography.Cose;

/// <summary>
/// COSE header labels for indirect signature formats (RFC 9054).
/// </summary>
public static class IndirectSignatureHeaderLabels
{
    /// <summary>
    /// PayloadHashAlg (258) - COSE algorithm identifier for the hash algorithm used on the payload.
    /// </summary>
    public static readonly CoseHeaderLabel PayloadHashAlg = new(258);

    /// <summary>
    /// PreimageContentType (259) - Content type of the original payload before hashing.
    /// </summary>
    public static readonly CoseHeaderLabel PreimageContentType = new(259);

    /// <summary>
    /// PayloadLocation (260) - Optional location where the original payload can be retrieved.
    /// </summary>
    public static readonly CoseHeaderLabel PayloadLocation = new(260);
}
