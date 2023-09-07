// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseX509;

/// <summary>
/// Specifies whether a COSE signature is found valid or invalid.
/// </summary>
public enum ValidationResultTypes
{
    /// <summary>
    /// The COSE signature is valid and chains to a trusted root.
    /// </summary>
    Success,

    /// <summary>
    /// The COSE signature is valid but does not chain to a trusted root.
    /// </summary>
    ValidUntrusted,

    /// <summary>
    /// The COSE signature is invalid.
    /// </summary>
    Invalid
}