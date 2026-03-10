// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace System.Security.Cryptography.Cose;

/// <summary>
/// Specifies which header locations to search when looking up COSE headers.
/// </summary>
[Flags]
public enum CoseHeaderLocation
{
    /// <summary>
    /// Search only protected headers.
    /// </summary>
    Protected = 1,

    /// <summary>
    /// Search only unprotected headers.
    /// </summary>
    Unprotected = 2,

    /// <summary>
    /// Search both protected and unprotected headers.
    /// Protected headers are searched first.
    /// </summary>
    Any = Protected | Unprotected
}
