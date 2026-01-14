// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Trust;

/// <summary>
/// Controls how certificate subject/issuer strings are matched.
/// </summary>
public enum CertificateIdentityMatchKind
{
    /// <summary>
    /// Case-insensitive exact match.
    /// </summary>
    Exact,

    /// <summary>
    /// Case-insensitive substring match.
    /// </summary>
    Contains,
}
