// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

using System.Diagnostics.CodeAnalysis;

/// <summary>
/// Well-known signing root identifiers for certificate-based signing.
/// </summary>
public static class CertificateSigningRootIds
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string X509Value = "x509";
    }

    /// <summary>
    /// The signing root id for X.509 certificate-based signing.
    /// </summary>
    public const string X509 = ClassStrings.X509Value;
}
