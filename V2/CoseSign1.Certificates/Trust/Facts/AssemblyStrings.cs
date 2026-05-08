// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Trust.Facts;

using System.Diagnostics.CodeAnalysis;

/// <summary>
/// String-literal pool for facts shipped from the certificate trust pack. The repo's
/// <c>StringLiteralAnalyzer</c> requires user-visible literals (including <c>[TrustFactId]</c>
/// values) to be sourced from a central <c>ClassStrings</c> static so id renames are diff-able
/// in one place.
/// </summary>
[ExcludeFromCodeCoverage]
internal static class AssemblyStrings
{
    internal const string FactIdCertificateSigningKeyTrust = "certificate-signing-key-trust/v1";
    internal const string FactIdX509ChainElementIdentity = "x509-chain-element-identity/v1";
    internal const string FactIdX509ChainTrusted = "x509-chain-trusted/v1";
    internal const string FactIdX509SigningCertificateBasicConstraints = "x509-cert-basic-constraints/v1";
    internal const string FactIdX509SigningCertificateEku = "x509-cert-eku/v1";
    internal const string FactIdX509SigningCertificateIdentityAllowed = "x509-cert-identity-allowed/v1";
    internal const string FactIdX509SigningCertificateIdentity = "x509-cert-identity/v1";
    internal const string FactIdX509SigningCertificateKeyUsage = "x509-cert-key-usage/v1";
    internal const string FactIdX509X5ChainCertificateIdentity = "x509-x5chain-cert-identity/v1";
}
