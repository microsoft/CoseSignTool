// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests;

/// <summary>
/// Custom class to test <see cref="X509Certificate2CoseSigningKeyProvider"/> protected methods.
/// </summary>
internal class TestX509Certificate2SigningKeyProvider : X509Certificate2CoseSigningKeyProvider
{
    public TestX509Certificate2SigningKeyProvider(ICertificateChainBuilder builder, X509Certificate2 cert) : base(builder, cert) { }
    public TestX509Certificate2SigningKeyProvider(X509Certificate2 cert) : base(cert) { }

    public IEnumerable<X509Certificate2> TestGetCertificateChain(X509ChainSortOrder sortOrder) => base.GetCertificateChain(sortOrder);

    public X509Certificate2 TestGetSigningCertificate() => base.GetSigningCertificate();
}
