// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions;
using CoseSign1.Certificates;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Remote;

namespace CoseSign1.Integration.Tests.Remote;

/// <summary>
/// Test implementation of a remote certificate signing service that uses TestRemoteCertificateSource.
/// This demonstrates how a remote signing service implementation would work - each remote service
/// (Azure Key Vault, Trusted Signing, HSM, etc.) would implement their own signing service.
/// </summary>
internal sealed class DirectSigningRemoteCertificateSigningService : CertificateSigningService
{
    private readonly RemoteCertificateSource RemoteCertificateSource;

    public DirectSigningRemoteCertificateSigningService(
        X509Certificate2 certificate,
        RemoteCertificateSource remoteCertificateSource,
        ICertificateChainBuilder chainBuilder)
        : base(isRemote: true)
    {
        _ = certificate ?? throw new ArgumentNullException(nameof(certificate));
        RemoteCertificateSource = remoteCertificateSource ?? throw new ArgumentNullException(nameof(remoteCertificateSource));
    }

    public DirectSigningRemoteCertificateSigningService(
        X509Certificate2 certificate,
        RemoteCertificateSource remoteCertificateSource,
        IReadOnlyList<X509Certificate2> certificateChain)
        : base(isRemote: true)
    {
        _ = certificate ?? throw new ArgumentNullException(nameof(certificate));
        RemoteCertificateSource = remoteCertificateSource ?? throw new ArgumentNullException(nameof(remoteCertificateSource));
    }

    protected override ISigningKey GetSigningKey(SigningContext context)
    {
        return new RemoteSigningKeyProvider(RemoteCertificateSource, this);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            // Remote certificate source is owned by the caller, don't dispose it here
        }
        base.Dispose(disposing);
    }
}