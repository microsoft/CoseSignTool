// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// A minimal <see cref="ISigningKey"/> implementation wrapping an X509Certificate2 resolved from COSE message headers.
/// This class is used by <see cref="CertificateSigningKeyResolver"/> to provide signing key
/// material to subsequent validation stages.
/// </summary>
/// <remarks>
/// <para>
/// This is a lightweight wrapper designed for validation scenarios where we only need to pass
/// the resolved key material to signature validators and assertion providers. It uses the
/// certificate's public key for verification operations.
/// </para>
/// <para>
/// For signing scenarios that require service context and metadata, use
/// <see cref="CertificateSigningServiceKey"/> instead.
/// </para>
/// </remarks>
internal sealed class X509CertificateSigningKey : ISigningKey
{
    private readonly X509Certificate2 SigningCertificate;
    private readonly X509Certificate2Collection? CertificateChain;
    private CoseKey? CoseKeyField;
    private readonly object CoseKeyLock = new();
    private bool Disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="X509CertificateSigningKey"/> class.
    /// </summary>
    /// <param name="signingCertificate">The signing certificate extracted from message headers.</param>
    /// <param name="certificateChain">Optional certificate chain from x5chain header.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="signingCertificate"/> is null.</exception>
    public X509CertificateSigningKey(X509Certificate2 signingCertificate, X509Certificate2Collection? certificateChain = null)
    {
        SigningCertificate = signingCertificate ?? throw new ArgumentNullException(nameof(signingCertificate));
        CertificateChain = certificateChain;
    }

    /// <summary>
    /// Gets the signing certificate.
    /// </summary>
    public X509Certificate2 Certificate => SigningCertificate;

    /// <summary>
    /// Gets the certificate chain, if available.
    /// </summary>
    public X509Certificate2Collection? Chain => CertificateChain;

    /// <inheritdoc/>
    public CoseKey GetCoseKey()
    {
#if NET6_0_OR_GREATER
        ObjectDisposedException.ThrowIf(Disposed, this);
#else
        if (Disposed)
        {
            throw new ObjectDisposedException(GetType().FullName);
        }
#endif

        if (CoseKeyField != null)
        {
            return CoseKeyField;
        }

        lock (CoseKeyLock)
        {
            if (CoseKeyField != null)
            {
                return CoseKeyField;
            }

            CoseKeyField = X509CertificateCoseKeyFactory.CreateFromPublicKey(SigningCertificate);
            return CoseKeyField;
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (Disposed)
        {
            return;
        }

        Disposed = true;
        // Note: We don't dispose the certificate or chain as they were passed in
        // and may be owned by the caller. The CoseKey is managed internally.
    }
}
