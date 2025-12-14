// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local;

/// <summary>
/// Factory interface for creating X.509 certificates.
/// </summary>
/// <remarks>
/// <para>
/// Implementations provide certificate generation functionality with customizable options.
/// The default implementation (<see cref="EphemeralCertificateFactory"/>) creates certificates
/// with software-generated keys suitable for testing and development.
/// </para>
/// <para>
/// For production scenarios with hardware-protected keys, use a factory configured with
/// an appropriate <see cref="IPrivateKeyProvider"/> implementation.
/// </para>
/// </remarks>
public interface ICertificateFactory
{
    /// <summary>
    /// Gets the private key provider used by this factory.
    /// </summary>
    IPrivateKeyProvider KeyProvider { get; }

    /// <summary>
    /// Creates a certificate with the specified options.
    /// </summary>
    /// <param name="configure">Action to configure certificate options.</param>
    /// <returns>A new certificate. Caller is responsible for disposal.</returns>
    /// <exception cref="ArgumentNullException">Thrown when configure is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when certificate creation fails.</exception>
    X509Certificate2 CreateCertificate(Action<CertificateOptions> configure);

    /// <summary>
    /// Creates a certificate with default options.
    /// </summary>
    /// <returns>A new certificate with default settings. Caller is responsible for disposal.</returns>
    X509Certificate2 CreateCertificate();

    /// <summary>
    /// Asynchronously creates a certificate with the specified options.
    /// </summary>
    /// <param name="configure">Action to configure certificate options.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task<X509Certificate2> CreateCertificateAsync(
        Action<CertificateOptions> configure,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a public-only certificate (no private key) from an existing certificate.
    /// </summary>
    /// <param name="certificate">The source certificate.</param>
    /// <returns>A new certificate containing only the public key. Caller is responsible for disposal.</returns>
    /// <remarks>
    /// Useful for scenarios where you need to distribute a certificate without the private key,
    /// such as creating trust anchors or intermediate CA certificates for chain validation.
    /// </remarks>
    static X509Certificate2 CreatePublicOnlyCertificate(X509Certificate2 certificate)
    {
        if (certificate == null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        return X509CertificateLoader.LoadCertificate(certificate.Export(X509ContentType.Cert));
    }
}