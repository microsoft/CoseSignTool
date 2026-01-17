// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local;

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Abstractions;

/// <summary>
/// Signing key provider that uses X509Certificate2 private keys directly.
/// Supports RSA, ECDsa, and ML-DSA (Post-Quantum) algorithms.
/// </summary>
public class DirectSigningKeyProvider : ISigningKeyProvider
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ErrorCertificateMustHavePrivateKeyForLocalSigning = "Certificate must have a private key for local signing.";
    }

    private readonly X509Certificate2 Certificate;
    private CoseKey? CoseKeyField;
    private readonly object CoseKeyLock = new();
    private bool Disposed;

    /// <summary>
    /// Initializes a new instance of DirectSigningKeyProvider.
    /// </summary>
    /// <param name="certificate">Certificate with private key</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificate"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="certificate"/> does not have a private key.</exception>
    public DirectSigningKeyProvider(X509Certificate2 certificate)
    {
        Guard.ThrowIfNull(certificate);
        Certificate = certificate;

        if (!certificate.HasPrivateKey)
        {
            throw new ArgumentException(ClassStrings.ErrorCertificateMustHavePrivateKeyForLocalSigning, nameof(certificate));
        }
    }

    /// <inheritdoc/>
    public CoseKey GetCoseKey()
    {
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

            CoseKeyField = X509CertificateCoseKeyFactory.CreateFromPrivateKey(Certificate);
            return CoseKeyField;
        }
    }

    /// <inheritdoc/>
    public bool IsRemote => false;

    /// <inheritdoc/>
    public void Dispose()
    {
        if (Disposed)
        {
            return;
        }

        // Don't dispose certificate - caller owns it
        Disposed = true;
        GC.SuppressFinalize(this);
    }
}