// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Extensions;

/// <summary>
/// Extension methods for <see cref="X509Certificate2"/>.
/// </summary>
public static class X509Certificate2Extensions
{
    /// <summary>
    /// Gets a <see cref="CoseKey"/> that verifies COSE signatures made with the certificate's ML-DSA public key.
    /// </summary>
    /// <param name="certificate">The certificate to read the public key from.</param>
    /// <returns>
    /// A verification key, or null if the certificate does not have an ML-DSA public key or the platform does not support ML-DSA.
    /// </returns>
    public static CoseKey? GetMLDsaVerificationKey(this X509Certificate2 certificate)
    {
        if (certificate is null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        try
        {
#pragma warning disable SYSLIB5006 // The ML-DSA certificate accessors and CoseKey(MLDsa) are marked experimental in .NET.
            MLDsa? publicKey = certificate.GetMLDsaPublicKey();
            return publicKey is null ? null : new CoseKey(publicKey);
#pragma warning restore SYSLIB5006
        }
        catch (PlatformNotSupportedException ex)
        {
            Trace.TraceWarning($"The certificate has an ML-DSA public key, but this platform does not support ML-DSA: {ex.Message}");
            return null;
        }
    }
}
