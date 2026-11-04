// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Extensions;

/// <summary>
/// Extension methods for <see cref="X509Certificate2"/>.
/// </summary>
public static class X509Certificate2Extensions
{
    /// <summary>
    /// Gets the certificate's ML-DSA public key, if it has one and the platform supports ML-DSA.
    /// </summary>
    /// <param name="certificate">The certificate to read the public key from.</param>
    /// <returns>
    /// A new <see cref="MLDsa"/> instance that the caller owns and should dispose, or null if the certificate does not have
    /// an ML-DSA public key or the platform does not support ML-DSA.
    /// </returns>
    public static MLDsa? GetMLDsaPublicKeyIfSupported(this X509Certificate2 certificate)
    {
        if (certificate is null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        try
        {
#pragma warning disable SYSLIB5006 // The ML-DSA certificate accessors are marked experimental in .NET.
            return certificate.GetMLDsaPublicKey();
#pragma warning restore SYSLIB5006
        }
        catch (PlatformNotSupportedException ex)
        {
            Trace.TraceWarning($"The certificate has an ML-DSA public key, but this platform does not support ML-DSA: {ex.Message}");
            return null;
        }
    }
}
