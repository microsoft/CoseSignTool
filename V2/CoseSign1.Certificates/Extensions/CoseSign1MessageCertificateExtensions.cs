// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Extensions;

using System.Formats.Cbor;
using System.Security.Cryptography.Cose;

/// <summary>
/// Extension methods for extracting certificates from CoseSign1Message.
/// Modernized from V1 with simpler, stateless implementations.
/// </summary>
public static class CoseSign1MessageCertificateExtensions
{
    /// <summary>
    /// Extracts the signing certificate from x5t header + x5chain.
    /// The signing certificate is identified by matching the x5t (certificate thumbprint)
    /// against the certificates in the x5chain.
    /// </summary>
    /// <param name="message">The COSE Sign1 message.</param>
    /// <param name="certificate">The extracted signing certificate.</param>
    /// <param name="headerLocation">Specifies which headers to search for certificate data.</param>
    /// <returns>True when the signing certificate was found; otherwise false.</returns>
    public static bool TryGetSigningCertificate(
        this CoseSign1Message message,
        out X509Certificate2? certificate,
        CoseHeaderLocation headerLocation = CoseHeaderLocation.Protected)
    {
        certificate = null;

        if (message == null)
        {
            return false;
        }

        // Get the certificate chain
        if (!message.TryGetCertificateChain(out X509Certificate2Collection? chain, headerLocation))
        {
            return false;
        }

        // Get the thumbprint
        if (!message.TryGetCertificateThumbprint(out CoseX509Thumbprint? thumbprint, headerLocation))
        {
            return false;
        }

        // Find the certificate in the chain that matches the thumbprint
        foreach (var cert in chain)
        {
            if (thumbprint.Match(cert))
            {
                certificate = cert;
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Extracts certificate chain from x5chain header (33).
    /// </summary>
    /// <param name="message">The COSE Sign1 message.</param>
    /// <param name="chain">The extracted certificate chain.</param>
    /// <param name="headerLocation">Specifies which headers to search for certificate data.</param>
    /// <returns>True when a certificate chain was found; otherwise false.</returns>
    public static bool TryGetCertificateChain(
        this CoseSign1Message message,
        out X509Certificate2Collection? chain,
        CoseHeaderLocation headerLocation = CoseHeaderLocation.Protected)
    {
        chain = null;

        if (message == null)
        {
            return false;
        }

        var label = CertificateHeaderContributor.HeaderLabels.X5Chain;
        var headers = headerLocation.HasFlag(CoseHeaderLocation.Unprotected)
            ? message.ProtectedHeaders.Concat(message.UnprotectedHeaders)
            : message.ProtectedHeaders;

        foreach (var kvp in headers)
        {
            if (kvp.Key.Equals(label))
            {
                try
                {
                    var reader = new CborReader(kvp.Value.EncodedValue);
                    var certificates = new List<X509Certificate2>();

                    if (reader.PeekState() == CborReaderState.ByteString)
                    {
                        // Single certificate
                        var certBytes = reader.ReadByteString();
#if NET10_0_OR_GREATER
                        certificates.Add(X509CertificateLoader.LoadCertificate(certBytes));
#else
                        certificates.Add(new X509Certificate2(certBytes));
#endif
                    }
                    else if (reader.PeekState() == CborReaderState.StartArray)
                    {
                        // Array of certificates
                        int? certCount = reader.ReadStartArray();
                        for (int i = 0; certCount == null || i < certCount; i++)
                        {
                            if (reader.PeekState() == CborReaderState.EndArray)
                            {
                                break;
                            }

                            var certBytes = reader.ReadByteString();
#if NET10_0_OR_GREATER
                            certificates.Add(X509CertificateLoader.LoadCertificate(certBytes));
#else
                            certificates.Add(new X509Certificate2(certBytes));
#endif
                        }
                        reader.ReadEndArray();
                    }
                    else
                    {
                        return false;
                    }

                    chain = new X509Certificate2Collection(certificates.ToArray());
                    return true;
                }
                catch
                {
                    return false;
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Extracts extra certificates from x5bag header (32).
    /// </summary>
    /// <param name="message">The COSE Sign1 message.</param>
    /// <param name="certificates">The extracted certificates.</param>
    /// <param name="headerLocation">Specifies which headers to search for certificate data.</param>
    /// <returns>True when certificates were found; otherwise false.</returns>
    public static bool TryGetExtraCertificates(
        this CoseSign1Message message,
        out X509Certificate2Collection? certificates,
        CoseHeaderLocation headerLocation = CoseHeaderLocation.Protected)
    {
        certificates = null;

        if (message == null)
        {
            return false;
        }

        var label = CertificateHeaderContributor.HeaderLabels.X5Bag;
        var headers = headerLocation.HasFlag(CoseHeaderLocation.Unprotected)
            ? message.ProtectedHeaders.Concat(message.UnprotectedHeaders)
            : message.ProtectedHeaders;

        foreach (var kvp in headers)
        {
            if (kvp.Key.Equals(label))
            {
                try
                {
                    var reader = new CborReader(kvp.Value.EncodedValue);
                    var certList = new List<X509Certificate2>();

                    if (reader.PeekState() == CborReaderState.ByteString)
                    {
                        // Single certificate
                        var certBytes = reader.ReadByteString();
#if NET10_0_OR_GREATER
                        certList.Add(X509CertificateLoader.LoadCertificate(certBytes));
#else
                        certList.Add(new X509Certificate2(certBytes));
#endif
                    }
                    else if (reader.PeekState() == CborReaderState.StartArray)
                    {
                        // Array of certificates
                        int? certCount = reader.ReadStartArray();
                        for (int i = 0; certCount == null || i < certCount; i++)
                        {
                            if (reader.PeekState() == CborReaderState.EndArray)
                            {
                                break;
                            }

                            var certBytes = reader.ReadByteString();
#if NET10_0_OR_GREATER
                            certList.Add(X509CertificateLoader.LoadCertificate(certBytes));
#else
                            certList.Add(new X509Certificate2(certBytes));
#endif
                        }
                        reader.ReadEndArray();
                    }
                    else
                    {
                        return false;
                    }

                    certificates = new X509Certificate2Collection(certList.ToArray());
                    return true;
                }
                catch
                {
                    return false;
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Extracts thumbprint from x5t header (34).
    /// </summary>
    /// <param name="message">The COSE Sign1 message.</param>
    /// <param name="thumbprint">The extracted thumbprint.</param>
    /// <param name="headerLocation">Specifies which headers to search for certificate data.</param>
    /// <returns>True when a thumbprint was found; otherwise false.</returns>
    public static bool TryGetCertificateThumbprint(
        this CoseSign1Message message,
        out CoseX509Thumbprint? thumbprint,
        CoseHeaderLocation headerLocation = CoseHeaderLocation.Protected)
    {
        thumbprint = null;

        if (message == null)
        {
            return false;
        }

        var label = CertificateHeaderContributor.HeaderLabels.X5T;
        var headers = headerLocation.HasFlag(CoseHeaderLocation.Unprotected)
            ? message.ProtectedHeaders.Concat(message.UnprotectedHeaders)
            : message.ProtectedHeaders;

        foreach (var kvp in headers)
        {
            if (kvp.Key.Equals(label))
            {
                try
                {
                    var reader = new CborReader(kvp.Value.EncodedValue);
                    thumbprint = CoseX509Thumbprint.Deserialize(reader);
                    return true;
                }
                catch
                {
                    return false;
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Verifies the COSE signature using the signing certificate from the message.
    /// Automatically detects and uses the appropriate algorithm (RSA, ECDsa, or ML-DSA).
    /// </summary>
    /// <param name="message">The COSE Sign1 message to verify</param>
    /// <param name="payload">The detached payload bytes (required only for detached signatures where message.Content is null)</param>
    /// <param name="headerLocation">Specifies which headers to search for certificate data</param>
    /// <returns>True if the signature is valid, false otherwise</returns>
    public static bool VerifySignature(
        this CoseSign1Message message,
        byte[]? payload = null,
        CoseHeaderLocation headerLocation = CoseHeaderLocation.Protected)
    {
        if (message == null)
        {
            return false;
        }

        if (!message.TryGetSigningCertificate(out X509Certificate2? certificate, headerLocation))
        {
            return false;
        }

        // If message has embedded content, verify embedded.
        // Otherwise, payload is required for detached verification.
        bool isEmbedded = message.Content != null;
        if (!isEmbedded && (payload == null || payload.Length == 0))
        {
            return false;
        }

        try
        {
            // Prefer verifying with the raw public key types for RSA/ECDsa.
            // The COSE library derives padding/hash from the message's 'alg' header.
            var rsa = certificate.GetRSAPublicKey();
            if (rsa != null)
            {
                return isEmbedded
                    ? message.VerifyEmbedded(rsa)
                    : message.VerifyDetached(rsa, payload!);
            }

            var ecdsa = certificate.GetECDsaPublicKey();
            if (ecdsa != null)
            {
                return isEmbedded
                    ? message.VerifyEmbedded(ecdsa)
                    : message.VerifyDetached(ecdsa, payload!);
            }

#pragma warning disable SYSLIB5006 // ML-DSA APIs are marked as preview
            // ML-DSA (Post-Quantum) currently uses the CoseKey surface.
            var mlDsa = certificate.GetMLDsaPublicKey();
            if (mlDsa != null)
            {
                var coseKey = new CoseKey(mlDsa);
                return isEmbedded
                    ? message.VerifyEmbedded(coseKey)
                    : message.VerifyDetached(coseKey, payload!);
            }
#pragma warning restore SYSLIB5006

            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }


}