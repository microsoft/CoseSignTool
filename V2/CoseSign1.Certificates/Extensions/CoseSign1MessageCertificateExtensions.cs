// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Extensions;

using System.Formats.Cbor;
using System.Security.Cryptography.Cose;
using CoseSign1.Certificates.Caching;
using CoseSign1.Certificates.Telemetry;

/// <summary>
/// Extension methods for extracting certificates from CoseSign1Message.
/// Modernized from V1 with simpler, stateless implementations.
/// </summary>
public static class CoseSign1MessageCertificateExtensions
{
    internal static class ClassStrings
    {
        public const string CertChainExceedsMaxLengthPrefix = "Certificate chain exceeds maximum length of ";
        public const string HeaderX5Chain = "x5chain";
        public const string HeaderX5Bag = "x5bag";
        public const string HeaderX5T = "x5t";
        public const string MethodVerifySignature = "VerifySignature";
    }

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
        return TryGetSigningCertificate(message, out certificate, headerLocation, certificateCache: null);
    }

    /// <summary>
    /// Extracts the signing certificate from x5t header + x5chain, using an optional
    /// <see cref="CertificateCache"/> to avoid re-parsing previously-seen DER certificates.
    /// </summary>
    /// <param name="message">The COSE Sign1 message.</param>
    /// <param name="certificate">The extracted signing certificate.</param>
    /// <param name="headerLocation">Specifies which headers to search for certificate data.</param>
    /// <param name="certificateCache">Optional certificate cache for DER parse avoidance.</param>
    /// <returns>True when the signing certificate was found; otherwise false.</returns>
    public static bool TryGetSigningCertificate(
        this CoseSign1Message message,
        out X509Certificate2? certificate,
        CoseHeaderLocation headerLocation,
        CertificateCache? certificateCache)
    {
        certificate = null;

        if (message == null)
        {
            return false;
        }

        // Get the certificate chain
        if (!message.TryGetCertificateChain(out X509Certificate2Collection? chain, headerLocation, certificateCache))
        {
            return false;
        }

        // Get the thumbprint
        if (!message.TryGetCertificateThumbprint(out CoseX509Thumbprint? thumbprint, headerLocation))
        {
            return false;
        }

        // Find the certificate in the chain that matches the thumbprint
        foreach (X509Certificate2 cert in chain)
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
        return TryGetCertificateChain(message, out chain, headerLocation, certificateCache: null);
    }

    /// <summary>
    /// Extracts certificate chain from x5chain header (33), using an optional
    /// <see cref="CertificateCache"/> to avoid re-parsing previously-seen DER certificates.
    /// </summary>
    /// <param name="message">The COSE Sign1 message.</param>
    /// <param name="chain">The extracted certificate chain.</param>
    /// <param name="headerLocation">Specifies which headers to search for certificate data.</param>
    /// <param name="certificateCache">Optional certificate cache for DER parse avoidance.</param>
    /// <returns>True when a certificate chain was found; otherwise false.</returns>
    /// <exception cref="CborContentException">Thrown when the certificate chain exceeds the maximum allowed length.</exception>
    public static bool TryGetCertificateChain(
        this CoseSign1Message message,
        out X509Certificate2Collection? chain,
        CoseHeaderLocation headerLocation,
        CertificateCache? certificateCache)
    {
        chain = null;

        if (message == null)
        {
            return false;
        }

        CoseHeaderLabel label = CertificateHeaderContributor.HeaderLabels.X5Chain;
        IEnumerable<KeyValuePair<CoseHeaderLabel, CoseHeaderValue>> headers = headerLocation.HasFlag(CoseHeaderLocation.Unprotected)
            ? message.ProtectedHeaders.Concat(message.UnprotectedHeaders)
            : message.ProtectedHeaders;

        foreach (KeyValuePair<CoseHeaderLabel, CoseHeaderValue> kvp in headers)
        {
            if (kvp.Key.Equals(label))
            {
                try
                {
                    CborReader reader = new CborReader(kvp.Value.EncodedValue);
                    List<X509Certificate2> certificates = new List<X509Certificate2>();

                    if (reader.PeekState() == CborReaderState.ByteString)
                    {
                        // Single certificate
                        byte[] certBytes = reader.ReadByteString();
                        certificates.Add(ParseOrCacheCertificate(certBytes, certificateCache));
                    }
                    else if (reader.PeekState() == CborReaderState.StartArray)
                    {
                        // Array of certificates
                        const int MaxCertificatesInChain = 100;
                        int? certCount = reader.ReadStartArray();
                        for (int i = 0; certCount == null || i < certCount; i++)
                        {
                            if (i >= MaxCertificatesInChain)
                            {
                                throw new CborContentException(string.Concat(ClassStrings.CertChainExceedsMaxLengthPrefix, MaxCertificatesInChain.ToString(System.Globalization.CultureInfo.InvariantCulture)));
                            }

                            if (reader.PeekState() == CborReaderState.EndArray)
                            {
                                break;
                            }

                            byte[] certBytes = reader.ReadByteString();
                            certificates.Add(ParseOrCacheCertificate(certBytes, certificateCache));
                        }
                        reader.ReadEndArray();
                    }
                    else
                    {
                        return false;
                    }

                    chain = new X509Certificate2Collection(certificates.ToArray());
                    CoseSign1CertificateEventSource.Log.CertificateChainExtracted(ClassStrings.HeaderX5Chain, certificates.Count);
                    return true;
                }
                catch (CborContentException ex)
                {
                    CoseSign1CertificateEventSource.Log.CertificateHeaderParseFailed(ClassStrings.HeaderX5Chain, nameof(CborContentException), ex.Message);
                    return false;
                }
                catch (CryptographicException ex)
                {
                    CoseSign1CertificateEventSource.Log.CertificateDerDecodeFailed(ClassStrings.HeaderX5Chain, nameof(CryptographicException), ex.Message);
                    return false;
                }
                catch (OverflowException ex)
                {
                    CoseSign1CertificateEventSource.Log.CertificateHeaderParseFailed(ClassStrings.HeaderX5Chain, nameof(OverflowException), ex.Message);
                    return false;
                }
                catch (InvalidOperationException ex)
                {
                    CoseSign1CertificateEventSource.Log.CertificateHeaderParseFailed(ClassStrings.HeaderX5Chain, nameof(InvalidOperationException), ex.Message);
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
        return TryGetExtraCertificates(message, out certificates, headerLocation, certificateCache: null);
    }

    /// <summary>
    /// Extracts extra certificates from x5bag header (32), using an optional
    /// <see cref="CertificateCache"/> to avoid re-parsing previously-seen DER certificates.
    /// </summary>
    /// <param name="message">The COSE Sign1 message.</param>
    /// <param name="certificates">The extracted certificates.</param>
    /// <param name="headerLocation">Specifies which headers to search for certificate data.</param>
    /// <param name="certificateCache">Optional certificate cache for DER parse avoidance.</param>
    /// <returns>True when certificates were found; otherwise false.</returns>
    /// <exception cref="CborContentException">Thrown when the certificate chain exceeds the maximum allowed length.</exception>
    public static bool TryGetExtraCertificates(
        this CoseSign1Message message,
        out X509Certificate2Collection? certificates,
        CoseHeaderLocation headerLocation,
        CertificateCache? certificateCache)
    {
        certificates = null;

        if (message == null)
        {
            return false;
        }

        CoseHeaderLabel label = CertificateHeaderContributor.HeaderLabels.X5Bag;
        IEnumerable<KeyValuePair<CoseHeaderLabel, CoseHeaderValue>> headers = headerLocation.HasFlag(CoseHeaderLocation.Unprotected)
            ? message.ProtectedHeaders.Concat(message.UnprotectedHeaders)
            : message.ProtectedHeaders;

        foreach (KeyValuePair<CoseHeaderLabel, CoseHeaderValue> kvp in headers)
        {
            if (kvp.Key.Equals(label))
            {
                try
                {
                    CborReader reader = new CborReader(kvp.Value.EncodedValue);
                    List<X509Certificate2> certList = new List<X509Certificate2>();

                    if (reader.PeekState() == CborReaderState.ByteString)
                    {
                        // Single certificate
                        byte[] certBytes = reader.ReadByteString();
                        certList.Add(ParseOrCacheCertificate(certBytes, certificateCache));
                    }
                    else if (reader.PeekState() == CborReaderState.StartArray)
                    {
                        // Array of certificates
                        const int MaxCertificatesInChain = 100;
                        int? certCount = reader.ReadStartArray();
                        for (int i = 0; certCount == null || i < certCount; i++)
                        {
                            if (i >= MaxCertificatesInChain)
                            {
                                throw new CborContentException(string.Concat(ClassStrings.CertChainExceedsMaxLengthPrefix, MaxCertificatesInChain.ToString(System.Globalization.CultureInfo.InvariantCulture)));
                            }

                            if (reader.PeekState() == CborReaderState.EndArray)
                            {
                                break;
                            }

                            byte[] certBytes = reader.ReadByteString();
                            certList.Add(ParseOrCacheCertificate(certBytes, certificateCache));
                        }
                        reader.ReadEndArray();
                    }
                    else
                    {
                        return false;
                    }

                    certificates = new X509Certificate2Collection(certList.ToArray());
                    CoseSign1CertificateEventSource.Log.CertificateChainExtracted(ClassStrings.HeaderX5Bag, certList.Count);
                    return true;
                }
                catch (CborContentException ex)
                {
                    CoseSign1CertificateEventSource.Log.CertificateHeaderParseFailed(ClassStrings.HeaderX5Bag, nameof(CborContentException), ex.Message);
                    return false;
                }
                catch (CryptographicException ex)
                {
                    CoseSign1CertificateEventSource.Log.CertificateDerDecodeFailed(ClassStrings.HeaderX5Bag, nameof(CryptographicException), ex.Message);
                    return false;
                }
                catch (OverflowException ex)
                {
                    CoseSign1CertificateEventSource.Log.CertificateHeaderParseFailed(ClassStrings.HeaderX5Bag, nameof(OverflowException), ex.Message);
                    return false;
                }
                catch (InvalidOperationException ex)
                {
                    CoseSign1CertificateEventSource.Log.CertificateHeaderParseFailed(ClassStrings.HeaderX5Bag, nameof(InvalidOperationException), ex.Message);
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
                catch (CborContentException ex)
                {
                    CoseSign1CertificateEventSource.Log.CertificateHeaderParseFailed(ClassStrings.HeaderX5T, nameof(CborContentException), ex.Message);
                    return false;
                }
                catch (CryptographicException ex)
                {
                    CoseSign1CertificateEventSource.Log.ThumbprintMatchFailed(0, nameof(CryptographicException), ex.Message);
                    return false;
                }
                catch (CoseX509FormatException ex)
                {
                    CoseSign1CertificateEventSource.Log.CertificateHeaderParseFailed(ClassStrings.HeaderX5T, nameof(CoseX509FormatException), ex.Message);
                    return false;
                }
                catch (OverflowException ex)
                {
                    CoseSign1CertificateEventSource.Log.CertificateHeaderParseFailed(ClassStrings.HeaderX5T, nameof(OverflowException), ex.Message);
                    return false;
                }
                catch (InvalidOperationException ex)
                {
                    CoseSign1CertificateEventSource.Log.CertificateHeaderParseFailed(ClassStrings.HeaderX5T, nameof(InvalidOperationException), ex.Message);
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
        catch (CryptographicException ex)
        {
            CoseSign1CertificateEventSource.Log.CertificateDerDecodeFailed(ClassStrings.MethodVerifySignature, nameof(CryptographicException), ex.Message);
            return false;
        }
    }

    /// <summary>
    /// Parses a certificate from DER bytes, using the cache when available.
    /// Falls back to direct parsing when <paramref name="certificateCache"/> is null.
    /// </summary>
    private static X509Certificate2 ParseOrCacheCertificate(byte[] derBytes, CertificateCache? certificateCache)
    {
        if (certificateCache is not null)
        {
            return certificateCache.GetOrCreate(derBytes);
        }

#if NET10_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(derBytes);
#else
        return new X509Certificate2(derBytes);
#endif
    }
}