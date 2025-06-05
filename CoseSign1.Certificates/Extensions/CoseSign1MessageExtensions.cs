// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Extensions;

using System.Diagnostics;
using System.Formats.Cbor;
using System.IO;
using System.Runtime.Caching;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates;

/// <summary>
/// Extension methods for the <see cref="CoseSign1Message"/> objects related to certificate operations.
/// </summary>
/// <remarks>
/// Logging is done through Trace.TraceError and Debug.WriteLine.
/// </remarks>
public static class CoseSign1MessageExtensions
{
    private static readonly ConcurrentDictionary<string, object> Locks = new();
    /// <summary>
    /// Tries to get the leaf node certificate of the current CoseSign1Message object and provides certificate chain status information.
    /// </summary>
    /// <param name="msg">The current CoseSign1Message object.</param>
    /// <param name="signingCert">The leaf node signing certificate if found.</param>
    /// <param name="allowUnprotected">True if the unprotected headers should be allowed to contribute, false (default - more secure) otherwise.</param>
    /// <returns>True if there is a signing certificate; false otherwise.</returns>
    /// <exception cref="CoseX509FormatException">The certificates could not be read from the header.</exception>
    public static bool TryGetSigningCertificate(
        this CoseSign1Message msg,
        out X509Certificate2? signingCert,
        bool allowUnprotected = false)
    {
        signingCert = null;
        CoseX509Thumprint? thumbprint = null;

        if (msg == null)
        {
            Trace.TraceWarning($"{nameof(msg)} is null and cannot produce a signing certificate.");
            return false;
        }

        int msgHashCode = msg.GetHashCode();
        string cacheEntry = $"{nameof(CoseSign1MessageExtensions)}_{nameof(TryGetSigningCertificate)}_{msgHashCode}";
        lock (Locks.GetOrAdd(cacheEntry, _ => new object()))
        {
            try
            {
                // check the in-memory cache for the object to avoid needing to re-do all the cbor reader work for at least some quick period of time.
                if (MemoryCache.Default[cacheEntry] is X509Certificate2 memoryCacheInstance)
                {
                    signingCert = memoryCacheInstance;
                    Debug.WriteLine($"Returning cert from cache for cache entry {cacheEntry} for message: {msgHashCode}");
                    return true;
                }

                if (!msg.TryGetCertificateChain(out List<X509Certificate2>? certChain, allowUnprotected))
                {
                    Trace.TraceWarning($"Failed to extract certificate chain from message: {msgHashCode}");
                    return false;
                }

                CborReader reader;
                IEnumerable<KeyValuePair<CoseHeaderLabel, CoseHeaderValue>> searchableHeaders = allowUnprotected
                    ? msg.ProtectedHeaders.Union(msg.UnprotectedHeaders)
                    : msg.ProtectedHeaders;

                foreach (KeyValuePair<CoseHeaderLabel, CoseHeaderValue> kvp in searchableHeaders)
                {
                    reader = new CborReader(kvp.Value.EncodedValue);

                    if (kvp.Key == CertificateCoseHeaderLabels.X5T)
                    {
                        thumbprint = CoseX509Thumprint.Deserialize(reader);
                        break;
                    }
                }

                if (thumbprint == null)
                {
                    Trace.TraceWarning($"Failed to extract a thumbprint from the x5t header of COSE message: {msgHashCode}");
                    return false;
                }

                signingCert = certChain.FirstOrDefault(thumbprint.Match);
                if (signingCert != null)
                {
                    // cache the certificate so we can return it faster in the future.
                    MemoryCache.Default.Add(cacheEntry, signingCert, new CacheItemPolicy() { AbsoluteExpiration = DateTimeOffset.UtcNow.AddMinutes(5) });
                }
                else
                {
                    Trace.TraceWarning($"Failed to find a certificate matching the x5t thumbprint of {thumbprint} in the certificate chain present in the x5chain header, unable to obtain the signing certificate from msg: {msgHashCode}");
                }
            }
            finally
            {
                // remove the item from locks that way we don't leak memory on lock objects.
                _ = Locks.TryRemove(cacheEntry, out _);
            }
        }

        return signingCert is not null;
    }

    /// <summary>
    /// Extracts certificates from the <see cref="CertificateCoseHeaderLabels.X5Chain"/> header label.
    /// </summary>
    /// <param name="msg">The message to attempt to extract the header from.</param>
    /// <param name="certChain">The list of certificates found if successful; null otherwise.</param>
    /// <param name="allowUnprotected">True if the unprotected headers should be allowed to contribute, false (default - more secure) otherwise.</param>
    /// <returns>True if the header was found and extracted, False if the header was not found, or the contents were not a proper cert list.</returns>
    public static bool TryGetCertificateChain(
        this CoseSign1Message msg,
        out List<X509Certificate2>? certChain,
        bool allowUnprotected = false,
        ICoseSigningKeyProvider? keyProvider = null) =>
            msg.TryGetCertificateList(CertificateCoseHeaderLabels.X5Chain, out certChain, allowUnprotected);

    /// <summary>
    /// Extracts certificates from the <see cref="CertificateCoseHeaderLabels.X5Bag"/> header label.
    /// </summary>
    /// <param name="msg">The message to attempt to extract the header from.</param>
    /// <param name="certChain">The list of certificates found if successful; null otherwise.</param>
    /// <param name="allowUnprotected">True if the unprotected headers should be allowed to contribute, false (default - more secure) otherwise.</param>
    /// <returns>True if the header was found and extracted, False if the header was not found, or the contents were not a proper cert list.</returns>
    public static bool TryGetExtraCertificates(
        this CoseSign1Message msg,
        out List<X509Certificate2>? certChain,
        bool allowUnprotected = false) =>
            msg.TryGetCertificateList(CertificateCoseHeaderLabels.X5Bag, out certChain, allowUnprotected);

    /// <summary>
    /// Attempts to get a certificate list from the specified <see cref="CoseHeaderLabel"/>
    /// </summary>
    /// <param name="msg">The <see cref="CoseSign1Message"/> this extension method is operating on.</param>
    /// <param name="labelForCertList">The label which should contain the certificate list.</param>
    /// <param name="certList">The certificate list if found encoded in the label.</param>
    /// <param name="allowUnprotected">true if the unprotected headers should also be searched for the label.</param>
    /// <returns>true if the certificate list was found, false otherwise.</returns>
    private static bool TryGetCertificateList(
        this CoseSign1Message msg,
        CoseHeaderLabel labelForCertList,
        out List<X509Certificate2>? certList,
        bool allowUnprotected = false)
    {
        certList = null;

        if (msg == null)
        {
            Trace.TraceWarning($"{nameof(msg)} is null and cannot produce a certificate list.");
            return false;
        }

        int msgHashCode = msg.GetHashCode();
        string cacheEntry = $"{nameof(CoseSign1MessageExtensions)}_{labelForCertList.GetHashCode()}_{msgHashCode}";
        lock (Locks.GetOrAdd(cacheEntry, _ => new object()))
        {
            try
            {
                // check the in-memory cache for the object to avoid needing to re-do all the cbor reader work for at least some quick period of time.
                if (MemoryCache.Default[cacheEntry] is List<X509Certificate2> memoryCacheInstance)
                {
                    Debug.WriteLine($"Returning certList from cache for cache entry {cacheEntry} for message: {msgHashCode}");
                    certList = memoryCacheInstance;
                    return true;
                }

                CborReader reader;
                IEnumerable<KeyValuePair<CoseHeaderLabel, CoseHeaderValue>> searchableHeaders = allowUnprotected
                    ? msg.ProtectedHeaders.Union(msg.UnprotectedHeaders)
                    : msg.ProtectedHeaders;

                DateTimeOffset expiry = DateTimeOffset.UtcNow.AddMinutes(5);
                foreach (KeyValuePair<CoseHeaderLabel, CoseHeaderValue> kvp in searchableHeaders)
                {
                    reader = new CborReader(kvp.Value.EncodedValue);

                    if (kvp.Key == labelForCertList)
                    {
                        certList = [];
                        bool certificatesRead = reader.TryReadCertificateSet(ref certList, out _);
                        if (certificatesRead)
                        {
                            // cache is a performance optimization for hitting an object quickly within 5 minutes.
                            MemoryCache.Default.Add(cacheEntry, certList, new CacheItemPolicy() { AbsoluteExpiration = expiry });
                        }
                        else
                        {
                            Trace.TraceWarning($"Failed to read certificate set in message: {msgHashCode}, returning false.");
                        }

                        return certificatesRead;
                    }
                }
            }
            finally
            {
                // remove the item from locks that way we don't leak memory on lock objects.
                _ = Locks.TryRemove(cacheEntry, out _);
            }
        }

        return false;
    }

    /// <summary>
    /// Attempts to verify the COSE_Sign1 message using the embedded signing certificate if present and the message is not detached.
    /// </summary>
    /// <param name="@this">The COSE_Sign1 message to verify.</param>
    /// <param name="allowUnprotected">True if the unprotected headers should be allowed to contribute, false (default - more secure) otherwise.</param>
    /// <returns>True if the message is verified with the embedded signing certificate; false otherwise.</returns>
    public static bool VerifyEmbeddedWithCertificate(
        this CoseSign1Message @this,
        bool allowUnprotected = false)
    {
        if(@this is null)
        {
            Trace.TraceWarning($"{nameof(@this)} is null and cannot be verified.");
            return false;
        }

        AsymmetricAlgorithm? publicKey = @this.GetEmbeddedPublicKey(allowUnprotected, out bool foundCert);
        if (!foundCert || publicKey is null)
        {
            return false;
        }

        // If the message is detached, we cannot verify without the payload.
        if (@this.Content is null)
        {
            Trace.TraceWarning($"Message is a detached payload; cannot verify without payload.");
            return false;
        }

        try
        {
            return @this.VerifyEmbedded(publicKey);
        }
        catch (CryptographicException ex)
        {
            Trace.TraceWarning($"Verification failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Attempts to verify the COSE_Sign1 message using the embedded signing certificate and the provided detached content (byte array).
    /// </summary>
    /// <param name="@this">The COSE_Sign1 message to verify.</param>
    /// <param name="detachedContent">The detached content to verify against.</param>
    /// <param name="allowUnprotected">True if the unprotected headers should be allowed to contribute, false (default - more secure) otherwise.</param>
    /// <returns>True if the message is verified with the embedded signing certificate; false otherwise.</returns>
    public static bool VerifyDetachedWithCertificate(this CoseSign1Message @this, byte[] detachedContent, bool allowUnprotected = false)
    {
        if(@this is null)
        {
            Trace.TraceWarning($"{nameof(@this)} is null and cannot be verified.");
            return false;
        }

        if (detachedContent is null || detachedContent.Length == 0)
        {
            Trace.TraceWarning($"Detached content is null or empty; cannot verify.");
            return false;
        }

        AsymmetricAlgorithm? publicKey = @this.GetEmbeddedPublicKey(allowUnprotected, out bool foundCert);
        if (!foundCert || publicKey is null)
        {
            return false;
        }
        try
        {
            return @this.VerifyDetached(publicKey, detachedContent);
        }
        catch (CryptographicException ex)
        {
            Trace.TraceWarning($"Verification failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Attempts to verify the COSE_Sign1 message using the embedded signing certificate and the provided detached content (ReadOnlySpan).
    /// </summary>
    /// <param name="@this">The COSE_Sign1 message to verify.</param>
    /// <param name="detachedContent">The detached content to verify against.</param>
    /// <param name="allowUnprotected">True if the unprotected headers should be allowed to contribute, false (default - more secure) otherwise.</param>
    /// <returns>True if the message is verified with the embedded signing certificate; false otherwise.</returns>
    public static bool VerifyDetachedWithCertificate(this CoseSign1Message @this, ReadOnlySpan<byte> detachedContent, bool allowUnprotected = false)
    {
        if(@this is null)
        {
            Trace.TraceWarning($"{nameof(@this)} is null and cannot be verified.");
            return false;
        }

        if (detachedContent.IsEmpty)
        {
            Trace.TraceWarning($"Detached content is empty; cannot verify.");
            return false;
        }

        AsymmetricAlgorithm? publicKey = @this.GetEmbeddedPublicKey(allowUnprotected, out bool foundCert);
        if (!foundCert || publicKey is null)
        {
            return false;
        }
        try
        {
            return @this.VerifyDetached(publicKey, detachedContent);
        }
        catch (CryptographicException ex)
        {
            Trace.TraceWarning($"Verification failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Attempts to verify the COSE_Sign1 message using the embedded signing certificate and the provided detached content (Stream).
    /// </summary>
    /// <param name="@this">The COSE_Sign1 message to verify.</param>
    /// <param name="detachedContent">The detached content to verify against.</param>
    /// <param name="allowUnprotected">True if the unprotected headers should be allowed to contribute, false (default - more secure) otherwise.</param>
    /// <returns>True if the message is verified with the embedded signing certificate; false otherwise.</returns>
    public static bool VerifyDetachedWithCertificate(this CoseSign1Message @this, Stream detachedContent, bool allowUnprotected = false)
    {
        if(@this is null)
        {
            Trace.TraceWarning($"{nameof(@this)} is null and cannot be verified.");
            return false;
        }

        if(detachedContent is null)
        {
            Trace.TraceWarning($"Detached content stream is null; cannot verify.");
            return false;
        }

        AsymmetricAlgorithm? publicKey = @this.GetEmbeddedPublicKey(allowUnprotected, out bool foundCert);
        if (!foundCert || publicKey is null)
        {
            return false;
        }
        try
        {
            return @this.VerifyDetached(publicKey, detachedContent);
        }
        catch (CryptographicException ex)
        {
            Trace.TraceWarning($"Verification failed: {ex.Message}");
            return false;
        }
    }

    // Shared logic to extract the public key from the embedded signing certificate
    private static AsymmetricAlgorithm? GetEmbeddedPublicKey(this CoseSign1Message @this, bool allowUnprotected, out bool foundCert)
    {
        foundCert = false;
        if (!@this.TryGetSigningCertificate(out X509Certificate2 signingCert, allowUnprotected) || signingCert == null)
        {
            Trace.TraceWarning($"No signing certificate found in message.");
            return null;
        }
        foundCert = true;
        AsymmetricAlgorithm? publicKey = (AsymmetricAlgorithm?)signingCert.GetRSAPublicKey() ?? signingCert.GetECDsaPublicKey();
        if (publicKey is null)
        {
            Trace.TraceWarning($"Signing certificate does not contain a valid public key for verification.");
            return null;
        }
        return publicKey;
    }
}
