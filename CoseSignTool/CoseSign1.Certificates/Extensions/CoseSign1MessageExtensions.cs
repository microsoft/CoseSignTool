// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Extensions;

/// <summary>
/// Extension methods for the <see cref="CoseSign1Message"/> objects related to certificate operations.
/// </summary>
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
        [NotNullWhen(returnValue: true)] out X509Certificate2? signingCert,
        bool allowUnprotected = false)
    {
        signingCert = null;
        CoseX509Thumprint? thumbprint = null;

        string cacheEntry = $"{nameof(CoseSign1MessageExtensions)}_{nameof(TryGetSigningCertificate)}_{msg.GetHashCode()}";
        lock (Locks.GetOrAdd(cacheEntry, _ => new object()))
        {
            // check the in-memory cache for the object to avoid needing to re-do all the cbor reader work for at least some quick period of time.
            if (MemoryCache.Default[cacheEntry] is X509Certificate2 memoryCacheInstance)
            {
                signingCert = memoryCacheInstance;
                return true;
            }

            if (!msg.TryGetCertificateChain(out List<X509Certificate2>? certChain, allowUnprotected))
            {
                return false;
            }

            CborReader reader;
            IEnumerable<KeyValuePair<CoseHeaderLabel, CoseHeaderValue>> searchableHeaders = allowUnprotected
                ? msg.ProtectedHeaders.Union(msg.UnprotectedHeaders)
                : msg.ProtectedHeaders;

            foreach ((CoseHeaderLabel label, CoseHeaderValue value) in searchableHeaders)
            {
                reader = new CborReader(value.EncodedValue);

                if (label == CertificateCoseHeaderLabels.X5T)
                {
                    thumbprint = CoseX509Thumprint.Deserialize(reader);
                    break;
                }
            }

            if (thumbprint == null)
            {
                return false;
            }

            signingCert = certChain.FirstOrDefault(thumbprint.Match);
            if (signingCert != null)
            {
                // cache the certificate so we can return it faster in the future.
                MemoryCache.Default.Add(cacheEntry, signingCert, new CacheItemPolicy() { AbsoluteExpiration = DateTimeOffset.UtcNow.AddMinutes(5) });
            }
        }

        // remove the item from locks that way we don't leak memory on lock objects.
        _ = Locks.TryRemove(cacheEntry, out _);

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
        [NotNullWhen(returnValue: true)] out List<X509Certificate2>? certChain,
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
        [NotNullWhen(returnValue: true)] out List<X509Certificate2>? certChain,
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
        [NotNullWhen(returnValue: true)] out List<X509Certificate2>? certList,
        bool allowUnprotected = false)
    {
        certList = null;
        string cacheEntry = $"{nameof(CoseSign1MessageExtensions)}_{labelForCertList.GetHashCode()}_{msg.GetHashCode()}";
        lock (Locks.GetOrAdd(cacheEntry, _ => new object()))
        {
            // check the in-memory cache for the object to avoid needing to re-do all the cbor reader work for at least some quick period of time.
            if (MemoryCache.Default[cacheEntry] is List<X509Certificate2> memoryCacheInstance)
            {
                certList = memoryCacheInstance;
                return true;
            }

            CborReader reader;
            IEnumerable<KeyValuePair<CoseHeaderLabel, CoseHeaderValue>> searchableHeaders = allowUnprotected
                ? msg.ProtectedHeaders.Union(msg.UnprotectedHeaders)
                : msg.ProtectedHeaders;

            DateTimeOffset expiry = DateTimeOffset.UtcNow.AddMinutes(5);
            foreach ((CoseHeaderLabel label, CoseHeaderValue value) in searchableHeaders)
            {
                reader = new CborReader(value.EncodedValue);

                if (label == labelForCertList)
                {
                    certList = new List<X509Certificate2>();
                    bool certificatesRead = reader.TryReadCertificateSet(ref certList, out _);
                    if (certificatesRead)
                    {
                        // cache is a performance optimization for hitting an object quickly within 5 minutes.
                        MemoryCache.Default.Add(cacheEntry, certList, new CacheItemPolicy() { AbsoluteExpiration = expiry });
                    }

                    return certificatesRead;
                }
            }
        }
        // remove the item from locks that way we don't leak memory on lock objects.
        _ = Locks.TryRemove(cacheEntry, out _);

        return false;
    }
}
