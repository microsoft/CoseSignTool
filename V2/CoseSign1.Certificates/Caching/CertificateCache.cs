// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Caching;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Cose.Abstractions;
using Microsoft.Extensions.Caching.Memory;

/// <summary>
/// Caches parsed <see cref="X509Certificate2"/> instances keyed by SHA-256 hash of their DER bytes.
/// Hashing raw bytes is ~1000x cheaper than full ASN.1 certificate parsing, making cache lookups
/// extremely fast compared to cache misses.
/// </summary>
/// <remarks>
/// <para>
/// Uses a sliding expiration window so frequently-accessed certificates (leaf certs in active
/// validation) remain cached, while infrequently-used certs (old issuer chains) are evicted.
/// </para>
/// <para>
/// Thread-safe: backed by <see cref="IMemoryCache"/> which is thread-safe by contract.
/// </para>
/// <para>
/// <b>Disposal:</b> Cached <see cref="X509Certificate2"/> instances are disposed when evicted
/// via <see cref="PostEvictionCallbackRegistration"/>. Consumers must not dispose certificates
/// obtained from this cache — the cache owns their lifetime.
/// </para>
/// </remarks>
public sealed class CertificateCache : IDisposable
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string CacheKeyPrefix = "cert:";
        public const string HexSeparator = "-";
        public const string HexSeparatorReplacement = "";
    }

    /// <summary>Default sliding expiration: 4 minutes.</summary>
    public static readonly TimeSpan DefaultSlidingExpiration = TimeSpan.FromMinutes(4);

    private readonly IMemoryCache cache;
    private readonly MemoryCacheEntryOptions entryOptions;
    private readonly bool ownedCache;
    private bool disposed;

    /// <summary>
    /// Creates a certificate cache with the default sliding expiration (4 minutes).
    /// </summary>
    public CertificateCache()
        : this(new MemoryCache(new MemoryCacheOptions()), DefaultSlidingExpiration, ownedCache: true)
    {
    }

    /// <summary>
    /// Creates a certificate cache with a custom sliding expiration.
    /// </summary>
    /// <param name="slidingExpiration">How long a certificate stays cached after last access.</param>
    public CertificateCache(TimeSpan slidingExpiration)
        : this(new MemoryCache(new MemoryCacheOptions()), slidingExpiration, ownedCache: true)
    {
    }

    /// <summary>
    /// Creates a certificate cache backed by an external <see cref="IMemoryCache"/>.
    /// </summary>
    /// <param name="cache">The memory cache instance to use.</param>
    /// <param name="slidingExpiration">How long a certificate stays cached after last access.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="cache"/> is null.</exception>
    public CertificateCache(IMemoryCache cache, TimeSpan slidingExpiration)
        : this(cache, slidingExpiration, ownedCache: false)
    {
    }

    private CertificateCache(IMemoryCache cache, TimeSpan slidingExpiration, bool ownedCache)
    {
        Guard.ThrowIfNull(cache);
        this.cache = cache;
        this.ownedCache = ownedCache;
        this.entryOptions = new MemoryCacheEntryOptions
        {
            SlidingExpiration = slidingExpiration,
        };
        // Register eviction callback to dispose X509Certificate2 when removed from cache
        this.entryOptions.RegisterPostEvictionCallback(static (key, value, reason, state) =>
        {
            if (value is X509Certificate2 cert)
            {
                cert.Dispose();
            }
        });
    }

    /// <summary>
    /// Gets or creates a cached <see cref="X509Certificate2"/> from DER-encoded bytes.
    /// </summary>
    /// <param name="derBytes">The DER-encoded certificate bytes.</param>
    /// <returns>A cached or newly-parsed X509Certificate2 instance.</returns>
    /// <remarks>
    /// Cache key is the SHA-256 hash of <paramref name="derBytes"/> — computing
    /// a 32-byte hash is dramatically cheaper than full ASN.1 certificate parsing.
    /// </remarks>
    public X509Certificate2 GetOrCreate(ReadOnlySpan<byte> derBytes)
    {
        // Compute SHA-256 hash as cache key (32 bytes → hex string)
        string cacheKey = ComputeCacheKey(derBytes);

        if (this.cache.TryGetValue(cacheKey, out X509Certificate2? cached) && cached is not null)
        {
            return cached;
        }

        // Cache miss: full ASN.1 parse
#if NET10_0_OR_GREATER
        X509Certificate2 cert = X509CertificateLoader.LoadCertificate(derBytes);
#else
        X509Certificate2 cert = new X509Certificate2(derBytes.ToArray());
#endif
        this.cache.Set(cacheKey, cert, this.entryOptions);
        return cert;
    }

    /// <summary>
    /// Gets or creates a cached <see cref="X509Certificate2"/> from DER-encoded byte array.
    /// </summary>
    /// <param name="derBytes">The DER-encoded certificate bytes.</param>
    /// <returns>A cached or newly-parsed X509Certificate2 instance.</returns>
    public X509Certificate2 GetOrCreate(byte[] derBytes)
    {
        return this.GetOrCreate(derBytes.AsSpan());
    }

    /// <summary>
    /// Computes a SHA-256-based cache key from DER bytes.
    /// </summary>
    private static string ComputeCacheKey(ReadOnlySpan<byte> data)
    {
#if NET5_0_OR_GREATER
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(data, hash);
        return string.Concat(ClassStrings.CacheKeyPrefix, Convert.ToHexString(hash));
#else
        using SHA256 sha = SHA256.Create();
        byte[] hash = sha.ComputeHash(data.ToArray());
        return string.Concat(ClassStrings.CacheKeyPrefix, BitConverter.ToString(hash).Replace(ClassStrings.HexSeparator, ClassStrings.HexSeparatorReplacement));
#endif
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (!this.disposed)
        {
            if (this.ownedCache && this.cache is IDisposable disposable)
            {
                disposable.Dispose();
            }

            this.disposed = true;
        }
    }
}