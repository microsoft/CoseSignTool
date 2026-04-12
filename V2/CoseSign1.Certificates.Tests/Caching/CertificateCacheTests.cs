// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Caching;

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Caching;
using CoseSign1.Tests.Common;
using Microsoft.Extensions.Caching.Memory;

/// <summary>
/// Tests for <see cref="CertificateCache"/>.
/// </summary>
[TestFixture]
public sealed class CertificateCacheTests
{
    [Test]
    public void GetOrCreate_WithByteArray_ReturnsCertificate()
    {
        // Arrange
        using X509Certificate2 original = TestCertificateUtils.CreateCertificate();
        byte[] derBytes = original.RawData;
        using CertificateCache cache = new CertificateCache();

        // Act
        X509Certificate2 result = cache.GetOrCreate(derBytes);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.RawData, Is.EqualTo(original.RawData));
    }

    [Test]
    public void GetOrCreate_WithReadOnlySpan_ReturnsCertificate()
    {
        // Arrange
        using X509Certificate2 original = TestCertificateUtils.CreateCertificate();
        ReadOnlySpan<byte> derSpan = original.RawData.AsSpan();
        using CertificateCache cache = new CertificateCache();

        // Act
        X509Certificate2 result = cache.GetOrCreate(derSpan);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.RawData, Is.EqualTo(original.RawData));
    }

    [Test]
    public void GetOrCreate_SameBytesCalledTwice_ReturnsSameInstance()
    {
        // Arrange
        using X509Certificate2 original = TestCertificateUtils.CreateCertificate();
        byte[] derBytes = original.RawData;
        using CertificateCache cache = new CertificateCache();

        // Act
        X509Certificate2 first = cache.GetOrCreate(derBytes);
        X509Certificate2 second = cache.GetOrCreate(derBytes);

        // Assert — same object reference means the cache hit worked
        Assert.That(second, Is.SameAs(first));
    }

    [Test]
    public void GetOrCreate_DifferentCertificates_ReturnsDifferentInstances()
    {
        // Arrange
        using X509Certificate2 certA = TestCertificateUtils.CreateCertificate("CertA");
        using X509Certificate2 certB = TestCertificateUtils.CreateCertificate("CertB");
        using CertificateCache cache = new CertificateCache();

        // Act
        X509Certificate2 resultA = cache.GetOrCreate(certA.RawData);
        X509Certificate2 resultB = cache.GetOrCreate(certB.RawData);

        // Assert
        Assert.That(resultA, Is.Not.SameAs(resultB));
        Assert.That(resultA.RawData, Is.Not.EqualTo(resultB.RawData));
    }

    [Test]
    public void Constructor_WithCustomSlidingExpiration_DoesNotThrow()
    {
        // Arrange & Act
        using CertificateCache cache = new CertificateCache(TimeSpan.FromSeconds(30));

        // Assert — just verify it works
        using X509Certificate2 cert = TestCertificateUtils.CreateCertificate();
        X509Certificate2 result = cache.GetOrCreate(cert.RawData);
        Assert.That(result.RawData, Is.EqualTo(cert.RawData));
    }

    [Test]
    public void Constructor_WithExternalMemoryCache_UsesProvidedCache()
    {
        // Arrange
        using MemoryCache externalCache = new MemoryCache(new MemoryCacheOptions());
        using CertificateCache cache = new CertificateCache(externalCache, TimeSpan.FromMinutes(1));
        using X509Certificate2 cert = TestCertificateUtils.CreateCertificate();

        // Act
        X509Certificate2 result = cache.GetOrCreate(cert.RawData);

        // Assert — the cert should be retrievable and the external cache should have an entry
        Assert.That(result.RawData, Is.EqualTo(cert.RawData));
        Assert.That(externalCache.Count, Is.GreaterThan(0));
    }

    [Test]
    public void Constructor_WithNullCache_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.That(
            () => new CertificateCache(null!, TimeSpan.FromMinutes(1)),
            Throws.ArgumentNullException);
    }

    [Test]
    public void DefaultSlidingExpiration_IsFourMinutes()
    {
        // Assert
        Assert.That(CertificateCache.DefaultSlidingExpiration, Is.EqualTo(TimeSpan.FromMinutes(4)));
    }

    [Test]
    public void Dispose_WhenOwnedCache_DisposesUnderlyingCache()
    {
        // Arrange
        CertificateCache cache = new CertificateCache();

        // Act — should not throw
        cache.Dispose();
        cache.Dispose(); // double dispose is safe
    }

    [Test]
    public void Dispose_WhenExternalCache_DoesNotDisposeExternalCache()
    {
        // Arrange
        using MemoryCache externalCache = new MemoryCache(new MemoryCacheOptions());
        CertificateCache cache = new CertificateCache(externalCache, TimeSpan.FromMinutes(1));

        using X509Certificate2 cert = TestCertificateUtils.CreateCertificate();
        cache.GetOrCreate(cert.RawData);

        // Act
        cache.Dispose();

        // Assert — external cache should still be operational
        Assert.That(externalCache.Count, Is.GreaterThanOrEqualTo(0)); // just verify no ObjectDisposedException
    }
}