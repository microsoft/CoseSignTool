// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Benchmarks;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using CoseSign1.Certificates.Caching;

/// <summary>
/// Benchmarks for certificate cache performance, comparing cache hits (SHA-256 hash lookup)
/// vs cache misses (full ASN.1 certificate parsing).
/// </summary>
[MemoryDiagnoser]
[SimpleJob(warmupCount: 3, iterationCount: 20)]
public class CertificateCacheBenchmarks : IDisposable
{
    private CertificateCache cache = null!;
    private byte[] certDer = null!;

    [GlobalSetup]
    public void Setup()
    {
        this.cache = new CertificateCache();

        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest req = new("CN=CacheBenchmark", ecdsa, HashAlgorithmName.SHA256);
        using X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddHours(1));
        this.certDer = cert.RawData;

        // Warm cache
        _ = this.cache.GetOrCreate(this.certDer);
    }

    [GlobalCleanup]
    public void Cleanup() => this.Dispose();

    public void Dispose()
    {
        this.cache?.Dispose();
        GC.SuppressFinalize(this);
    }

    [Benchmark(Description = "CertificateCache hit (SHA-256 lookup)")]
    public X509Certificate2 CacheHit() =>
        this.cache.GetOrCreate(this.certDer);

    [Benchmark(Description = "CertificateCache miss (ASN.1 parse)")]
    public X509Certificate2 CacheMiss()
    {
        using CertificateCache freshCache = new();
        return freshCache.GetOrCreate(this.certDer);
    }
}
