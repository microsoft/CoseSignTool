// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Benchmarks;

using BenchmarkDotNet.Attributes;
using Cose.Headers;

/// <summary>
/// Benchmarks for CWT claims CBOR serialization, measuring cache hit vs miss performance.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(warmupCount: 3, iterationCount: 20)]
public class HeaderBenchmarks
{
    private CwtClaims warmedClaims = null!;

    [GlobalSetup]
    public void Setup()
    {
        this.warmedClaims = new CwtClaims
        {
            Issuer = "benchmark-issuer",
            Subject = "benchmark-subject",
            Audience = "benchmark-audience",
            IssuedAt = DateTimeOffset.UtcNow,
            NotBefore = DateTimeOffset.UtcNow,
            ExpirationTime = DateTimeOffset.UtcNow.AddHours(1)
        };

        // Warm the cache
        _ = this.warmedClaims.ToCborBytes();
    }

    [Benchmark(Description = "CwtClaims ToCborBytes cache hit")]
    public byte[] CwtClaims_ToCborBytes_CacheHit() =>
        this.warmedClaims.ToCborBytes();

    [Benchmark(Description = "CwtClaims ToCborBytes cache miss")]
    public byte[] CwtClaims_ToCborBytes_CacheMiss()
    {
        CwtClaims fresh = new()
        {
            Issuer = "benchmark-issuer",
            Subject = "benchmark-subject",
            Audience = "benchmark-audience",
            IssuedAt = DateTimeOffset.UtcNow,
            NotBefore = DateTimeOffset.UtcNow,
            ExpirationTime = DateTimeOffset.UtcNow.AddHours(1)
        };
        return fresh.ToCborBytes();
    }

    [Benchmark(Description = "CwtClaims FromCborBytes roundtrip")]
    public CwtClaims CwtClaims_FromCborBytes_Roundtrip()
    {
        byte[] bytes = this.warmedClaims.ToCborBytes();
        return CwtClaims.FromCborBytes(bytes);
    }
}
