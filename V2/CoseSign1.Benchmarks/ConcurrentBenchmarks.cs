// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Benchmarks;

using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using CoseSign1.Certificates;
using CoseSign1.Certificates.Local;
using CoseSign1.Factories.Direct;

/// <summary>
/// Benchmarks for concurrent COSE Sign1 signing throughput.
/// Measures how well the signing pipeline scales across multiple threads.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(warmupCount: 2, iterationCount: 5)]
public class ConcurrentBenchmarks : IDisposable
{
    private DirectSignatureFactory factory = null!;
    private byte[] payload = null!;
    private X509Certificate2Collection chain = null!;

    [Params(1, 2, 4, 8)]
    public int Threads { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        CertificateChainFactory chainFactory = new();

        this.chain = chainFactory.CreateChain(opts =>
        {
            opts.KeyAlgorithm = KeyAlgorithm.ECDSA;
            opts.KeySize = 256;
            opts.LeafFirst = true;
        });

        CertificateSigningService service = CertificateSigningService.Create(
            this.chain[0],
            this.chain.ToArray());
        this.factory = new DirectSignatureFactory(service);

        this.payload = new byte[1024];
        Random.Shared.NextBytes(this.payload);
    }

    [GlobalCleanup]
    public void Cleanup() => this.Dispose();

    public void Dispose()
    {
        this.factory?.Dispose();

        if (this.chain is not null)
        {
            foreach (X509Certificate2 cert in this.chain)
            {
                cert.Dispose();
            }
        }

        GC.SuppressFinalize(this);
    }

    [Benchmark(Description = "Concurrent ES256 sign (50 ops/thread)")]
    public void ConcurrentSign()
    {
        int opsPerThread = 50;
        Task[] tasks = Enumerable.Range(0, this.Threads).Select(_ =>
            Task.Run(() =>
            {
                for (int i = 0; i < opsPerThread; i++)
                {
                    this.factory.CreateCoseSign1MessageBytes(
                        this.payload, "application/octet-stream");
                }
            })).ToArray();
        Task.WaitAll(tasks);
    }
}
