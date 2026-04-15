// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Benchmarks;

using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using CoseSign1.Certificates;
using CoseSign1.Certificates.Local;
using CoseSign1.Factories.Direct;

/// <summary>
/// Benchmarks for streaming (Stream-based) COSE Sign1 signature creation.
/// Measures signing throughput for large payloads passed as MemoryStream.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(warmupCount: 2, iterationCount: 10)]
public class StreamingBenchmarks : IDisposable
{
    private DirectSignatureFactory factory = null!;
    private MemoryStream payload1MB = null!;
    private MemoryStream payload10MB = null!;
    private X509Certificate2Collection chain = null!;

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

        byte[] data1mb = new byte[1024 * 1024];
        Random.Shared.NextBytes(data1mb);
        this.payload1MB = new MemoryStream(data1mb, writable: false);

        byte[] data10mb = new byte[10 * 1024 * 1024];
        Random.Shared.NextBytes(data10mb);
        this.payload10MB = new MemoryStream(data10mb, writable: false);
    }

    [GlobalCleanup]
    public void Cleanup() => this.Dispose();

    public void Dispose()
    {
        this.factory?.Dispose();
        this.payload1MB?.Dispose();
        this.payload10MB?.Dispose();

        if (this.chain is not null)
        {
            foreach (X509Certificate2 cert in this.chain)
            {
                cert.Dispose();
            }
        }

        GC.SuppressFinalize(this);
    }

    [Benchmark(Description = "Stream sign ES256 1 MB")]
    public async Task<byte[]> StreamSign_ES256_1MB()
    {
        this.payload1MB.Position = 0;
        return await this.factory.CreateCoseSign1MessageBytesAsync(
            this.payload1MB, "application/octet-stream");
    }

    [Benchmark(Description = "Stream sign ES256 10 MB detached")]
    public async Task<byte[]> StreamSign_ES256_10MB_Detached()
    {
        this.payload10MB.Position = 0;
        return await this.factory.CreateCoseSign1MessageBytesAsync(
            this.payload10MB,
            "application/octet-stream",
            new DirectSignatureOptions { EmbedPayload = false });
    }
}
