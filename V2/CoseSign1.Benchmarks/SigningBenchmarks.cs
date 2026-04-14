// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Benchmarks;

using System.Security.Cryptography.X509Certificates;
using BenchmarkDotNet.Attributes;
using CoseSign1.Certificates;
using CoseSign1.Certificates.Local;
using CoseSign1.Factories.Direct;
using CoseSign1.Factories.Indirect;

/// <summary>
/// Benchmarks for COSE Sign1 direct signature creation using certificate-based signing.
/// Measures signing throughput for different payload sizes and key algorithms.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(warmupCount: 3, iterationCount: 20)]
public class SigningBenchmarks : IDisposable
{
    private DirectSignatureFactory ecdsaP256Factory = null!;
    private DirectSignatureFactory ecdsaP384Factory = null!;
    private DirectSignatureFactory rsaFactory = null!;
    private DirectSignatureFactory mldsaFactory = null!;
    private IndirectSignatureFactory indirectP256Factory = null!;
    private X509Certificate2Collection ecdsaP256Chain = null!;
    private X509Certificate2Collection ecdsaP384Chain = null!;
    private X509Certificate2Collection rsaChain = null!;
    private X509Certificate2Collection mldsaChain = null!;
    private byte[] payload1KB = null!;
    private byte[] payload100KB = null!;
    private byte[] payload1MB = null!;

    [GlobalSetup]
    public void Setup()
    {
        CertificateChainFactory chainFactory = new();

        // ECDSA P-256 (3-tier chain: Root CA → Intermediate CA → Leaf)
        this.ecdsaP256Chain = chainFactory.CreateChain(opts =>
        {
            opts.KeyAlgorithm = KeyAlgorithm.ECDSA;
            opts.KeySize = 256;
            opts.LeafFirst = true;
        });

        CertificateSigningService ecdsaP256Service = CertificateSigningService.Create(
            this.ecdsaP256Chain[0],
            this.ecdsaP256Chain.ToArray());
        this.ecdsaP256Factory = new DirectSignatureFactory(ecdsaP256Service);

        // Indirect signature factory wrapping the ECDSA P-256 direct factory
        this.indirectP256Factory = new IndirectSignatureFactory(this.ecdsaP256Factory);

        // ECDSA P-384 (3-tier chain: Root CA → Intermediate CA → Leaf)
        this.ecdsaP384Chain = chainFactory.CreateChain(opts =>
        {
            opts.KeyAlgorithm = KeyAlgorithm.ECDSA;
            opts.KeySize = 384;
            opts.LeafFirst = true;
        });

        CertificateSigningService ecdsaP384Service = CertificateSigningService.Create(
            this.ecdsaP384Chain[0],
            this.ecdsaP384Chain.ToArray());
        this.ecdsaP384Factory = new DirectSignatureFactory(ecdsaP384Service);

        // RSA-2048 (3-tier chain: Root CA → Intermediate CA → Leaf)
        this.rsaChain = chainFactory.CreateChain(opts =>
        {
            opts.KeyAlgorithm = KeyAlgorithm.RSA;
            opts.KeySize = 2048;
            opts.LeafFirst = true;
        });

        CertificateSigningService rsaService = CertificateSigningService.Create(
            this.rsaChain[0],
            this.rsaChain.ToArray());
        this.rsaFactory = new DirectSignatureFactory(rsaService);

#pragma warning disable SYSLIB5006 // ML-DSA is preview in .NET 10
        // ML-DSA-65 (3-tier chain: Root CA → Intermediate CA → Leaf)
        this.mldsaChain = chainFactory.CreateChain(opts =>
        {
            opts.KeyAlgorithm = KeyAlgorithm.MLDSA;
            opts.KeySize = 65;
            opts.LeafFirst = true;
        });

        CertificateSigningService mldsaService = CertificateSigningService.Create(
            this.mldsaChain[0],
            this.mldsaChain.ToArray());
        this.mldsaFactory = new DirectSignatureFactory(mldsaService);
#pragma warning restore SYSLIB5006

        // Generate payloads
        this.payload1KB = new byte[1024];
        this.payload100KB = new byte[100 * 1024];
        this.payload1MB = new byte[1024 * 1024];
        Random.Shared.NextBytes(this.payload1KB);
        Random.Shared.NextBytes(this.payload100KB);
        Random.Shared.NextBytes(this.payload1MB);
    }

    [GlobalCleanup]
    public void Cleanup() => this.Dispose();

    public void Dispose()
    {
        // Do NOT dispose indirectP256Factory — it would double-dispose ecdsaP256Factory.
        this.ecdsaP256Factory?.Dispose();
        this.ecdsaP384Factory?.Dispose();
        this.rsaFactory?.Dispose();
        this.mldsaFactory?.Dispose();
        DisposeCertificateChain(this.ecdsaP256Chain);
        DisposeCertificateChain(this.ecdsaP384Chain);
        DisposeCertificateChain(this.rsaChain);
        DisposeCertificateChain(this.mldsaChain);
        GC.SuppressFinalize(this);
    }

    private static void DisposeCertificateChain(X509Certificate2Collection? chain)
    {
        if (chain is null)
        {
            return;
        }

        foreach (X509Certificate2 cert in chain)
        {
            cert.Dispose();
        }
    }

    // --- ECDSA P-256 ---

    [Benchmark(Description = "Sign ECDSA P-256 1 KB")]
    public byte[] Sign_ECDSA_P256_1KB() =>
        this.ecdsaP256Factory.CreateCoseSign1MessageBytes(this.payload1KB, "application/octet-stream");

    [Benchmark(Description = "Sign ECDSA P-256 100 KB")]
    public byte[] Sign_ECDSA_P256_100KB() =>
        this.ecdsaP256Factory.CreateCoseSign1MessageBytes(this.payload100KB, "application/octet-stream");

    [Benchmark(Description = "Sign ECDSA P-256 1 MB")]
    public byte[] Sign_ECDSA_P256_1MB() =>
        this.ecdsaP256Factory.CreateCoseSign1MessageBytes(this.payload1MB, "application/octet-stream");

    // --- ECDSA P-384 ---

    [Benchmark(Description = "Sign ECDSA P-384 1 KB")]
    public byte[] Sign_ECDSA_P384_1KB() =>
        this.ecdsaP384Factory.CreateCoseSign1MessageBytes(this.payload1KB, "application/octet-stream");

    [Benchmark(Description = "Sign ECDSA P-384 100 KB")]
    public byte[] Sign_ECDSA_P384_100KB() =>
        this.ecdsaP384Factory.CreateCoseSign1MessageBytes(this.payload100KB, "application/octet-stream");

    [Benchmark(Description = "Sign ECDSA P-384 1 MB")]
    public byte[] Sign_ECDSA_P384_1MB() =>
        this.ecdsaP384Factory.CreateCoseSign1MessageBytes(this.payload1MB, "application/octet-stream");

    // --- RSA-2048 ---

    [Benchmark(Description = "Sign RSA-2048 1 KB")]
    public byte[] Sign_RSA2048_1KB() =>
        this.rsaFactory.CreateCoseSign1MessageBytes(this.payload1KB, "application/octet-stream");

    [Benchmark(Description = "Sign RSA-2048 100 KB")]
    public byte[] Sign_RSA2048_100KB() =>
        this.rsaFactory.CreateCoseSign1MessageBytes(this.payload100KB, "application/octet-stream");

    [Benchmark(Description = "Sign RSA-2048 1 MB")]
    public byte[] Sign_RSA2048_1MB() =>
        this.rsaFactory.CreateCoseSign1MessageBytes(this.payload1MB, "application/octet-stream");

    // --- ML-DSA-65 (Post-Quantum) ---

    [Benchmark(Description = "Sign ML-DSA-65 1 KB")]
    public byte[] Sign_MLDSA65_1KB() =>
        this.mldsaFactory.CreateCoseSign1MessageBytes(this.payload1KB, "application/octet-stream");

    [Benchmark(Description = "Sign ML-DSA-65 100 KB")]
    public byte[] Sign_MLDSA65_100KB() =>
        this.mldsaFactory.CreateCoseSign1MessageBytes(this.payload100KB, "application/octet-stream");

    [Benchmark(Description = "Sign ML-DSA-65 1 MB")]
    public byte[] Sign_MLDSA65_1MB() =>
        this.mldsaFactory.CreateCoseSign1MessageBytes(this.payload1MB, "application/octet-stream");

    // --- Indirect ECDSA P-256 (hash-then-sign) ---
    // EdDSA / Ed25519: N/A — System.Security.Cryptography.EdDsa does not exist in .NET 10

    [Benchmark(Description = "Sign Indirect ECDSA P-256 1 KB")]
    public byte[] Sign_Indirect_ECDSA_P256_1KB() =>
        this.indirectP256Factory.CreateCoseSign1MessageBytes(this.payload1KB, "application/octet-stream");

    [Benchmark(Description = "Sign Indirect ECDSA P-256 100 KB")]
    public byte[] Sign_Indirect_ECDSA_P256_100KB() =>
        this.indirectP256Factory.CreateCoseSign1MessageBytes(this.payload100KB, "application/octet-stream");

    [Benchmark(Description = "Sign Indirect ECDSA P-256 1 MB")]
    public byte[] Sign_Indirect_ECDSA_P256_1MB() =>
        this.indirectP256Factory.CreateCoseSign1MessageBytes(this.payload1MB, "application/octet-stream");
}
