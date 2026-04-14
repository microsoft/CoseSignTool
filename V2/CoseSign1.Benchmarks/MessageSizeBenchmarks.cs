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
/// Reports COSE_Sign1 message sizes across all algorithms.
/// The benchmark itself is a no-op; sizes are printed during GlobalSetup.
/// </summary>
[MemoryDiagnoser]
public class MessageSizeBenchmarks
{
    private Dictionary<string, int> sizes = new();

    [GlobalSetup]
    public void Setup()
    {
        byte[] payload = new byte[1024];
        Random.Shared.NextBytes(payload);

        string contentType = "application/octet-stream";
        CertificateChainFactory chainFactory = new();

        // ECDSA P-256 (3-tier chain: Root CA → Intermediate CA → Leaf)
        X509Certificate2Collection ecdsaP256Chain = chainFactory.CreateChain(opts =>
        {
            opts.KeyAlgorithm = KeyAlgorithm.ECDSA;
            opts.KeySize = 256;
            opts.LeafFirst = true;
        });
        CertificateSigningService ecdsaP256Service = CertificateSigningService.Create(ecdsaP256Chain[0], ecdsaP256Chain.ToArray());
        using DirectSignatureFactory ecdsaP256Factory = new(ecdsaP256Service);
        this.sizes["ECDSA P-256"] = ecdsaP256Factory.CreateCoseSign1MessageBytes(payload, contentType).Length;

        // ECDSA P-384 (3-tier chain: Root CA → Intermediate CA → Leaf)
        X509Certificate2Collection ecdsaP384Chain = chainFactory.CreateChain(opts =>
        {
            opts.KeyAlgorithm = KeyAlgorithm.ECDSA;
            opts.KeySize = 384;
            opts.LeafFirst = true;
        });
        CertificateSigningService ecdsaP384Service = CertificateSigningService.Create(ecdsaP384Chain[0], ecdsaP384Chain.ToArray());
        using DirectSignatureFactory ecdsaP384Factory = new(ecdsaP384Service);
        this.sizes["ECDSA P-384"] = ecdsaP384Factory.CreateCoseSign1MessageBytes(payload, contentType).Length;

        // RSA-PSS 2048 (3-tier chain: Root CA → Intermediate CA → Leaf)
        X509Certificate2Collection rsaChain = chainFactory.CreateChain(opts =>
        {
            opts.KeyAlgorithm = KeyAlgorithm.RSA;
            opts.KeySize = 2048;
            opts.LeafFirst = true;
        });
        CertificateSigningService rsaService = CertificateSigningService.Create(rsaChain[0], rsaChain.ToArray());
        using DirectSignatureFactory rsaFactory = new(rsaService);
        this.sizes["RSA-PSS 2048"] = rsaFactory.CreateCoseSign1MessageBytes(payload, contentType).Length;

#pragma warning disable SYSLIB5006 // ML-DSA is preview in .NET 10
        // ML-DSA-65 (3-tier chain: Root CA → Intermediate CA → Leaf)
        X509Certificate2Collection mldsaChain = chainFactory.CreateChain(opts =>
        {
            opts.KeyAlgorithm = KeyAlgorithm.MLDSA;
            opts.KeySize = 65;
            opts.LeafFirst = true;
        });
        CertificateSigningService mldsaService = CertificateSigningService.Create(mldsaChain[0], mldsaChain.ToArray());
        using DirectSignatureFactory mldsaFactory = new(mldsaService);
        this.sizes["ML-DSA-65"] = mldsaFactory.CreateCoseSign1MessageBytes(payload, contentType).Length;
#pragma warning restore SYSLIB5006

        // Indirect ECDSA P-256 (hash-then-sign)
        using IndirectSignatureFactory indirectP256Factory = new(ecdsaP256Factory);
        this.sizes["ES256 Indirect SHA-256"] = indirectP256Factory.CreateCoseSign1MessageBytes(payload, contentType).Length;

        // EdDSA / Ed25519: N/A — System.Security.Cryptography.EdDsa does not exist in .NET 10

        // Print table
        Console.WriteLine();
        Console.WriteLine("=== COSE_Sign1 Message Sizes (1 KB payload, 3-tier cert chains) ===");
        Console.WriteLine($"{"Algorithm",-25} {"Size",10} {"Overhead",10} {"Overhead%",10}");
        foreach (KeyValuePair<string, int> entry in this.sizes)
        {
            int overhead = entry.Value - 1024;
            double pct = overhead * 100.0 / 1024;
            Console.WriteLine($"{entry.Key,-25} {entry.Value,10:N0} {overhead,10:N0} {pct,9:F1}%");
        }

        Console.WriteLine();
    }

    [Benchmark(Description = "Message size reference (no-op)")]
    public int Reference() => this.sizes.Count;
}