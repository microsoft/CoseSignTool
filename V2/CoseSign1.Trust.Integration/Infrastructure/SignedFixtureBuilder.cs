// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Trust.Integration.Infrastructure;

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CoseSign1.Certificates;
using CoseSign1.Certificates.Local;
using CoseSign1.Factories.Direct;
using CoseSign1.Tests.Common;

/// <summary>
/// On-disk artefacts produced by <see cref="SignedFixtureBuilder"/>. Owns a temp directory
/// that contains the COSE signature and (for X509 chains) a PEM-encoded root certificate the
/// CLI can pick up via <c>--trust-roots</c>. Disposing the fixture removes the directory.
/// </summary>
public sealed class SignedFixture : IDisposable
{
    private readonly string _directory;
    private bool _disposed;

    internal SignedFixture(string directory, string signaturePath, string? rootPemPath, string? leafSubjectCn, string? leafThumbprint)
    {
        _directory = directory;
        SignaturePath = signaturePath;
        RootPemPath = rootPemPath;
        LeafSubjectCn = leafSubjectCn;
        LeafThumbprint = leafThumbprint;
    }

    /// <summary>
    /// Absolute path of the produced <c>.cose</c> file with embedded payload + x5chain.
    /// </summary>
    public string SignaturePath { get; }

    /// <summary>
    /// Absolute path of the PEM-encoded root certificate, or <see langword="null"/> when the
    /// fixture was built without a chain (e.g., MST receipt fixtures imported from disk).
    /// </summary>
    public string? RootPemPath { get; }

    /// <summary>
    /// Common name of the leaf certificate, or <see langword="null"/> for non-X509 fixtures.
    /// Tests use this to author <c>x509-cert-identity-allowed/v1</c> + parameter-binding cases.
    /// </summary>
    public string? LeafSubjectCn { get; }

    /// <summary>
    /// Hex thumbprint of the leaf certificate, or <see langword="null"/> for non-X509 fixtures.
    /// </summary>
    public string? LeafThumbprint { get; }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        TryDeleteDirectory(_directory);
        _disposed = true;
    }

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = "Best-effort cleanup; the catch arm only fires when the OS denies the directory-delete (e.g., another process holds a file handle), which the test suite does not synthesise.")]
    private static void TryDeleteDirectory(string directory)
    {
        try
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
        catch
        {
            // Best-effort cleanup; failures here would mask real test failures.
        }
    }
}

/// <summary>
/// Builds end-to-end test fixtures: a signed COSE message + (optionally) a PEM-encoded trust
/// root that lets the CLI's <c>verify x509</c> command treat the chain as trusted. The factory
/// reuses <see cref="TestCertificateUtils"/> so chains match every other V2 test surface.
/// </summary>
public static class SignedFixtureBuilder
{
    private const string DefaultPayload = "Trust-policy integration test payload";
    private const string ContentType = "application/cose-trust-policy-itest";

    /// <summary>
    /// Creates a signed COSE_Sign1 message under a fresh ECDSA test chain. Root + intermediate +
    /// leaf are produced via the canonical chain factory so the leaf's CN and EKU set match the
    /// Phase 2/3 expectations. The leaf signs the supplied payload (or a default one) and the
    /// resulting message embeds the full x5chain so the verifier resolves the signing key
    /// without out-of-band material.
    /// </summary>
    /// <param name="testName">Used to disambiguate chain CNs across parallel tests.</param>
    /// <param name="payload">Optional payload bytes; a default UTF-8 marker is used otherwise.</param>
    /// <returns>Disposable fixture containing the <c>.cose</c> file and a PEM trust-root file.</returns>
    public static SignedFixture CreateX509Signed(string testName, byte[]? payload = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(testName);

        string dir = CreateTempDirectory(testName);

        // Use ECDSA P-256 so the signing path matches the production default + tests are fast.
        // leafFirst:true lets the producer pull the leaf as chain[0] to match X509-test conventions.
        var chain = TestCertificateUtils.CreateTestChain(testName, useEcc: true, keySize: 256, leafFirst: true);
        try
        {
            using var leaf = chain[0];
            var chainArray = chain.Cast<X509Certificate2>().ToArray();
            X509Certificate2 root = chainArray[chainArray.Length - 1];

            using var signingService = CertificateSigningService.Create(leaf, chainArray);
            using var factory = new DirectSignatureFactory(signingService);

            byte[] payloadBytes = payload ?? Encoding.UTF8.GetBytes(DefaultPayload);
            byte[] cose = factory.CreateCoseSign1MessageBytes(payloadBytes, ContentType);

            string signaturePath = Path.Combine(dir, "signed.cose");
            File.WriteAllBytes(signaturePath, cose);

            string rootPemPath = Path.Combine(dir, "root.pem");
            File.WriteAllText(rootPemPath, root.ExportCertificatePem());

            // ExtractCommonName isn't worth a separate helper — the chain factory is documented
            // to produce CN=<ChainLeafPrefix><testName>, but we read the cert to be defensive
            // about future changes to the factory.
            string subjectCn = ExtractCommonName(leaf.Subject);

            return new SignedFixture(dir, signaturePath, rootPemPath, subjectCn, leaf.Thumbprint);
        }
        catch
        {
            CleanupOnConstructionFailure(dir, chain);
            throw;
        }
        finally
        {
            // The signing service holds its own clones; release the originals after the message
            // has been encoded so we don't keep duplicate handles open.
            for (int i = 1; i < chain.Count; i++)
            {
                chain[i].Dispose();
            }
        }
    }

    /// <summary>
    /// Builds a signed X509 chain whose leaf carries the supplied custom EKU OIDs. Used by EKU
    /// matrix tests that need a specific OID present (or absent) on the certificate.
    /// </summary>
    /// <param name="testName">Disambiguator for the leaf CN.</param>
    /// <param name="ekuOids">Closed list of OIDs to attach as the leaf's enhanced key usages.</param>
    /// <returns>A disposable fixture with the signed message + trust-root PEM.</returns>
    public static SignedFixture CreateX509SignedWithLeafEkus(string testName, params string[] ekuOids)
    {
        ArgumentException.ThrowIfNullOrEmpty(testName);
        ArgumentNullException.ThrowIfNull(ekuOids);

        string dir = CreateTempDirectory(testName);

        // Use the canonical chain factory but pin the leaf's EKU set explicitly. The factory
        // produces a non-CA leaf with KeyUsage=DigitalSignature, which both keeps chain
        // validation honest and means the produced X509SigningCertificateEkuFact set carries
        // exactly the OIDs we requested.
        var chain = TestCertificateUtils.Chain.CreateChain(o =>
        {
            o.WithRootName("CN=ItestRoot-" + testName)
             .WithIntermediateName("CN=ItestIntermediate-" + testName)
             .WithLeafName("CN=ItestLeaf-" + testName)
             .WithKeyAlgorithm(KeyAlgorithm.ECDSA)
             .WithKeySize(256)
             .WithLeafEkus(ekuOids)
             .LeafFirstOrder();
        });

        try
        {
            using var leaf = chain[0];
            var chainArray = chain.Cast<X509Certificate2>().ToArray();
            X509Certificate2 root = chainArray[chainArray.Length - 1];

            using var signingService = CertificateSigningService.Create(leaf, chainArray);
            using var factory = new DirectSignatureFactory(signingService);

            byte[] payloadBytes = Encoding.UTF8.GetBytes(DefaultPayload);
            byte[] cose = factory.CreateCoseSign1MessageBytes(payloadBytes, ContentType);

            string signaturePath = Path.Combine(dir, "signed.cose");
            File.WriteAllBytes(signaturePath, cose);

            string rootPemPath = Path.Combine(dir, "root.pem");
            File.WriteAllText(rootPemPath, root.ExportCertificatePem());

            return new SignedFixture(dir, signaturePath, rootPemPath, ExtractCommonName(leaf.Subject), leaf.Thumbprint);
        }
        catch
        {
            CleanupOnConstructionFailure(dir, chain);
            throw;
        }
        finally
        {
            // Release every cert except chain[0] (already disposed via the using block).
            for (int i = 1; i < chain.Count; i++)
            {
                chain[i].Dispose();
            }
        }
    }

    /// <summary>
    /// Releases certificate handles and removes the temp directory created for a fixture whose
    /// construction subsequently failed. Excluded from coverage because the only paths that
    /// reach it are exceptional (cert factory failure, COSE encoding failure, file IO failure)
    /// and synthesising those reliably from a unit test would brittle-couple to internal
    /// behaviour of certificate construction in net10.0.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = "Defensive cleanup for fixture-construction failures; reaching this path requires synthesising a failure inside the .NET cert factory or COSE encoder, neither of which the integration suite drives.")]
    private static void CleanupOnConstructionFailure(string dir, X509Certificate2Collection chain)
    {
        foreach (X509Certificate2 cert in chain)
        {
            cert.Dispose();
        }

        try
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
        catch
        {
            // Cleanup is best-effort — let the original exception propagate.
        }
    }

    /// <summary>
    /// Returns the absolute path of the bundled SCITT receipt fixture (deployed via the test
    /// project's <c>TestData\Scitt</c> link). The fixture is read-only and shared across tests.
    /// </summary>
    /// <param name="receiptName">File-name stem (e.g., <c>1ts-statement</c>).</param>
    /// <returns>Absolute path of the .scitt file.</returns>
    public static string GetMstReceiptFixturePath(string receiptName = "1ts-statement")
    {
        string baseDir = TestContext.CurrentContext.TestDirectory;
        return Path.Combine(baseDir, "TestData", "Scitt", receiptName + ".scitt");
    }

    /// <summary>
    /// Returns the absolute path of the bundled MST issuer JWKS file used to verify the SCITT
    /// fixture's receipt offline.
    /// </summary>
    public static string GetMstIssuerJwksPath()
    {
        string baseDir = TestContext.CurrentContext.TestDirectory;
        return Path.Combine(baseDir, "TestData", "Mst", "esrp-cts-cp.confidential-ledger.azure.com.jwks.json");
    }

    /// <summary>
    /// Canonical issuer host bound by the bundled JWKS. Tests use this both as the
    /// <c>verify scitt --issuer-offline-keys &lt;host&gt;=&lt;path&gt;</c> input and as the
    /// expected value inside the trust-policy document predicates.
    /// </summary>
    public const string MstIssuerHost = "esrp-cts-cp.confidential-ledger.azure.com";

    private static string CreateTempDirectory(string testName)
    {
        // Place under the test directory so artefacts are co-located with the build output —
        // makes failure triage straightforward and avoids polluting the user's TEMP root.
        string root = Path.Combine(TestContext.CurrentContext.TestDirectory, "fixture-output", testName + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    private static string ExtractCommonName(string distinguishedName)
    {
        if (string.IsNullOrEmpty(distinguishedName))
        {
            return string.Empty;
        }

        // Distinguished names are emitted as "CN=<value>, OU=..., ..."; we want only the CN.
        foreach (string part in distinguishedName.Split(','))
        {
            string trimmed = part.Trim();
            if (trimmed.StartsWith("CN=", StringComparison.Ordinal))
            {
                return trimmed[3..];
            }
        }

        return distinguishedName;
    }
}
