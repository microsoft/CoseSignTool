// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.ChainBuilders;

namespace CoseSign1.Certificates.Tests.ChainBuilders;

public class ExplicitCertificateChainBuilderTests
{
    [Test]
    public void Constructor_WithValidChain_Succeeds()
    {
        var chain = TestCertificateUtils.CreateTestChain().Cast<X509Certificate2>().ToArray();
        using var builder = new ExplicitCertificateChainBuilder(chain);

        Assert.That(builder, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullChain_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new ExplicitCertificateChainBuilder((IReadOnlyList<X509Certificate2>)null!));
    }

    [Test]
    public void Constructor_WithEmptyChain_ThrowsArgumentException()
    {
        var emptyChain = Array.Empty<X509Certificate2>();
        Assert.Throws<ArgumentException>(() => new ExplicitCertificateChainBuilder(emptyChain));
    }

    [Test]
    public void Build_WithMatchingCertificate_ReturnsTrue()
    {
        var certs = TestCertificateUtils.CreateTestChain().Cast<X509Certificate2>().ToArray();
        var chain = new[] { certs[2], certs[1], certs[0] }; // Reverse to leaf-first
        using var builder = new ExplicitCertificateChainBuilder(chain);

        var result = builder.Build(chain[0]);

        Assert.That(result, Is.True, () => string.Join("; ", builder.ChainStatus.Select(s => s.StatusInformation)));
        Assert.That(builder.ChainElements, Has.Count.EqualTo(chain.Length));
        // Note: ChainStatus may contain UntrustedRoot which is expected for self-signed test certificates
    }

    [Test]
    public void Build_WithNonMatchingCertificate_ReturnsFalse()
    {
        var chain = TestCertificateUtils.CreateTestChain().Cast<X509Certificate2>().ToArray();
        using var otherCert = TestCertificateUtils.CreateCertificate();
        using var builder = new ExplicitCertificateChainBuilder(chain);

        var result = builder.Build(otherCert);

        Assert.That(result, Is.False);
        // Note: ChainStatus behavior depends on X509Chain, may or may not have entries
    }

    [Test]
    public void Build_WithValidChainOrder_ReturnsTrue()
    {
        // Create a properly ordered chain: leaf -> intermediate -> root
        var chain = TestCertificateUtils.CreateTestChain(leafFirst: true).Cast<X509Certificate2>().ToArray();
        using var builder = new ExplicitCertificateChainBuilder(chain);

        var result = builder.Build(chain[0]);

        Assert.That(result, Is.True);
        Assert.That(builder.ChainElements, Has.Count.EqualTo(3));
    }

    [Test]
    public void Build_WithEccChain_ReturnsTrue()
    {
        var certs = TestCertificateUtils.CreateTestChain(useEcc: true).Cast<X509Certificate2>().ToArray();
        var chain = new[] { certs[2], certs[1], certs[0] }; // Reverse to leaf-first
        using var builder = new ExplicitCertificateChainBuilder(chain);

        var result = builder.Build(chain[0]);

        Assert.That(result, Is.True, () => string.Join("; ", builder.ChainStatus.Select(s => s.StatusInformation)));
        Assert.That(builder.ChainElements, Has.Count.EqualTo(3));
    }

    [Test]
    public void Build_WithRootCertificate_ReturnsTrue()
    {
        // Building a chain from a root certificate should succeed (chain of length 1)
        var certs = TestCertificateUtils.CreateTestChain().Cast<X509Certificate2>().ToArray();
        var chain = new[] { certs[0], certs[1], certs[2] }; // root, intermediate, leaf
        using var builder = new ExplicitCertificateChainBuilder(chain);

        // Build from root certificate
        var result = builder.Build(certs[0]);

        Assert.That(result, Is.True);
        Assert.That(builder.ChainElements, Has.Count.EqualTo(1)); // Only root in chain
    }

    [Test]
    public void Build_WithUnorderedChain_AutomaticallyOrders()
    {
        // Create chain in random order: intermediate, root, leaf
        var certs = TestCertificateUtils.CreateTestChain().Cast<X509Certificate2>().ToArray();
        var unorderedChain = new[] { certs[1], certs[0], certs[2] }; // intermediate, root, leaf
        using var builder = new ExplicitCertificateChainBuilder(unorderedChain);

        // Build from leaf certificate
        var result = builder.Build(certs[2]);

        Assert.That(result, Is.True, () => string.Join("; ", builder.ChainStatus.Select(s => s.StatusInformation)));
        Assert.That(builder.ChainElements, Has.Count.EqualTo(3));

        // Verify the chain is in correct order: leaf -> intermediate -> root
        var chainArray = builder.ChainElements.ToArray();
        Assert.That(chainArray[0].Thumbprint, Is.EqualTo(certs[2].Thumbprint)); // leaf
        Assert.That(chainArray[1].Thumbprint, Is.EqualTo(certs[1].Thumbprint)); // intermediate
        Assert.That(chainArray[2].Thumbprint, Is.EqualTo(certs[0].Thumbprint)); // root
    }

    [Test]
    public void Build_WithSingleCertificate_ReturnsTrue()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var chain = new[] { cert };
        using var builder = new ExplicitCertificateChainBuilder(chain);

        var result = builder.Build(cert);

        Assert.That(result, Is.True);
        Assert.That(builder.ChainElements, Has.Count.EqualTo(1));
    }

    [Test]
    public void ChainElements_BeforeBuild_ReturnsEmpty()
    {
        var chain = TestCertificateUtils.CreateTestChain().Cast<X509Certificate2>().ToArray();
        using var builder = new ExplicitCertificateChainBuilder(chain);

        Assert.That(builder.ChainElements, Is.Empty);
    }

    [Test]
    public void ChainPolicy_CanBeSetAndRetrieved()
    {
        var chain = TestCertificateUtils.CreateTestChain().Cast<X509Certificate2>().ToArray();
        using var builder = new ExplicitCertificateChainBuilder(chain);

        var policy = new X509ChainPolicy
        {
            RevocationMode = X509RevocationMode.NoCheck
        };
        builder.ChainPolicy = policy;

        Assert.That(builder.ChainPolicy, Is.SameAs(policy));
    }

    [Test]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        var chain = TestCertificateUtils.CreateTestChain().Cast<X509Certificate2>().ToArray();
        var builder = new ExplicitCertificateChainBuilder(chain);

        builder.Dispose();
        builder.Dispose(); // Should not throw
    }

    [Test]
    public void Dispose_PreventsSubsequentOperations()
    {
        var chain = TestCertificateUtils.CreateTestChain().Cast<X509Certificate2>().ToArray();
        var builder = new ExplicitCertificateChainBuilder(chain);

        builder.Dispose();

        Assert.Throws<ObjectDisposedException>(() => builder.Build(chain[0]));
    }
}