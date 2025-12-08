// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Tests.Common;
using NUnit.Framework;

namespace CoseSign1.Certificates.Tests.ChainBuilders;

public class X509ChainBuilderTests
{
    [Test]
    public void Constructor_Default_Succeeds()
    {
        using var builder = new X509ChainBuilder();

        Assert.That(builder, Is.Not.Null);
        Assert.That(builder.ChainPolicy, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithChainPolicy_Succeeds()
    {
        var policy = new X509ChainPolicy
        {
            RevocationMode = X509RevocationMode.NoCheck
        };
        using var builder = new X509ChainBuilder(policy);

        Assert.That(builder, Is.Not.Null);
        Assert.That(builder.ChainPolicy, Is.SameAs(policy));
    }

    [Test]
    public void Constructor_WithNullPolicy_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new X509ChainBuilder(null!));
    }

    [Test]
    public void Build_WithValidCertificate_ReturnsTrue()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        using var builder = new X509ChainBuilder();

        // Configure to not check revocation for test
        builder.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        builder.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

        var result = builder.Build(cert);

        Assert.That(result, Is.True);
    }

    [Test]
    public void Build_WithNullCertificate_ThrowsArgumentNullException()
    {
        using var builder = new X509ChainBuilder();

        Assert.Throws<ArgumentNullException>(() => builder.Build(null!));
    }

    [Test]
    public void Build_PopulatesChainElements()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        using var builder = new X509ChainBuilder();
        builder.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        builder.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

        builder.Build(cert);

        Assert.That(builder.ChainElements, Is.Not.Empty);
    }

    [Test]
    public void ChainElements_ContainsCertificates()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        using var builder = new X509ChainBuilder();
        builder.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        builder.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

        builder.Build(cert);

        Assert.That(builder.ChainElements.Count, Is.GreaterThan(0));
        Assert.That(builder.ChainElements.First().Thumbprint, Is.EqualTo(cert.Thumbprint));
    }

    [Test]
    public void ChainPolicy_CanBeModified()
    {
        using var builder = new X509ChainBuilder();

        builder.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        builder.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;

        Assert.That(builder.ChainPolicy.RevocationMode, Is.EqualTo(X509RevocationMode.Online));
        Assert.That(builder.ChainPolicy.VerificationFlags, Is.EqualTo(X509VerificationFlags.IgnoreNotTimeValid));
    }

    [Test]
    public void ChainPolicy_CanBeReplaced()
    {
        using var builder = new X509ChainBuilder();

        var newPolicy = new X509ChainPolicy
        {
            RevocationMode = X509RevocationMode.Offline
        };
        builder.ChainPolicy = newPolicy;

        Assert.That(builder.ChainPolicy, Is.SameAs(newPolicy));
    }

    [Test]
    public void ChainPolicy_SetNull_ThrowsArgumentNullException()
    {
        using var builder = new X509ChainBuilder();

        Assert.Throws<ArgumentNullException>(() => builder.ChainPolicy = null!);
    }

    [Test]
    public void ChainStatus_ReflectsChainValidation()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        using var builder = new X509ChainBuilder();
        builder.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        builder.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

        builder.Build(cert);

        Assert.That(builder.ChainStatus, Is.Not.Null);
    }

    [Test]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        var builder = new X509ChainBuilder();

        builder.Dispose();
        builder.Dispose(); // Should not throw
    }

    [Test]
    public void Dispose_PreventsSubsequentOperations()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var builder = new X509ChainBuilder();

        builder.Dispose();

        Assert.Throws<ObjectDisposedException>(() => builder.Build(cert));
        Assert.Throws<ObjectDisposedException>(() => _ = builder.ChainElements);
        Assert.Throws<ObjectDisposedException>(() => _ = builder.ChainPolicy);
        Assert.Throws<ObjectDisposedException>(() => builder.ChainPolicy = new X509ChainPolicy());
        Assert.Throws<ObjectDisposedException>(() => _ = builder.ChainStatus);
    }
}
