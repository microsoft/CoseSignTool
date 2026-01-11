// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.ChainBuilders;

using CoseSign1.Certificates.ChainBuilders;

/// <summary>
/// Extended tests for <see cref="X509ChainBuilder"/>.
/// </summary>
[TestFixture]
public class X509ChainBuilderExtendedTests
{
    #region Constructor Tests

    [Test]
    public void Constructor_Default_UsesDefaultChainPolicy()
    {
        // Arrange & Act
        using var builder = new X509ChainBuilder();

        // Assert
        Assert.That(builder, Is.Not.Null);
        Assert.That(builder.ChainPolicy, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullChainPolicy_ThrowsArgumentNullException()
    {
        // Act & Assert
        X509ChainPolicy? nullPolicy = null;
        Assert.Throws<ArgumentNullException>(() => new X509ChainBuilder(nullPolicy!));
    }

    [Test]
    public void Constructor_WithCustomPolicy_UsesProvidedPolicy()
    {
        // Arrange
        var customPolicy = new X509ChainPolicy
        {
            RevocationMode = X509RevocationMode.NoCheck,
            RevocationFlag = X509RevocationFlag.EntireChain,
            VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority
        };

        // Act
        using var builder = new X509ChainBuilder(customPolicy);

        // Assert
        Assert.That(builder.ChainPolicy.RevocationMode, Is.EqualTo(X509RevocationMode.NoCheck));
        Assert.That(builder.ChainPolicy.RevocationFlag, Is.EqualTo(X509RevocationFlag.EntireChain));
        Assert.That(builder.ChainPolicy.VerificationFlags, Is.EqualTo(X509VerificationFlags.AllowUnknownCertificateAuthority));
    }

    [Test]
    public void Constructor_WithPolicyContainingApplicationPolicies_CopiesApplicationPolicies()
    {
        // Arrange
        var customPolicy = new X509ChainPolicy();
        customPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1")); // Server Auth
        customPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2")); // Client Auth

        // Act
        using var builder = new X509ChainBuilder(customPolicy);

        // Assert
        Assert.That(builder.ChainPolicy.ApplicationPolicy.Count, Is.EqualTo(2));
    }

    [Test]
    public void Constructor_WithPolicyContainingCertificatePolicies_CopiesCertificatePolicies()
    {
        // Arrange
        var customPolicy = new X509ChainPolicy();
        customPolicy.CertificatePolicy.Add(new Oid("2.5.29.32.0")); // Any Policy

        // Act
        using var builder = new X509ChainBuilder(customPolicy);

        // Assert
        Assert.That(builder.ChainPolicy.CertificatePolicy.Count, Is.EqualTo(1));
    }

    [Test]
    public void Constructor_WithPolicyContainingExtraStore_CopiesExtraStore()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("ExtraStoreCert");
        var customPolicy = new X509ChainPolicy();
        customPolicy.ExtraStore.Add(cert);

        // Act
        using var builder = new X509ChainBuilder(customPolicy);

        // Assert
        Assert.That(builder.ChainPolicy.ExtraStore.Count, Is.EqualTo(1));
    }

    #endregion

    #region Build Tests

    [Test]
    public void Build_WithNullCertificate_ThrowsArgumentNullException()
    {
        // Arrange
        using var builder = new X509ChainBuilder();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => builder.Build(null!));
    }

    [Test]
    public void Build_WithValidSelfSignedCertificate_ExecutesWithoutException()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("SelfSigned");
        var customPolicy = new X509ChainPolicy
        {
            RevocationMode = X509RevocationMode.NoCheck,
            VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority
        };
        using var builder = new X509ChainBuilder(customPolicy);

        // Act & Assert - just verifying it doesn't throw
        Assert.DoesNotThrow(() => builder.Build(cert));
    }

    [Test]
    public void Build_PopulatesChainElements()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("ChainElementsCert");
        var customPolicy = new X509ChainPolicy
        {
            RevocationMode = X509RevocationMode.NoCheck,
            VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority
        };
        using var builder = new X509ChainBuilder(customPolicy);

        // Act
        builder.Build(cert);

        // Assert
        var elements = builder.ChainElements;
        Assert.That(elements, Is.Not.Empty);
        Assert.That(elements.First().Thumbprint, Is.EqualTo(cert.Thumbprint));
    }

    #endregion

    #region ChainPolicy Property Tests

    [Test]
    public void ChainPolicy_CanBeSet()
    {
        // Arrange
        using var builder = new X509ChainBuilder();
        var newPolicy = new X509ChainPolicy
        {
            RevocationMode = X509RevocationMode.Offline
        };

        // Act
        builder.ChainPolicy = newPolicy;

        // Assert - the policy is replaced
        Assert.That(builder.ChainPolicy.RevocationMode, Is.EqualTo(X509RevocationMode.Offline));
    }

    [Test]
    public void ChainPolicy_SetWithNull_ThrowsArgumentNullException()
    {
        // Arrange
        using var builder = new X509ChainBuilder();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => builder.ChainPolicy = null!);
    }

    #endregion

    #region ChainStatus Tests

    [Test]
    public void ChainStatus_AfterBuild_ReturnsStatus()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("ChainStatusCert");
        var customPolicy = new X509ChainPolicy
        {
            RevocationMode = X509RevocationMode.NoCheck,
            VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority
        };
        using var builder = new X509ChainBuilder(customPolicy);

        // Act
        builder.Build(cert);
        var status = builder.ChainStatus;

        // Assert
        Assert.That(status, Is.Not.Null);
    }

    #endregion

    #region Dispose Tests

    [Test]
    public void Dispose_CalledMultipleTimes_DoesNotThrow()
    {
        // Arrange
        var builder = new X509ChainBuilder();

        // Act & Assert
        Assert.DoesNotThrow(() =>
        {
            builder.Dispose();
            builder.Dispose();
        });
    }

    [Test]
    public void ChainElements_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var builder = new X509ChainBuilder();
        builder.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => _ = builder.ChainElements);
    }

    [Test]
    public void ChainPolicy_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var builder = new X509ChainBuilder();
        builder.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => _ = builder.ChainPolicy);
    }

    [Test]
    public void ChainStatus_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var builder = new X509ChainBuilder();
        builder.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => _ = builder.ChainStatus);
    }

    [Test]
    public void Build_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("DisposedBuildCert");
        var builder = new X509ChainBuilder();
        builder.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => builder.Build(cert));
    }

    [Test]
    public void ChainPolicySet_AfterDispose_ThrowsObjectDisposedException()
    {
        // Arrange
        var builder = new X509ChainBuilder();
        builder.Dispose();

        // Act & Assert
        Assert.Throws<ObjectDisposedException>(() => builder.ChainPolicy = new X509ChainPolicy());
    }

    #endregion

    #region DefaultChainPolicy Tests

    [Test]
    public void DefaultChainPolicy_HasExpectedValues()
    {
        // Arrange & Act
        var defaultPolicy = X509ChainBuilder.DefaultChainPolicy;

        // Assert
        Assert.That(defaultPolicy.RevocationMode, Is.EqualTo(X509RevocationMode.Online));
        Assert.That(defaultPolicy.RevocationFlag, Is.EqualTo(X509RevocationFlag.ExcludeRoot));
        Assert.That(defaultPolicy.VerificationFlags, Is.EqualTo(X509VerificationFlags.NoFlag));
        Assert.That(defaultPolicy.UrlRetrievalTimeout, Is.EqualTo(TimeSpan.FromSeconds(30)));
    }

    #endregion
}
