// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests;

/// <summary>
/// Test class for <see cref="X509ChainBuilder"/>
/// </summary>
public class X509ChainBuilderTests
{
    /// <summary>
    /// Setup method
    /// </summary>
    [SetUp]
    public void Setup()
    {
    }

    /// <summary>
    /// Just verify the shim for <see cref="X509Chain"/> functions properly.
    /// </summary>
    [Test]
    public void TestX509ChainBuilderBuilds()
    {
        // setup
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate();
        X509ChainBuilder chainBuilder = new();
        X509ChainPolicy policy = new()
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
        };
        policy.CustomTrustStore.Add(cert);

        // test
        chainBuilder.ChainPolicy = policy;
        chainBuilder.Build(cert).Should().BeTrue();

        // verify
        chainBuilder.ChainElements.Should().HaveCount(1);
        chainBuilder.ChainStatus.Should().HaveCount(0); // chain status will be 0 for custom trust modes.
        chainBuilder.ChainPolicy.Should().NotBeNull();
        chainBuilder.ChainPolicy.RevocationFlag.Should().Be(policy.RevocationFlag);
        chainBuilder.ChainPolicy.TrustMode.Should().Be(policy.TrustMode);
        chainBuilder.ChainPolicy.RevocationMode.Should().Be(policy.RevocationMode);
    }
}
