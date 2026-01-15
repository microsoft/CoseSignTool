// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Trust;

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Trust;
using CoseSign1.Tests.Common;

[TestFixture]
public class CertificateTrustBuilderTests
{
    [Test]
    public void TrustSource_CannotBeChangedOnceConfigured()
    {
        var builder = new CertificateTrustBuilder().UseSystemTrust();

        Assert.Throws<InvalidOperationException>(() => builder.UseEmbeddedChainOnly());
    }

    [Test]
    public void UseCustomRootTrust_NullRoots_ThrowsArgumentNullException()
    {
        var builder = new CertificateTrustBuilder();
        Assert.Throws<ArgumentNullException>(() => builder.UseCustomRootTrust(null!));
    }

    [Test]
    public void AllowThumbprint_Null_ThrowsArgumentNullException()
    {
        var builder = new CertificateTrustBuilder();
        Assert.Throws<ArgumentNullException>(() => builder.EnableCertificateIdentityPinning(p => p.AllowThumbprint(null!)));
    }

    [Test]
    public void NormalizeThumbprint_RemovesSpacesAndUppercases()
    {
        var normalized = CertificateTrustBuilder.CertificateTrustOptions.NormalizeThumbprint("aa bb cc");
        Assert.That(normalized, Is.EqualTo("AABBCC"));

        Assert.That(CertificateTrustBuilder.CertificateTrustOptions.NormalizeThumbprint(null!), Is.EqualTo(string.Empty));
    }

    [Test]
    public void Validate_ThrowsWhenTrustSourceMissing()
    {
        var builder = new CertificateTrustBuilder();

        Assert.Throws<InvalidOperationException>(() => builder.Options.Validate());
    }

    [Test]
    public void Validate_DoesNotRequireIdentityConstraints_WhenPinningDisabledByDefault()
    {
        var builder = new CertificateTrustBuilder().UseSystemTrust();

        Assert.DoesNotThrow(() => builder.Options.Validate());
    }

    [Test]
    public void EnableCertificateIdentityPinning_WhenNoStrategiesConfigured_ThrowsInvalidOperationException()
    {
        var builder = new CertificateTrustBuilder().UseSystemTrust();

        Assert.Throws<InvalidOperationException>(() => builder.EnableCertificateIdentityPinning(_ => { }));
    }

    [Test]
    public void IsIdentityAllowed_ReturnsTrue_WhenPinningDisabledByDefault()
    {
        var builder = new CertificateTrustBuilder();

        Assert.That(builder.Options.IsIdentityAllowed("tp", "sub", "iss"), Is.True);
    }

    [Test]
    public void IsIdentityAllowed_MatchesThumbprintIgnoringCaseAndSpaces()
    {
        var builder = new CertificateTrustBuilder().EnableCertificateIdentityPinning(p => p.AllowThumbprint("aa bb"));

        Assert.That(builder.Options.IsIdentityAllowed("AABB", "sub", "iss"), Is.True);
        Assert.That(builder.Options.IsIdentityAllowed("a a b b", "sub", "iss"), Is.True);
        Assert.That(builder.Options.IsIdentityAllowed("CCCC", "sub", "iss"), Is.False);
    }

    [Test]
    public void IsIdentityAllowed_MatchesSubjectIssuerPatterns()
    {
        var builder = new CertificateTrustBuilder().EnableCertificateIdentityPinning(p =>
        {
            p.AllowSubjectIssuerPattern("CN=Leaf", issuer: null, matchKind: CertificateIdentityMatchKind.Exact)
                .AllowSubjectIssuerPattern("CN=Test", issuer: "CN=Root", matchKind: CertificateIdentityMatchKind.Contains);
        });

        Assert.That(builder.Options.IsIdentityAllowed("tp", "CN=Leaf", "CN=Any"), Is.True);
        Assert.That(builder.Options.IsIdentityAllowed("tp", "CN=Test Leaf", "CN=Root CA"), Is.True);
        Assert.That(builder.Options.IsIdentityAllowed("tp", "CN=Test Leaf", "CN=Other"), Is.False);
    }

    [Test]
    public void UseCustomRootTrust_AddsRootsAndSetsSourceKind()
    {
        var chain = TestCertificateUtils.CreateTestChain(leafFirst: true);
        using var root = chain[^1];

        var builder = new CertificateTrustBuilder().UseCustomRootTrust(new X509Certificate2Collection { root });

        Assert.That(builder.Options.CustomTrustRoots.Count, Is.EqualTo(1));
    }
}
