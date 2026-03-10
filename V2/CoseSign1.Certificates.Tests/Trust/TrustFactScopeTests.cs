// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Trust;

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Trust.Facts;
using CoseSign1.Validation.Trust.Facts;

/// <summary>
/// Tests for trust fact data classes and their Scope properties.
/// </summary>
[TestFixture]
public class TrustFactScopeTests
{
    [Test]
    public void X509ChainTrustedFact_Scope_ReturnsSigningKey()
    {
        X509ChainTrustedFact fact = new(
            chainBuilt: true,
            isTrusted: true,
            statusFlags: X509ChainStatusFlags.NoError,
            statusSummary: "OK",
            elementCount: 3);

        Assert.That(fact.Scope, Is.EqualTo(TrustFactScope.SigningKey));
        Assert.That(fact.ChainBuilt, Is.True);
        Assert.That(fact.IsTrusted, Is.True);
        Assert.That(fact.StatusFlags, Is.EqualTo(X509ChainStatusFlags.NoError));
        Assert.That(fact.StatusSummary, Is.EqualTo("OK"));
        Assert.That(fact.ElementCount, Is.EqualTo(3));
    }

    [Test]
    public void X509SigningCertificateBasicConstraintsFact_Scope_ReturnsSigningKey()
    {
        X509SigningCertificateBasicConstraintsFact fact = new("AABB", true, true, 2);

        Assert.That(fact.Scope, Is.EqualTo(TrustFactScope.SigningKey));
        Assert.That(fact.CertificateThumbprint, Is.EqualTo("AABB"));
        Assert.That(fact.CertificateAuthority, Is.True);
        Assert.That(fact.HasPathLengthConstraint, Is.True);
        Assert.That(fact.PathLengthConstraint, Is.EqualTo(2));
    }

    [Test]
    public void X509SigningCertificateKeyUsageFact_Scope_ReturnsSigningKey()
    {
        X509SigningCertificateKeyUsageFact fact = new("CCDD", X509KeyUsageFlags.DigitalSignature);

        Assert.That(fact.Scope, Is.EqualTo(TrustFactScope.SigningKey));
        Assert.That(fact.CertificateThumbprint, Is.EqualTo("CCDD"));
        Assert.That(fact.KeyUsages, Is.EqualTo(X509KeyUsageFlags.DigitalSignature));
    }

    [Test]
    public void X509SigningCertificateEkuFact_Scope_ReturnsSigningKey()
    {
        X509SigningCertificateEkuFact fact = new("EEFF", "1.3.6.1.5.5.7.3.3");

        Assert.That(fact.Scope, Is.EqualTo(TrustFactScope.SigningKey));
        Assert.That(fact.CertificateThumbprint, Is.EqualTo("EEFF"));
        Assert.That(fact.OidValue, Is.EqualTo("1.3.6.1.5.5.7.3.3"));
    }

    [Test]
    public void CertificateSigningKeyTrustFact_Scope_ReturnsSigningKey()
    {
        CertificateSigningKeyTrustFact fact = new(
            thumbprint: "0011",
            subject: "CN=Test",
            issuer: "CN=Issuer",
            chainBuilt: true,
            chainTrusted: false,
            chainStatusFlags: X509ChainStatusFlags.UntrustedRoot,
            chainStatusSummary: "Untrusted root");

        Assert.That(fact.Scope, Is.EqualTo(TrustFactScope.SigningKey));
        Assert.That(fact.Thumbprint, Is.EqualTo("0011"));
        Assert.That(fact.Subject, Is.EqualTo("CN=Test"));
        Assert.That(fact.Issuer, Is.EqualTo("CN=Issuer"));
        Assert.That(fact.ChainTrusted, Is.False);
    }

    [Test]
    public void X509SigningCertificateIdentityAllowedFact_Scope_ReturnsSigningKey()
    {
        X509SigningCertificateIdentityAllowedFact fact = new("2233", "CN=Leaf", "CN=CA", true);

        Assert.That(fact.Scope, Is.EqualTo(TrustFactScope.SigningKey));
        Assert.That(fact.IsAllowed, Is.True);
    }

    [Test]
    public void X509ChainElementIdentityFact_Scope_ReturnsSigningKey()
    {
        DateTime now = DateTime.UtcNow;
        X509ChainElementIdentityFact fact = new(
            depth: 0,
            chainLength: 3,
            certificateThumbprint: "4455",
            subject: "CN=Leaf",
            issuer: "CN=CA",
            serialNumber: "01",
            notBefore: now.AddYears(-1),
            notAfter: now.AddYears(1));

        Assert.That(fact.Scope, Is.EqualTo(TrustFactScope.SigningKey));
        Assert.That(fact.Depth, Is.EqualTo(0));
        Assert.That(fact.ChainLength, Is.EqualTo(3));
        Assert.That(fact.IsRoot, Is.False);
    }

    [Test]
    public void X509X5ChainCertificateIdentityFact_Scope_ReturnsSigningKey()
    {
        X509X5ChainCertificateIdentityFact fact = new(0, "6677", "CN=Leaf", "CN=CA");

        Assert.That(fact.Scope, Is.EqualTo(TrustFactScope.SigningKey));
        Assert.That(fact.Index, Is.EqualTo(0));
        Assert.That(fact.CertificateThumbprint, Is.EqualTo("6677"));
    }

    [Test]
    public void X509SigningCertificateIdentityFact_Scope_ReturnsSigningKey()
    {
        DateTime now = DateTime.UtcNow;
        X509SigningCertificateIdentityFact fact = new(
            certificateThumbprint: "8899",
            subject: "CN=Cert",
            issuer: "CN=Issuer",
            serialNumber: "FF",
            notBefore: now.AddYears(-1),
            notAfter: now.AddYears(1));

        Assert.That(fact.Scope, Is.EqualTo(TrustFactScope.SigningKey));
        Assert.That(fact.SerialNumber, Is.EqualTo("FF"));
    }
}
