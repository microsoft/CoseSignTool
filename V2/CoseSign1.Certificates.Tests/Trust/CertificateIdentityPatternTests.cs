// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Trust;

using CoseSign1.Certificates.Trust;

[TestFixture]
public class CertificateIdentityPatternTests
{
    [Test]
    public void Constructor_NullSubject_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new CertificateIdentityPattern(null!, issuer: null, matchKind: CertificateIdentityMatchKind.Exact));
    }

    [Test]
    public void Constructor_SetsProperties()
    {
        var pattern = new CertificateIdentityPattern("CN=Leaf", issuer: "CN=Root", matchKind: CertificateIdentityMatchKind.Contains);

        Assert.That(pattern.Subject, Is.EqualTo("CN=Leaf"));
        Assert.That(pattern.Issuer, Is.EqualTo("CN=Root"));
        Assert.That(pattern.MatchKind, Is.EqualTo(CertificateIdentityMatchKind.Contains));
    }
}
