// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Validation;
using CoseSign1.Tests.Common;
using NUnit.Framework;

[TestFixture]
public sealed class X509CertificateSigningKeyTests
{
    [Test]
    public void Ctor_WithCertificateAndChain_ExposesSameInstances()
    {
        using var certificate = TestCertificateUtils.CreateCertificate();
        var chain = new X509Certificate2Collection { certificate };

        using var signingKey = new X509CertificateSigningKey(certificate, chain);

        Assert.That(signingKey.Certificate, Is.SameAs(certificate));
        Assert.That(signingKey.Chain, Is.SameAs(chain));
    }

    [Test]
    public void GetCoseKey_WhenCalledMultipleTimes_ReturnsCachedInstance()
    {
        using var certificate = TestCertificateUtils.CreateCertificate();
        using var signingKey = new X509CertificateSigningKey(certificate);

        var first = signingKey.GetCoseKey();
        var second = signingKey.GetCoseKey();

        Assert.That(first, Is.Not.Null);
        Assert.That(second, Is.SameAs(first));
    }

    [Test]
    public void GetCoseKey_AfterDispose_ThrowsObjectDisposedException()
    {
        using var certificate = TestCertificateUtils.CreateCertificate();
        using var signingKey = new X509CertificateSigningKey(certificate);

        signingKey.Dispose();

        Assert.That(() => signingKey.GetCoseKey(), Throws.TypeOf<ObjectDisposedException>());
    }

    [Test]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        using var certificate = TestCertificateUtils.CreateCertificate();
        var signingKey = new X509CertificateSigningKey(certificate);

        signingKey.Dispose();
        signingKey.Dispose();

        Assert.Pass();
    }
}
