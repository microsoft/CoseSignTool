// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Validation;
using CoseSign1.Tests.Common;
using CoseSign1.Validation;
using NUnit.Framework;

namespace CoseSign1.Certificates.Tests.Validation;

[TestFixture]
public class CertificateValidatorBuilderCoverageTests
{
    private X509Certificate2? TestCert;

    [SetUp]
    public void SetUp()
    {
        TestCert = TestCertificateUtils.CreateCertificate("CoverageTest");
    }

    [TearDown]
    public void TearDown()
    {
        TestCert?.Dispose();
    }

    [Test]
    public void AddCertificateValidator_WhenNoValidatorsConfigured_Throws()
    {
        var builder = Cose.Sign1Message();

        Assert.Throws<InvalidOperationException>(() => builder.AddCertificateValidator(_ => { }));
    }

    [Test]
    public void AddCertificateValidator_CanInvokeAllBuilderMethods()
    {
        var builder = Cose.Sign1Message();

        var customRoots = new X509Certificate2Collection { TestCert! };
        var chainBuilder = new X509ChainBuilder();
        var detachedPayload = new byte[] { 1, 2, 3 };

        var result = builder.AddCertificateValidator(b => b
            .AllowUnprotectedHeaders()
            .ValidateSignature()
            .ValidateSignature(detachedPayload)
            .ValidateSignature(detachedPayload.AsMemory())
            .ValidateExpiration()
            .ValidateExpiration(DateTime.UtcNow)
            .ValidateCommonName("CoverageTest")
            .ValidateIssuer("CoverageTest")
            .ValidateKeyUsage(X509KeyUsageFlags.DigitalSignature)
            .ValidateEnhancedKeyUsage(new Oid("1.3.6.1.5.5.7.3.3"))
            .ValidateEnhancedKeyUsage("1.3.6.1.5.5.7.3.3")
            .ValidateChain()
            .ValidateChain(customRoots, trustUserRoots: false, revocationMode: X509RevocationMode.Offline)
            .ValidateChain(chainBuilder, allowUntrusted: true, customRoots: customRoots, trustUserRoots: false));

        Assert.That(result, Is.SameAs(builder));
        Assert.DoesNotThrow(() => builder.Build());
    }

    [Test]
    public void AddCertificateValidator_WhenBuilderArgumentsAreNull_Throws()
    {
        var builder = Cose.Sign1Message();

        Assert.Throws<ArgumentNullException>(() => builder.AddCertificateValidator(b => b.ValidateSignature((byte[])null!)));
        Assert.Throws<ArgumentNullException>(() => builder.AddCertificateValidator(b => b.ValidateChain((X509Certificate2Collection)null!)));
        Assert.Throws<ArgumentNullException>(() => builder.AddCertificateValidator(b => b.ValidateChain((ICertificateChainBuilder)null!)));
    }
}
