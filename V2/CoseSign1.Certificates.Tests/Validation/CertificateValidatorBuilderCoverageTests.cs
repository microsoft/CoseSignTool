// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation;

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
    public void CertificateValidationBuilder_WhenNoPropertyValidatorsConfigured_DoesNotThrow()
    {
        var validator = new CertificateValidationBuilder().Build();
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void CertificateValidationBuilder_CanInvokeAllBuilderMethods()
    {
        var builder = Cose.Sign1Message();

        var customRoots = new X509Certificate2Collection { TestCert! };
        var chainBuilder = new X509ChainBuilder();

        var certValidator = new CertificateValidationBuilder()
            .AllowUnprotectedHeaders()
            .NotExpired()
            .NotExpired(DateTime.UtcNow)
            .HasCommonName("CoverageTest")
            .IsIssuedBy("CoverageTest")
            .HasKeyUsage(X509KeyUsageFlags.DigitalSignature)
            .HasEnhancedKeyUsage(new Oid("1.3.6.1.5.5.7.3.3"))
            .HasEnhancedKeyUsage("1.3.6.1.5.5.7.3.3")
            .Matches(_ => true)
            .ValidateChain()
            .ValidateChain(customRoots, trustUserRoots: false, revocationMode: X509RevocationMode.Offline)
            .ValidateChain(chainBuilder, allowUntrusted: true, customRoots: customRoots, trustUserRoots: false)
            .Build();

        builder.AddValidator(certValidator);
        Assert.DoesNotThrow(() => builder.Build());
    }

    [Test]
    public void CertificateValidationBuilder_WhenBuilderArgumentsAreNull_Throws()
    {
        var certBuilder = new CertificateValidationBuilder();

        Assert.Throws<ArgumentNullException>(() => certBuilder.Matches(null!));
        Assert.Throws<ArgumentNullException>(() => certBuilder.ValidateChain((X509Certificate2Collection)null!));
        Assert.Throws<ArgumentNullException>(() => certBuilder.ValidateChain((ICertificateChainBuilder)null!));
    }
}
