// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation;

[TestFixture]
public class CertificateValidatorBuilderCoverageTests
{
    /// <summary>
    /// Holds the test state for each test method.
    /// </summary>
    private sealed record TestContext(X509Certificate2 TestCert) : IDisposable
    {
        public void Dispose() => TestCert?.Dispose();
    }

    /// <summary>
    /// Creates a fresh test context with isolated state.
    /// </summary>
    private static TestContext CreateTestContext()
    {
        var testCert = TestCertificateUtils.CreateCertificate("CoverageTest");
        return new TestContext(testCert);
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
        using var ctx = CreateTestContext();
        var builder = Cose.Sign1Message();

        var customRoots = new X509Certificate2Collection { ctx.TestCert };
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
