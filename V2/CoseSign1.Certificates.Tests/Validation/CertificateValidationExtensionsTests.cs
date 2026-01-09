// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Validation;
using CoseSign1.Direct;
using CoseSign1.Validation;

[TestFixture]
[System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
public class CertificateValidationExtensionsTests
{
    /// <summary>
    /// Holds the test state for each test method.
    /// </summary>
    private sealed record TestContext(
        X509Certificate2 TestCert,
        CoseSign1Message ValidMessage) : IDisposable
    {
        public void Dispose() => TestCert?.Dispose();
    }

    /// <summary>
    /// Creates a fresh test context with isolated state.
    /// </summary>
    private static TestContext CreateTestContext()
    {
        var testCert = TestCertificateUtils.CreateCertificate("ExtensionTest");

        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(testCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var validMessage = CoseSign1Message.DecodeSign1(messageBytes);

        return new TestContext(testCert, validMessage);
    }

    [Test]
    public void CertificateValidationBuilder_ValidatesMessage_WhenCommonNameAndNotExpiredConfigured()
    {
        using var ctx = CreateTestContext();
        var verifier = Cose.Sign1Message()
            .AddValidator(new CertificateValidationBuilder()
                .NotExpired()
                .HasCommonName("ExtensionTest")
                .Build())
            .Build();

        var result = verifier.Validate(ctx.ValidMessage);

        Assert.That(result.Trust.IsValid, Is.True);
        Assert.That(result.Signature.IsValid, Is.True);
        Assert.That(result.Overall.IsValid, Is.True);
    }

    [Test]
    public void CertificateValidationBuilder_CanConfigureCustomRootsChain()
    {
        using var ctx = CreateTestContext();
        var customRoots = new X509Certificate2Collection { ctx.TestCert };

        var certValidator = new CertificateValidationBuilder()
            .ValidateChain(customRoots, trustUserRoots: false, revocationMode: X509RevocationMode.NoCheck)
            .Build();

        Assert.That(certValidator, Is.Not.Null);
    }

    [Test]
    public void CertificateValidationBuilder_CanConfigureEnhancedKeyUsage()
    {
        var certValidator = new CertificateValidationBuilder()
            .HasEnhancedKeyUsage("1.3.6.1.5.5.7.3.3")
            .Build();

        Assert.That(certValidator, Is.Not.Null);
    }
}
