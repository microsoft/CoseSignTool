// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Validation;
using CoseSign1.Direct;
using CoseSign1.Validation;

namespace CoseSign1.Certificates.Tests.Validation;

[TestFixture]
[System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
public class CertificateValidationExtensionsTests
{
    private X509Certificate2? TestCert;
    private CoseSign1Message? ValidMessage;

    [SetUp]
    public void SetUp()
    {
        TestCert = TestCertificateUtils.CreateCertificate("ExtensionTest");

        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        ValidMessage = CoseSign1Message.DecodeSign1(messageBytes);
    }

    [TearDown]
    public void TearDown()
    {
        TestCert?.Dispose();
    }

    [Test]
    public void CertificateValidationBuilder_ValidatesMessage_WhenCommonNameAndNotExpiredConfigured()
    {
        var verifier = Cose.Sign1Message()
            .AddValidator(new CertificateValidationBuilder()
                .NotExpired()
                .HasCommonName("ExtensionTest")
                .Build())
            .Build();

        var result = verifier.Validate(ValidMessage!);

        Assert.That(result.Trust.IsValid, Is.True);
        Assert.That(result.Signature.IsValid, Is.True);
        Assert.That(result.Overall.IsValid, Is.True);
    }

    [Test]
    public void CertificateValidationBuilder_CanConfigureCustomRootsChain()
    {
        var customRoots = new X509Certificate2Collection { TestCert! };

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
