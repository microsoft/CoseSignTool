// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Validation;
using CoseSign1.Direct;
using CoseSign1.Validation;

namespace CoseSign1.Certificates.Tests.Validation;

[TestFixture]
[System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
public class CertificateValidatorBuilderExtensionsTests
{
    private System.Security.Cryptography.X509Certificates.X509Certificate2? TestCert;
    private CoseSign1Message? ValidMessage;

    [SetUp]
    public void SetUp()
    {
        // Create a self-signed cert with subject CN = "ExtensionTest".
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
    public void ValidateCertificate_AddsValidatorsAndValidatesMessage()
    {
        var verifier = Cose.Sign1Message()
            .AddValidator(
                new CertificateValidationBuilder()
                    .AllowUnprotectedHeaders(true)
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
    public void ValidateCertificateIssuer_AddsValidator()
    {
        var validator = new CertificateValidationBuilder()
            .AllowUnprotectedHeaders(true)
            .IsIssuedBy("TestIssuer")
            .Build();

        Assert.That(validator, Is.Not.Null);
    }
}
