// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Local;
using CoseSign1.Certificates.Validation;
using CoseSign1.Direct;
using CoseSign1.Tests.Common;
using CoseSign1.Validation;
using NUnit.Framework;

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
    public void AddCertificateValidator_AddsValidatorsAndValidatesMessage()
    {
        var validator = Cose.Sign1Message()
            .AddCertificateValidator(b => b
                .AllowUnprotectedHeaders(true)
                .ValidateSignature()
                .ValidateExpiration()
                .ValidateCommonName("ExtensionTest"))
            .Build();

        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificateIssuer_AddsValidator()
    {
        var builder = Cose.Sign1Message();

        var result = builder.ValidateCertificateIssuer("TestIssuer", allowUnprotectedHeaders: true);

        Assert.That(result, Is.SameAs(builder));
    }
}
