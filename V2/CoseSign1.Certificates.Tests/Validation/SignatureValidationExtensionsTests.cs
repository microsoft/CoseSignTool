// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
public class SignatureValidationExtensionsTests
{
    private System.Security.Cryptography.X509Certificates.X509Certificate2? TestCert;
    private CoseSign1Message? ValidMessage;
    private byte[]? Payload;

    [SetUp]
    public void SetUp()
    {
        TestCert = TestCertificateUtils.CreateCertificate("ExtensionTest");

        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        Payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(Payload, "application/test");
        ValidMessage = CoseSign1Message.DecodeSign1(messageBytes);
    }

    [TearDown]
    public void TearDown()
    {
        TestCert?.Dispose();
    }

    [Test]
    public void ValidateCertificateSignature_AddsValidator()
    {
        var builder = Cose.Sign1Message();

        var result = builder.ValidateCertificateSignature();

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateCertificateSignature_WithAllowUnprotectedHeaders_AddsValidator()
    {
        var builder = Cose.Sign1Message();

        var result = builder.ValidateCertificateSignature(allowUnprotectedHeaders: true);

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateCertificateSignature_WithDetachedPayloadByteArray_AddsValidator()
    {
        var builder = Cose.Sign1Message();
        var payload = new byte[] { 1, 2, 3 };

        var result = builder.ValidateCertificateSignature(payload);

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateCertificateSignature_WithDetachedPayloadReadOnlyMemory_AddsValidator()
    {
        var builder = Cose.Sign1Message();
        var payload = new ReadOnlyMemory<byte>(new byte[] { 1, 2, 3 });

        var result = builder.ValidateCertificateSignature(payload);

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateCertificateSignature_ValidatesMessage()
    {
        var builder = Cose.Sign1Message()
            .ValidateCertificateSignature();

        var validator = builder.Build();
        var validationResult = validator.Validate(ValidMessage!);

        Assert.That(validationResult.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificateSignature_WithUnprotectedHeaders_ValidatesMessage()
    {
        var builder = Cose.Sign1Message()
            .ValidateCertificateSignature(allowUnprotectedHeaders: true);

        var validator = builder.Build();
        var validationResult = validator.Validate(ValidMessage!);

        Assert.That(validationResult.IsValid, Is.True);
    }
}