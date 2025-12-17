// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;
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
    public void ValidateCertificate_WithConfigureAction_AddsValidator()
    {
        var builder = Cose.Sign1Message();

        // Must configure at least one validator to avoid exception
        var result = builder.ValidateCertificate(certBuilder =>
        {
            certBuilder.NotExpired();
        });

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateCertificateCommonName_AddsValidator()
    {
        var builder = Cose.Sign1Message();

        var result = builder.ValidateCertificateCommonName("Test");

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateCertificateCommonName_ValidatesMessage()
    {
        var builder = Cose.Sign1Message()
            .ValidateCertificateCommonName("ExtensionTest");

        var validator = builder.Build();
        var validationResult = validator.Validate(ValidMessage!);

        Assert.That(validationResult.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificateCommonName_WithUnprotectedHeaders_AddsValidator()
    {
        var builder = Cose.Sign1Message();

        var result = builder.ValidateCertificateCommonName("Test", allowUnprotectedHeaders: true);

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateCertificateExpiration_AddsValidator()
    {
        var builder = Cose.Sign1Message();

        var result = builder.ValidateCertificateExpiration();

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateCertificateExpiration_ValidatesMessage()
    {
        var builder = Cose.Sign1Message()
            .ValidateCertificateExpiration();

        var validator = builder.Build();
        var validationResult = validator.Validate(ValidMessage!);

        Assert.That(validationResult.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificateExpiration_WithTime_AddsValidator()
    {
        var builder = Cose.Sign1Message();
        var time = DateTime.UtcNow;

        var result = builder.ValidateCertificateExpiration(time);

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateCertificateExpiration_WithTimeAndUnprotectedHeaders_AddsValidator()
    {
        var builder = Cose.Sign1Message();
        var time = DateTime.UtcNow;

        var result = builder.ValidateCertificateExpiration(time, allowUnprotectedHeaders: true);

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateCertificateChain_AddsValidator()
    {
        var builder = Cose.Sign1Message();

        var result = builder.ValidateCertificateChain();

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateCertificateChain_WithOptions_AddsValidator()
    {
        var builder = Cose.Sign1Message();

        var result = builder.ValidateCertificateChain(
            allowUnprotectedHeaders: true,
            allowUntrusted: true,
            revocationMode: X509RevocationMode.NoCheck);

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateCertificateChain_WithCustomRoots_AddsValidator()
    {
        var builder = Cose.Sign1Message();
        var customRoots = new X509Certificate2Collection();

        var result = builder.ValidateCertificateChain(customRoots);

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateCertificateChain_WithChainBuilder_AddsValidator()
    {
        var builder = Cose.Sign1Message();
        var chainBuilder = new X509ChainBuilder();

        var result = builder.ValidateCertificateChain(chainBuilder);

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateCertificateKeyUsage_AddsValidator()
    {
        var builder = Cose.Sign1Message();

        var result = builder.ValidateCertificateKeyUsage(X509KeyUsageFlags.DigitalSignature);

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateCertificateKeyUsage_WithUnprotectedHeaders_AddsValidator()
    {
        var builder = Cose.Sign1Message();

        var result = builder.ValidateCertificateKeyUsage(
            X509KeyUsageFlags.DigitalSignature,
            allowUnprotectedHeaders: true);

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateCertificateEnhancedKeyUsage_WithOid_AddsValidator()
    {
        var builder = Cose.Sign1Message();
        var codeSigningOid = new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.3", "Code Signing");

        var result = builder.ValidateCertificateEnhancedKeyUsage(codeSigningOid);

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateCertificateEnhancedKeyUsage_WithOidAndUnprotectedHeaders_AddsValidator()
    {
        var builder = Cose.Sign1Message();
        var codeSigningOid = new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.3", "Code Signing");

        var result = builder.ValidateCertificateEnhancedKeyUsage(codeSigningOid, allowUnprotectedHeaders: true);

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateCertificateEnhancedKeyUsage_WithOidString_AddsValidator()
    {
        var builder = Cose.Sign1Message();

        var result = builder.ValidateCertificateEnhancedKeyUsage("1.3.6.1.5.5.7.3.3");

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateCertificateEnhancedKeyUsage_WithOidStringAndUnprotectedHeaders_AddsValidator()
    {
        var builder = Cose.Sign1Message();

        var result = builder.ValidateCertificateEnhancedKeyUsage("1.3.6.1.5.5.7.3.3", allowUnprotectedHeaders: true);

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateCertificateChain_WithChainBuilderAndAllOptions_AddsValidator()
    {
        var builder = Cose.Sign1Message();
        var chainBuilder = new X509ChainBuilder();
        var customRoots = new X509Certificate2Collection();

        var result = builder.ValidateCertificateChain(
            chainBuilder,
            allowUnprotectedHeaders: true,
            allowUntrusted: true,
            customRoots: customRoots,
            trustUserRoots: false);

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateCertificateChain_WithCustomRootsAndOptions_AddsValidator()
    {
        var builder = Cose.Sign1Message();
        var customRoots = new X509Certificate2Collection { TestCert! };

        var result = builder.ValidateCertificateChain(
            customRoots,
            allowUnprotectedHeaders: true,
            trustUserRoots: false,
            revocationMode: X509RevocationMode.NoCheck);

        Assert.That(result, Is.SameAs(builder));
    }
}