// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Local;
using CoseSign1.Certificates.Validation;
using CoseSign1.Direct;
using CoseSign1.Tests.Common;
using CoseSign1.Validation;
using NUnit.Framework;
using System.Security.Cryptography.X509Certificates;

namespace CoseSign1.Certificates.Tests.Validation;

[TestFixture]
public class CertificateValidationExtensionsTests
{
    private X509Certificate2? _testCert;
    private CoseSign1Message? _validMessage;

    [SetUp]
    #pragma warning disable CA2252 // Preview features
    public void SetUp()
    {
        _testCert = TestCertificateUtils.CreateCertificate("ExtensionTest");
        
        var chainBuilder = new X509ChainBuilder();
        var signingService = new LocalCertificateSigningService(_testCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        _validMessage = CoseSign1Message.DecodeSign1(messageBytes);
    }
    #pragma warning restore CA2252

    [TearDown]
    public void TearDown()
    {
        _testCert?.Dispose();
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
        var validationResult = validator.Validate(_validMessage!);
        
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
        var validationResult = validator.Validate(_validMessage!);
        
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
}
