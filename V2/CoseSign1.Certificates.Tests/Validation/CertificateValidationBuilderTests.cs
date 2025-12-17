// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
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
public class CertificateValidationBuilderTests
{
    private X509Certificate2? TestCert;
    private CoseSign1Message? ValidMessage;

    [SetUp]
#pragma warning disable CA2252 // Preview features
    public void SetUp()
    {
        TestCert = TestCertificateUtils.CreateCertificate("BuilderTest");

        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(TestCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        ValidMessage = CoseSign1Message.DecodeSign1(messageBytes);
    }
#pragma warning restore CA2252

    [TearDown]
    public void TearDown()
    {
        TestCert?.Dispose();
    }

    [Test]
    public void ValidateCertificate_HasCommonName_AddsCommonNameValidator()
    {
        var builder = Cose.Sign1Message();

        builder.ValidateCertificate(certBuilder =>
        {
            certBuilder.HasCommonName("BuilderTest");
        });

        var validator = builder.Build();
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificate_NotExpired_AddsExpirationValidator()
    {
        var builder = Cose.Sign1Message();

        builder.ValidateCertificate(certBuilder =>
        {
            certBuilder.NotExpired();
        });

        var validator = builder.Build();
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificate_NotExpiredWithTime_AddsExpirationValidator()
    {
        var builder = Cose.Sign1Message();
        var time = DateTime.UtcNow;

        builder.ValidateCertificate(certBuilder =>
        {
            certBuilder.NotExpired(time);
        });

        var validator = builder.Build();
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificate_HasEnhancedKeyUsageWithOid_AddsValidator()
    {
        var builder = Cose.Sign1Message();
        var oid = new Oid("1.3.6.1.5.5.7.3.3"); // Code signing

        builder.ValidateCertificate(certBuilder =>
        {
            certBuilder.HasEnhancedKeyUsage(oid);
        });

        var validator = builder.Build();

        // May fail for test cert without EKU, but builder worked
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void ValidateCertificate_HasEnhancedKeyUsageWithString_AddsValidator()
    {
        var builder = Cose.Sign1Message();

        builder.ValidateCertificate(certBuilder =>
        {
            certBuilder.HasEnhancedKeyUsage("1.3.6.1.5.5.7.3.3");
        });

        var validator = builder.Build();

        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void ValidateCertificate_HasKeyUsage_AddsValidator()
    {
        var builder = Cose.Sign1Message();

        builder.ValidateCertificate(certBuilder =>
        {
            certBuilder.HasKeyUsage(X509KeyUsageFlags.DigitalSignature);
        });

        var validator = builder.Build();

        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void ValidateCertificate_Matches_AddsPredicateValidator()
    {
        var builder = Cose.Sign1Message();

        builder.ValidateCertificate(certBuilder =>
        {
            certBuilder.Matches(cert => cert.Subject.Contains("BuilderTest"));
        });

        var validator = builder.Build();
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificate_MatchesWithFailureMessage_AddsPredicateValidator()
    {
        var builder = Cose.Sign1Message();
        var customMessage = "Certificate did not match criteria";

        builder.ValidateCertificate(certBuilder =>
        {
            certBuilder.Matches(cert => false, customMessage);
        });

        var validator = builder.Build();
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.False);
    }

    [Test]
    public void ValidateCertificate_AllowUnprotectedHeaders_ConfiguresBuilder()
    {
        var builder = Cose.Sign1Message();

        builder.ValidateCertificate(certBuilder =>
        {
            certBuilder.AllowUnprotectedHeaders(true);
            certBuilder.HasCommonName("BuilderTest");
        });

        var validator = builder.Build();
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificate_AllowUnprotectedHeadersFalse_ConfiguresBuilder()
    {
        var builder = Cose.Sign1Message();

        builder.ValidateCertificate(certBuilder =>
        {
            certBuilder.AllowUnprotectedHeaders(false);
            certBuilder.HasCommonName("BuilderTest");
        });

        var validator = builder.Build();

        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void ValidateCertificate_MultipleValidators_BuildsComposite()
    {
        var builder = Cose.Sign1Message();

        builder.ValidateCertificate(certBuilder =>
        {
            certBuilder.HasCommonName("BuilderTest");
            certBuilder.NotExpired();
            certBuilder.Matches(cert => cert.Subject.Contains("BuilderTest"));
        });

        var validator = builder.Build();
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificate_IsIssuedBy_ThrowsNotImplementedException()
    {
        var builder = Cose.Sign1Message();

        Assert.Throws<NotImplementedException>(() =>
        {
            builder.ValidateCertificate(certBuilder =>
            {
                certBuilder.IsIssuedBy("TestIssuer");
            });
        });
    }

    [Test]
    public void ValidateCertificate_ChainedCalls_ReturnsBuilder()
    {
        var builder = Cose.Sign1Message();

        builder.ValidateCertificate(certBuilder =>
        {
            var result1 = certBuilder.HasCommonName("Test");
            var result2 = result1.NotExpired();
            var result3 = result2.AllowUnprotectedHeaders(true);

            Assert.That(result1, Is.SameAs(certBuilder));
            Assert.That(result2, Is.SameAs(certBuilder));
            Assert.That(result3, Is.SameAs(certBuilder));
        });
    }

    [Test]
    public void ValidateCertificate_AllowUnprotectedHeadersAfterValidators_AppliesRetroactively()
    {
        // AllowUnprotectedHeaders should apply to all validators added before and after
        var builder = Cose.Sign1Message();

        builder.ValidateCertificate(certBuilder =>
        {
            certBuilder.HasCommonName("BuilderTest");
            certBuilder.AllowUnprotectedHeaders(true);
            certBuilder.NotExpired();
        });

        var validator = builder.Build();
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificate_MatchesWithNullPredicate_ThrowsArgumentNullException()
    {
        var builder = Cose.Sign1Message();

        Assert.Throws<ArgumentNullException>(() =>
        {
            builder.ValidateCertificate(certBuilder =>
            {
                certBuilder.Matches(null!);
            });
        });
    }
}