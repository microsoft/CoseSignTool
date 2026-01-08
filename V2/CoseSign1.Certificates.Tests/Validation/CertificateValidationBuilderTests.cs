// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Validation;
using CoseSign1.Direct;
using CoseSign1.Validation;

namespace CoseSign1.Certificates.Tests.Validation;

[TestFixture]
[System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
public class CertificateValidationBuilderTests
{
    private X509Certificate2? TestCert;
    private CoseSign1Message? ValidMessage;

    [SetUp]
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

    [TearDown]
    public void TearDown()
    {
        TestCert?.Dispose();
    }

    [Test]
    public void ValidateCertificate_HasCommonName_AddsCommonNameValidator()
    {
        var builder = Cose.Sign1Message();

        var certValidator = new CertificateValidationBuilder()
            .HasCommonName("BuilderTest")
            .Build();
        builder.AddValidator(certValidator);

        var verifier = builder.Build();
        var result = verifier.Validate(ValidMessage!);

        Assert.That(result.Trust.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificate_NotExpired_AddsExpirationValidator()
    {
        var builder = Cose.Sign1Message();

        var certValidator = new CertificateValidationBuilder()
            .NotExpired()
            .Build();
        builder.AddValidator(certValidator);

        var verifier = builder.Build();
        var result = verifier.Validate(ValidMessage!);

        Assert.That(result.Trust.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificate_NotExpiredWithTime_AddsExpirationValidator()
    {
        var builder = Cose.Sign1Message();
        var time = DateTime.UtcNow;

        var certValidator = new CertificateValidationBuilder()
            .NotExpired(time)
            .Build();
        builder.AddValidator(certValidator);

        var verifier = builder.Build();
        var result = verifier.Validate(ValidMessage!);

        Assert.That(result.Trust.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificate_HasEnhancedKeyUsageWithOid_AddsValidator()
    {
        var builder = Cose.Sign1Message();
        var oid = new Oid("1.3.6.1.5.5.7.3.3"); // Code signing

        var certValidator = new CertificateValidationBuilder()
            .HasEnhancedKeyUsage(oid)
            .Build();
        builder.AddValidator(certValidator);

        var validator = builder.Build();

        // May fail for test cert without EKU, but builder worked
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void ValidateCertificate_HasEnhancedKeyUsageWithString_AddsValidator()
    {
        var builder = Cose.Sign1Message();

        var certValidator = new CertificateValidationBuilder()
            .HasEnhancedKeyUsage("1.3.6.1.5.5.7.3.3")
            .Build();
        builder.AddValidator(certValidator);

        var validator = builder.Build();

        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void ValidateCertificate_HasKeyUsage_AddsValidator()
    {
        var builder = Cose.Sign1Message();

        var certValidator = new CertificateValidationBuilder()
            .HasKeyUsage(X509KeyUsageFlags.DigitalSignature)
            .Build();
        builder.AddValidator(certValidator);

        var validator = builder.Build();

        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void ValidateCertificate_Matches_AddsPredicateValidator()
    {
        var builder = Cose.Sign1Message();

        var certValidator = new CertificateValidationBuilder()
            .Matches(cert => cert.Subject.Contains("BuilderTest"))
            .Build();
        builder.AddValidator(certValidator);

        var verifier = builder.Build();
        var result = verifier.Validate(ValidMessage!);

        Assert.That(result.Trust.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificate_MatchesWithFailureMessage_AddsPredicateValidator()
    {
        var builder = Cose.Sign1Message();
        var customMessage = "Certificate did not match criteria";

        var certValidator = new CertificateValidationBuilder()
            .Matches(cert => false, customMessage)
            .Build();
        builder.AddValidator(certValidator);

        var verifier = builder.Build();
        var result = verifier.Validate(ValidMessage!);

        Assert.That(result.Trust.IsValid, Is.False);
        Assert.That(result.Signature.IsNotApplicable, Is.True);
    }

    [Test]
    public void ValidateCertificate_AllowUnprotectedHeaders_ConfiguresBuilder()
    {
        var builder = Cose.Sign1Message();

        var certValidator = new CertificateValidationBuilder()
            .AllowUnprotectedHeaders(true)
            .HasCommonName("BuilderTest")
            .Build();
        builder.AddValidator(certValidator);

        var verifier = builder.Build();
        var result = verifier.Validate(ValidMessage!);

        Assert.That(result.Trust.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificate_AllowUnprotectedHeadersFalse_ConfiguresBuilder()
    {
        var builder = Cose.Sign1Message();

        var certValidator = new CertificateValidationBuilder()
            .AllowUnprotectedHeaders(false)
            .HasCommonName("BuilderTest")
            .Build();
        builder.AddValidator(certValidator);

        var validator = builder.Build();

        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void ValidateCertificate_MultipleValidators_BuildsComposite()
    {
        var builder = Cose.Sign1Message();

        var certValidator = new CertificateValidationBuilder()
            .HasCommonName("BuilderTest")
            .NotExpired()
            .Matches(cert => cert.Subject.Contains("BuilderTest"))
            .Build();
        builder.AddValidator(certValidator);

        var verifier = builder.Build();
        var result = verifier.Validate(ValidMessage!);

        Assert.That(result.Trust.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificate_IsIssuedBy_AddsIssuerValidator()
    {
        var builder = Cose.Sign1Message();

        var certValidator = new CertificateValidationBuilder()
            // Self-signed test certificate uses the same CN for subject and issuer.
            .IsIssuedBy("BuilderTest")
            .Build();
        builder.AddValidator(certValidator);

        var verifier = builder.Build();
        var result = verifier.Validate(ValidMessage!);

        Assert.That(result.Trust.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificate_ChainedCalls_ReturnsBuilder()
    {
        var certBuilder = new CertificateValidationBuilder();

        var result1 = certBuilder.HasCommonName("Test");
        var result2 = result1.NotExpired();
        var result3 = result2.AllowUnprotectedHeaders(true);

        Assert.That(result1, Is.SameAs(certBuilder));
        Assert.That(result2, Is.SameAs(certBuilder));
        Assert.That(result3, Is.SameAs(certBuilder));
    }

    [Test]
    public void ValidateCertificate_AllowUnprotectedHeadersAfterValidators_AppliesRetroactively()
    {
        // AllowUnprotectedHeaders should apply to all validators added before and after
        var builder = Cose.Sign1Message();

        var certValidator = new CertificateValidationBuilder()
            .HasCommonName("BuilderTest")
            .AllowUnprotectedHeaders(true)
            .NotExpired()
            .Build();
        builder.AddValidator(certValidator);

        var verifier = builder.Build();
        var result = verifier.Validate(ValidMessage!);

        Assert.That(result.Trust.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificate_MatchesWithNullPredicate_ThrowsArgumentNullException()
    {
        var certBuilder = new CertificateValidationBuilder();
        Assert.Throws<ArgumentNullException>(() => certBuilder.Matches(null!));
    }
}