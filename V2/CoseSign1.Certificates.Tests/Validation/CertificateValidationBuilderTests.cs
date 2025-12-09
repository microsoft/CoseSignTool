// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.Extensions;
using CoseSign1.Certificates.Local;
using CoseSign1.Certificates.Validation;
using CoseSign1.Direct;
using CoseSign1.Tests.Common;
using CoseSign1.Validation;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CoseSign1.Certificates.Tests.Validation;

[TestFixture]
public class CertificateValidationBuilderTests
{
    private static readonly byte[] TestPayload = Encoding.UTF8.GetBytes("Hello, world!");

    [Test]
    public void ValidateCertificate_WithSubBuilder_ValidatesCommonName()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("Test Certificate", useEcc: true);
        using var signingService = new LocalCertificateSigningService(cert, new[] { cert });
        using var factory = new DirectSignatureFactory(signingService);

        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/json");
        var msg = CoseMessage.DecodeSign1(messageBytes);

        // Act - Using sub-builder pattern
        var validator = Cose.Sign1Message()
            .ValidateCertificate(cert => cert
                .HasCommonName("Test Certificate"))
            .Build();

        var result = validator.Validate(msg);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificate_WithSubBuilder_ValidatesExpiration()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate(useEcc: true);
        using var signingService = new LocalCertificateSigningService(cert, new[] { cert });
        using var factory = new DirectSignatureFactory(signingService);

        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/json");
        var msg = CoseMessage.DecodeSign1(messageBytes);

        // Act - Using sub-builder pattern
        var validator = Cose.Sign1Message()
            .ValidateCertificate(cert => cert
                .NotExpired())
            .Build();

        var result = validator.Validate(msg);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificate_WithSubBuilder_CombinesMultipleValidators()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("Test Certificate", useEcc: true);
        using var signingService = new LocalCertificateSigningService(cert, new[] { cert });
        using var factory = new DirectSignatureFactory(signingService);

        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/json");
        var msg = CoseMessage.DecodeSign1(messageBytes);

        // Act - Using sub-builder pattern with multiple validators
        var validator = Cose.Sign1Message()
            .ValidateCertificate(cert => cert
                .HasCommonName("Test Certificate")
                .NotExpired())
            .Build();

        var result = validator.Validate(msg);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificate_WithSubBuilder_FailsOnWrongCommonName()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("Test Certificate", useEcc: true);
        using var signingService = new LocalCertificateSigningService(cert, new[] { cert });
        using var factory = new DirectSignatureFactory(signingService);

        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/json");
        var msg = CoseMessage.DecodeSign1(messageBytes);

        // Act - Using sub-builder pattern with wrong CN
        var validator = Cose.Sign1Message()
            .ValidateCertificate(cert => cert
                .HasCommonName("Wrong Name"))
            .Build();

        var result = validator.Validate(msg);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Some.Matches<ValidationFailure>(f => f.ErrorCode == "CN_MISMATCH"));
    }

    [Test]
    public void ValidateCertificate_WithSubBuilder_CustomPredicate()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("Test Certificate", useEcc: true);
        using var signingService = new LocalCertificateSigningService(cert, new[] { cert });
        using var factory = new DirectSignatureFactory(signingService);

        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/json");
        var msg = CoseMessage.DecodeSign1(messageBytes);

        // Act - Using sub-builder pattern with custom predicate
        var validator = Cose.Sign1Message()
            .ValidateCertificate(c => c
                .Matches(cert => cert.Subject.Contains("Test"), "Certificate must have 'Test' in subject"))
            .Build();

        var result = validator.Validate(msg);

        // Assert
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificate_WithSubBuilder_CollectsAllFailures()
    {
        // Arrange
        using var cert = TestCertificateUtils.CreateCertificate("Test Certificate", useEcc: true);
        using var signingService = new LocalCertificateSigningService(cert, new[] { cert });
        using var factory = new DirectSignatureFactory(signingService);

        var messageBytes = factory.CreateCoseSign1MessageBytes(TestPayload, "application/json");
        var msg = CoseMessage.DecodeSign1(messageBytes);

        var futureDate = DateTime.UtcNow.AddYears(100);

        // Act - Using sub-builder pattern with multiple failing validators
        var validator = Cose.Sign1Message()
            .ValidateCertificate(cert => cert
                .HasCommonName("Wrong Name")
                .NotExpired(futureDate))
            .Build();

        var result = validator.Validate(msg);

        // Assert
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(2));
        Assert.That(result.Failures, Has.Some.Matches<ValidationFailure>(f => f.ErrorCode == "CN_MISMATCH"));
        Assert.That(result.Failures, Has.Some.Matches<ValidationFailure>(f => f.ErrorCode == "CERTIFICATE_EXPIRED"));
    }
}
