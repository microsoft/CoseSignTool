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
public class CertificateKeyUsageValidatorTests
{
    private X509Certificate2? TestCert;
    private CoseSign1Message? ValidMessage;

    [SetUp]
#pragma warning disable CA2252 // Preview features
    public void SetUp()
    {
        TestCert = TestCertificateUtils.CreateCertificate("KeyUsageTest");

        var chainBuilder = new X509ChainBuilder();
        var signingService = new LocalCertificateSigningService(TestCert, chainBuilder);
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
    public void Constructor_WithKeyUsageFlags_CreatesValidator()
    {
        var validator = new CertificateKeyUsageValidator(X509KeyUsageFlags.DigitalSignature);
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithOid_CreatesValidator()
    {
        var oid = new Oid("1.3.6.1.5.5.7.3.3");
        var validator = new CertificateKeyUsageValidator(oid);
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullOid_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new CertificateKeyUsageValidator((Oid)null!));
    }

    [Test]
    public void Constructor_WithOidString_CreatesValidator()
    {
        var validator = new CertificateKeyUsageValidator("1.3.6.1.5.5.7.3.3");
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithNullOidString_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
            new CertificateKeyUsageValidator((string)null!));
    }

    [Test]
    public void Constructor_WithEmptyOidString_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
            new CertificateKeyUsageValidator(""));
    }

    [Test]
    public void Constructor_WithWhitespaceOidString_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
            new CertificateKeyUsageValidator("   "));
    }

    [Test]
    public void Validate_WithNullInput_ReturnsFailure()
    {
        var validator = new CertificateKeyUsageValidator(X509KeyUsageFlags.DigitalSignature);
        var result = validator.Validate(null!);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateKeyUsageValidator)));
        Assert.That(result.Failures.Any(e => e.ErrorCode == "NULL_INPUT"), Is.True);
    }

    [Test]
    public void Validate_WithValidKeyUsage_ReturnsSuccess()
    {
        var validator = new CertificateKeyUsageValidator(X509KeyUsageFlags.KeyCertSign);
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateKeyUsageValidator)));
        Assert.That(result.Metadata.ContainsKey("KeyUsage"), Is.True);
        Assert.That(result.Metadata.ContainsKey("CertificateThumbprint"), Is.True);
    }

    [Test]
    public async Task ValidateAsync_ReturnsResultSynchronously()
    {
        var validator = new CertificateKeyUsageValidator(X509KeyUsageFlags.KeyCertSign);
        var result = await validator.ValidateAsync(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithCancellationToken_CompletesSuccessfully()
    {
        var validator = new CertificateKeyUsageValidator(X509KeyUsageFlags.KeyCertSign);
        using var cts = new CancellationTokenSource();
        var result = await validator.ValidateAsync(ValidMessage!, cts.Token);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Validate_WithWrongKeyUsage_ReturnsFailure()
    {
        // The test certificate has KeyCertSign, try to validate for a different key usage that it doesn't have
        var validator = new CertificateKeyUsageValidator(X509KeyUsageFlags.CrlSign);
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(e => e.ErrorCode == "KEY_USAGE_MISMATCH"), Is.True);
    }

    [Test]
#pragma warning disable CA2252
    public void Validate_WithValidEKU_ReturnsSuccess()
    {
        // Create a certificate with Code Signing EKU
        using var certWithEku = TestCertificateUtils.CreateCertificate("EkuTest", customEkus: new[] { "1.3.6.1.5.5.7.3.3" });
        var chainBuilder = new X509ChainBuilder();
        var signingService = new LocalCertificateSigningService(certWithEku, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var validator = new CertificateKeyUsageValidator("1.3.6.1.5.5.7.3.3");
        var result = validator.Validate(message);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata.ContainsKey("EnhancedKeyUsage"), Is.True);
        Assert.That(result.Metadata.ContainsKey("CertificateThumbprint"), Is.True);
    }
#pragma warning restore CA2252

    [Test]
#pragma warning disable CA2252
    public void Validate_WithValidEKUOid_ReturnsSuccess()
    {
        // Create a certificate with Code Signing EKU
        using var certWithEku = TestCertificateUtils.CreateCertificate("EkuOidTest", customEkus: new[] { "1.3.6.1.5.5.7.3.3" });
        var chainBuilder = new X509ChainBuilder();
        var signingService = new LocalCertificateSigningService(certWithEku, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var oid = new Oid("1.3.6.1.5.5.7.3.3"); // Code Signing
        var validator = new CertificateKeyUsageValidator(oid);
        var result = validator.Validate(message);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata.ContainsKey("EnhancedKeyUsage"), Is.True);
    }
#pragma warning restore CA2252

    [Test]
    public void Validate_WithWrongEKU_ReturnsFailure()
    {
        // Try to validate for a different EKU than what's in the cert
        var validator = new CertificateKeyUsageValidator("1.2.3.4.5.6"); // Non-existent EKU
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(e => e.ErrorCode == "EKU_MISMATCH"), Is.True);
    }

    [Test]
#pragma warning disable CA2252
    public void Validate_WithMissingEKUExtension_ReturnsFailure()
    {
        // Create a certificate without any EKU extension (empty array still creates extension with 0 entries)
        // This tests the case where the extension exists but doesn't contain the required EKU
        using var certWithoutEku = TestCertificateUtils.CreateCertificate("NoEkuTest", customEkus: Array.Empty<string>());
        var chainBuilder = new X509ChainBuilder();
        var signingService = new LocalCertificateSigningService(certWithoutEku, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var message = CoseSign1Message.DecodeSign1(messageBytes);

        var validator = new CertificateKeyUsageValidator("1.3.6.1.5.5.7.3.3");
        var result = validator.Validate(message);

        // Empty EKU array still creates an extension, so we get EKU_MISMATCH not EKU_NOT_FOUND
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(e => e.ErrorCode == "EKU_NOT_FOUND" || e.ErrorCode == "EKU_MISMATCH"), Is.True);
    }
#pragma warning restore CA2252

    [Test]
    public void Validate_WithAllowUnprotectedHeaders_UsesUnprotectedHeaders()
    {
        var validator = new CertificateKeyUsageValidator(X509KeyUsageFlags.KeyCertSign, allowUnprotectedHeaders: true);
        var result = validator.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void Constructor_WithKeyUsageFlags_AndAllowUnprotectedHeaders_CreatesValidator()
    {
        var validator = new CertificateKeyUsageValidator(X509KeyUsageFlags.DigitalSignature, allowUnprotectedHeaders: true);
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithOid_AndAllowUnprotectedHeaders_CreatesValidator()
    {
        var oid = new Oid("1.3.6.1.5.5.7.3.3");
        var validator = new CertificateKeyUsageValidator(oid, allowUnprotectedHeaders: true);
        Assert.That(validator, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithOidString_AndAllowUnprotectedHeaders_CreatesValidator()
    {
        var validator = new CertificateKeyUsageValidator("1.3.6.1.5.5.7.3.3", allowUnprotectedHeaders: true);
        Assert.That(validator, Is.Not.Null);
    }
}