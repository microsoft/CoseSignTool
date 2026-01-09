// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Validation;
using CoseSign1.Direct;
using CoseSign1.Validation;
using CoseSign1.Validation.Interfaces;

[TestFixture]
[System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
public class SignatureValidationExtensionsTests
{
    /// <summary>
    /// Holds the test state for each test method.
    /// </summary>
    private sealed record TestContext(
        System.Security.Cryptography.X509Certificates.X509Certificate2 TestCert,
        CoseSign1Message ValidMessage,
        byte[] Payload) : IDisposable
    {
        public void Dispose() => TestCert?.Dispose();
    }

    /// <summary>
    /// Creates a fresh test context with isolated state.
    /// </summary>
    private static TestContext CreateTestContext()
    {
        var testCert = TestCertificateUtils.CreateCertificate("ExtensionTest");

        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(testCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var validMessage = CoseSign1Message.DecodeSign1(messageBytes);

        return new TestContext(testCert, validMessage, payload);
    }

    #region ValidateCertificate fluent API tests

    [Test]
    public void ValidateCertificate_WithConfigure_ReturnsBuilder()
    {
        var builder = Cose.Sign1Message();

        var result = builder.ValidateCertificate(cert => cert.NotExpired());

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateCertificate_WithNullBuilder_ThrowsArgumentNullException()
    {
        ICoseSign1ValidationBuilder? builder = null;

        Assert.That(() => builder!.ValidateCertificate(cert => cert.NotExpired()),
            Throws.ArgumentNullException);
    }

    [Test]
    public void ValidateCertificate_WithNullConfigure_ThrowsArgumentNullException()
    {
        var builder = Cose.Sign1Message();

        Assert.That(() => builder.ValidateCertificate(null!),
            Throws.ArgumentNullException);
    }

    [Test]
    public void ValidateCertificate_WithDetachedPayload_ReturnsBuilder()
    {
        var builder = Cose.Sign1Message();
        var payload = new byte[] { 1, 2, 3 };

        var result = builder.ValidateCertificate(payload, cert => cert.NotExpired());

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateCertificate_WithDetachedPayloadReadOnlyMemory_ReturnsBuilder()
    {
        var builder = Cose.Sign1Message();
        var payload = new ReadOnlyMemory<byte>(new byte[] { 1, 2, 3 });

        var result = builder.ValidateCertificate(payload, cert => cert.NotExpired());

        Assert.That(result, Is.SameAs(builder));
    }

    [Test]
    public void ValidateCertificate_WithNullDetachedPayload_ThrowsArgumentNullException()
    {
        var builder = Cose.Sign1Message();
        byte[]? payload = null;

        Assert.That(() => builder.ValidateCertificate(payload!, cert => cert.NotExpired()),
            Throws.ArgumentNullException);
    }

    [Test]
    public void ValidateCertificate_FluentApi_ValidatesMessage()
    {
        using var ctx = CreateTestContext();
        var verifier = Cose.Sign1Message()
            .ValidateCertificate(cert => cert
                .AllowUnprotectedHeaders()
                .NotExpired()
                .ValidateChain(allowUntrusted: true))
            .AllowAllTrust("test")
            .Build();

        var result = verifier.Validate(ctx.ValidMessage);

        Assert.That(result.Signature.IsValid, Is.True);
        Assert.That(result.Overall.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificate_WithCommonName_ValidatesMessage()
    {
        using var ctx = CreateTestContext();
        var verifier = Cose.Sign1Message()
            .ValidateCertificate(cert => cert
                .AllowUnprotectedHeaders()
                .HasCommonName("ExtensionTest")
                .ValidateChain(allowUntrusted: true))
            .AllowAllTrust("test")
            .Build();

        var result = verifier.Validate(ctx.ValidMessage);

        Assert.That(result.Signature.IsValid, Is.True);
        Assert.That(result.Overall.IsValid, Is.True);
    }

    [Test]
    public void ValidateCertificate_WithWrongCommonName_FailsValidation()
    {
        using var ctx = CreateTestContext();
        var verifier = Cose.Sign1Message()
            .ValidateCertificate(cert => cert
                .AllowUnprotectedHeaders()
                .HasCommonName("WrongName")
                .ValidateChain(allowUntrusted: true))
            .AllowAllTrust("test")
            .Build();

        var result = verifier.Validate(ctx.ValidMessage);

        Assert.That(result.Overall.IsValid, Is.False);
    }

    #endregion
}