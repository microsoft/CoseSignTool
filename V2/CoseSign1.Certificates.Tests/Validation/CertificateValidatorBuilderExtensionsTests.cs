// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Validation;
using CoseSign1.Direct;
using CoseSign1.Validation;

[TestFixture]
[System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
public class CertificateValidatorBuilderExtensionsTests
{
    /// <summary>
    /// Holds the test state for each test method.
    /// </summary>
    private sealed record TestContext(
        System.Security.Cryptography.X509Certificates.X509Certificate2 TestCert,
        CoseSign1Message ValidMessage) : IDisposable
    {
        public void Dispose() => TestCert?.Dispose();
    }

    /// <summary>
    /// Creates a fresh test context with isolated state.
    /// </summary>
    private static TestContext CreateTestContext()
    {
        // Create a self-signed cert with subject CN = "ExtensionTest".
        var testCert = TestCertificateUtils.CreateCertificate("ExtensionTest");

        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(testCert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        var validMessage = CoseSign1Message.DecodeSign1(messageBytes);

        return new TestContext(testCert, validMessage);
    }

    [Test]
    public void ValidateCertificate_AddsValidatorsAndValidatesMessage()
    {
        using var ctx = CreateTestContext();
        var verifier = Cose.Sign1Message()
            .AddValidator(
                new CertificateValidationBuilder()
                    .AllowUnprotectedHeaders(true)
                    .NotExpired()
                    .HasCommonName("ExtensionTest")
                    .Build())
            .Build();

        var result = verifier.Validate(ctx.ValidMessage);

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
