// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using Azure.Security.CodeTransparency;
using CoseSign1.Tests.Common;
using CoseSign1.Transparent.MST.Validation;
using CoseSign1.Validation;

namespace CoseSign1.Transparent.MST.Tests;

[TestFixture]
public class MstReceiptOnlineValidatorTests
{
    private X509Certificate2 TestCert = null!;

    [SetUp]
    public void Setup()
    {
        TestCert = TestCertificateUtils.CreateCertificate("MstReceiptOnlineValidatorTests", useEcc: true);
    }

    [TearDown]
    public void TearDown()
    {
        TestCert?.Dispose();
    }

    [Test]
    public void IsApplicable_WithNullInput_ReturnsFalse()
    {
        var validator = new MstReceiptOnlineValidator(new CodeTransparencyClient(new Uri("https://example.test")), "example.test");
        Assert.That(validator.IsApplicable(null!, ValidationStage.KeyMaterialTrust), Is.False);
    }

    [Test]
    public void IsApplicable_WithWrongStage_ReturnsFalse()
    {
        var validator = new MstReceiptOnlineValidator(new CodeTransparencyClient(new Uri("https://example.test")), "example.test");
        var message = CreateSignedMessage(TestCert);
        Assert.That(validator.IsApplicable(message, ValidationStage.Signature), Is.False);
    }

    [Test]
    public void Validate_WithWrongStage_ReturnsNotApplicable()
    {
        var validator = new MstReceiptOnlineValidator(new CodeTransparencyClient(new Uri("https://example.test")), "example.test");
        var message = CreateSignedMessage(TestCert);

        var result = validator.Validate(message, ValidationStage.Signature);
        Assert.That(result.IsNotApplicable, Is.True);
    }

    [Test]
    public void ValidateAsync_WithNullInput_ReturnsFailure()
    {
        var validator = new MstReceiptOnlineValidator(new CodeTransparencyClient(new Uri("https://example.test")), "example.test");

        var result = validator.ValidateAsync(null!, ValidationStage.KeyMaterialTrust).GetAwaiter().GetResult();
        Assert.That(result.IsFailure, Is.True);
    }

    private static CoseSign1Message CreateSignedMessage(X509Certificate2 cert)
    {
        using var key = cert.GetECDsaPrivateKey()!;
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        var payloadBytes = System.Text.Encoding.UTF8.GetBytes("payload");
        var signedBytes = CoseSign1Message.SignEmbedded(payloadBytes, signer);
        return CoseMessage.DecodeSign1(signedBytes);
    }
}
