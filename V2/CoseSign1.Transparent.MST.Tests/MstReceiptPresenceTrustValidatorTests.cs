// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Tests.Common;
using CoseSign1.Transparent.MST.Validation;
using CoseSign1.Validation;

namespace CoseSign1.Transparent.MST.Tests;

[TestFixture]
public class MstReceiptPresenceTrustValidatorTests
{
    private X509Certificate2 TestCert = null!;

    [SetUp]
    public void Setup()
    {
        TestCert = TestCertificateUtils.CreateCertificate("MstPresenceTrustValidatorTest", useEcc: true);
    }

    [TearDown]
    public void TearDown()
    {
        TestCert?.Dispose();
    }

    [Test]
    public void Validate_WithWrongStage_ReturnsNotApplicable()
    {
        var validator = new MstReceiptPresenceTrustValidator();
        var message = CreateSignedMessageWithoutReceipt(TestCert);

        var result = validator.Validate(message, ValidationStage.Signature);
        Assert.That(result.IsNotApplicable, Is.True);
    }

    [Test]
    public void Validate_WithNullInput_ReturnsFailure()
    {
        var validator = new MstReceiptPresenceTrustValidator();

        var result = validator.Validate(null!, ValidationStage.KeyMaterialTrust);
        Assert.That(result.IsFailure, Is.True);
        Assert.That(result.Failures, Is.Not.Empty);
    }

    [Test]
    public void Validate_WithoutReceipt_EmitsReceiptPresentFalseAndReceiptTrustedFalse()
    {
        var validator = new MstReceiptPresenceTrustValidator();
        var message = CreateSignedMessageWithoutReceipt(TestCert);

        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);
        Assert.That(result.IsSuccess, Is.True);

        var assertions = TrustAssertionMetadata.GetAssertionsOrEmpty(result);
        Assert.That(assertions, Has.Count.EqualTo(2));

        Assert.That(assertions.Any(a => a.ClaimId == MstTrustClaims.ReceiptPresent && a.Satisfied == false), Is.True);
        Assert.That(assertions.Any(a => a.ClaimId == MstTrustClaims.ReceiptTrusted && a.Satisfied == false), Is.True);
    }

    [Test]
    public void Validate_WithReceipt_EmitsReceiptPresentTrueAndReceiptTrustedFalseNotVerified()
    {
        var validator = new MstReceiptPresenceTrustValidator();
        var message = CreateSignedMessageWithReceipt(TestCert);

        var result = validator.Validate(message, ValidationStage.KeyMaterialTrust);
        Assert.That(result.IsSuccess, Is.True);

        var assertions = TrustAssertionMetadata.GetAssertionsOrEmpty(result);
        Assert.That(assertions, Has.Count.EqualTo(2));

        var present = assertions.Single(a => a.ClaimId == MstTrustClaims.ReceiptPresent);
        Assert.That(present.Satisfied, Is.True);

        var trusted = assertions.Single(a => a.ClaimId == MstTrustClaims.ReceiptTrusted);
        Assert.That(trusted.Satisfied, Is.False);
        Assert.That(trusted.Details, Is.EqualTo("NotVerified"));
    }

    private static CoseSign1Message CreateSignedMessageWithoutReceipt(X509Certificate2 cert)
    {
        using var key = cert.GetECDsaPrivateKey()!;
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        var payloadBytes = System.Text.Encoding.UTF8.GetBytes("payload");
        var signedBytes = CoseSign1Message.SignEmbedded(payloadBytes, signer);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    private static CoseSign1Message CreateSignedMessageWithReceipt(X509Certificate2 cert)
    {
        var receiptBytes = CreateMinimalReceiptBytes();

        var arrayWriter = new CborWriter();
        arrayWriter.WriteStartArray(1);
        arrayWriter.WriteByteString(receiptBytes);
        arrayWriter.WriteEndArray();
        var receiptsArrayBytes = arrayWriter.Encode();

        var message = CreateSignedMessageWithoutReceipt(cert);
        message.UnprotectedHeaders.Add(new CoseHeaderLabel(394), CoseHeaderValue.FromEncodedValue(receiptsArrayBytes));
        return message;
    }

    private static byte[] CreateMinimalReceiptBytes()
    {
        var receiptWriter = new CborWriter();
        receiptWriter.WriteStartArray(4);
        receiptWriter.WriteByteString(new byte[] { 0xA0 });
        receiptWriter.WriteStartMap(0);
        receiptWriter.WriteEndMap();
        receiptWriter.WriteNull();
        receiptWriter.WriteByteString(new byte[64]);
        receiptWriter.WriteEndArray();
        return receiptWriter.Encode();
    }
}
