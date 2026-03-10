// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests.Trust;

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Transparent.MST;
using CoseSign1.Transparent.MST.Extensions;
using CoseSign1.Transparent.MST.Trust;
using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Subjects;

[TestFixture]
public sealed class MstTrustPackTests
{
    [Test]
    public async Task ProduceAsync_WhenSubjectIsNotCounterSignature_ReturnsAvailableEmptySet()
    {
        var options = new MstTrustOptions { VerifyReceipts = true };
        var pack = new MstTrustPack(options, new NoopVerifier());

        var message = CreateMessageWithSingleEmptyReceipt();
        var messageSubject = TrustSubject.Message(message);
        var context = new TrustFactContext(messageSubject.Id, messageSubject, new TrustEvaluationOptions(), memoryCache: null, message);

        var result = await pack.ProduceAsync(context, typeof(MstReceiptTrustedFact), CancellationToken.None);

        Assert.That(result.IsMissing, Is.False);
        Assert.That(result.Count, Is.EqualTo(0));
    }

    [Test]
    public async Task ProduceAsync_WhenMessageIsNull_ReturnsMissingForCounterSignatureSubject()
    {
        var options = new MstTrustOptions { VerifyReceipts = true };
        var pack = new MstTrustPack(options, new NoopVerifier());

        var messageId = TrustSubjectId.FromSha256OfBytes([1, 2, 3]);
        var subject = TrustSubject.CounterSignature(messageId, [4, 5, 6]);
        var context = new TrustFactContext(messageId, subject, new TrustEvaluationOptions(), memoryCache: null, message: null);

        var result = await pack.ProduceAsync(context, typeof(MstReceiptTrustedFact), CancellationToken.None);

        Assert.That(result.IsMissing, Is.True);
        Assert.That(result.MissingReason, Is.Not.Null);
    }

    [Test]
    public async Task ProduceAsync_WhenMessageIsNull_ReturnsMissingForPresentFact()
    {
        var options = new MstTrustOptions { VerifyReceipts = true };
        var pack = new MstTrustPack(options, new NoopVerifier());

        var messageId = TrustSubjectId.FromSha256OfBytes([1, 2, 3]);
        var subject = TrustSubject.CounterSignature(messageId, [4, 5, 6]);
        var context = new TrustFactContext(messageId, subject, new TrustEvaluationOptions(), memoryCache: null, message: null);

        var result = await pack.ProduceAsync(context, typeof(MstReceiptPresentFact), CancellationToken.None);

        Assert.That(result.IsMissing, Is.True);
        Assert.That(result.MissingReason, Is.Not.Null);
    }

    [Test]
    public async Task ProduceAsync_WhenVerifyReceiptsDisabled_ReturnsAvailableEmptySet()
    {
        var options = new MstTrustOptions { VerifyReceipts = false };
        var pack = new MstTrustPack(options, new NoopVerifier());

        var message = CreateMessageWithSingleEmptyReceipt();
        var messageSubject = TrustSubject.Message(message);
        var receiptBytes = message.GetMstReceiptBytes().Single();
        var receiptSubject = TrustSubject.CounterSignature(messageSubject.Id, receiptBytes);
        var context = new TrustFactContext(messageSubject.Id, receiptSubject, new TrustEvaluationOptions(), memoryCache: null, message);

        var result = await pack.ProduceAsync(context, typeof(MstReceiptTrustedFact), CancellationToken.None);

        Assert.That(result.IsMissing, Is.False);
        Assert.That(result.Count, Is.EqualTo(0));
    }

    [Test]
    public async Task ProduceAsync_WhenOfflineOnlyAndNoOfflineKeys_ReturnsMissingOfflineKeys()
    {
        var options = new MstTrustOptions
        {
            VerifyReceipts = true,
            OfflineOnly = true,
            HasOfflineKeys = false,
        };
        var pack = new MstTrustPack(options, new NoopVerifier());

        var message = CreateMessageWithSingleEmptyReceipt();
        var messageSubject = TrustSubject.Message(message);
        var receiptBytes = message.GetMstReceiptBytes().Single();
        var receiptSubject = TrustSubject.CounterSignature(messageSubject.Id, receiptBytes);
        var context = new TrustFactContext(messageSubject.Id, receiptSubject, new TrustEvaluationOptions(), memoryCache: null, message);

        var result = await pack.ProduceAsync(context, typeof(MstReceiptTrustedFact), CancellationToken.None);

        Assert.That(result.IsMissing, Is.True);
        Assert.That(result.MissingReason, Is.Not.Null);
        Assert.That(result.MissingReason!.Code, Is.EqualTo("MissingOfflineKeys"));
    }

    [Test]
    public async Task ProduceAsync_WhenCounterSignatureIsNotReceipt_ReturnsNotMstReceipt()
    {
        var options = new MstTrustOptions { VerifyReceipts = true };
        var pack = new MstTrustPack(options, new NoopVerifier());

        var message = CreateMessageWithSingleEmptyReceipt();
        var messageSubject = TrustSubject.Message(message);

        // Not equal to the one empty receipt bytes entry.
        var notReceiptSubject = TrustSubject.CounterSignature(messageSubject.Id, [1]);
        var context = new TrustFactContext(messageSubject.Id, notReceiptSubject, new TrustEvaluationOptions(), memoryCache: null, message);

        var result = await pack.ProduceAsync(context, typeof(MstReceiptTrustedFact), CancellationToken.None);

        var typed = (ITrustFactSet<MstReceiptTrustedFact>)result;
        Assert.That(result.IsMissing, Is.False);
        Assert.That(typed.Values, Has.Count.EqualTo(1));
        Assert.That(typed.Values[0].IsTrusted, Is.False);
        Assert.That(typed.Values[0].Details, Is.EqualTo("NotMstReceipt"));
    }

    [Test]
    public void ProduceAsync_WhenFactTypeIsUnsupported_ThrowsNotSupportedException()
    {
        var options = new MstTrustOptions { VerifyReceipts = true };
        var pack = new MstTrustPack(options, new NoopVerifier());

        var message = CreateMessageWithSingleEmptyReceipt();
        var messageSubject = TrustSubject.Message(message);
        var context = new TrustFactContext(messageSubject.Id, messageSubject, new TrustEvaluationOptions(), memoryCache: null, message);

        Assert.ThrowsAsync<NotSupportedException>(async () =>
            await pack.ProduceAsync(context, typeof(string), CancellationToken.None));
    }

    [Test]
    public async Task ProduceAsync_WhenReceiptSubjectAndVerificationSucceeds_ReturnsTrustedFact()
    {
        var options = new MstTrustOptions { VerifyReceipts = true, OfflineOnly = false };
        var pack = new MstTrustPack(options, new NoopVerifier());

        var message = CreateMessageWithSingleEmptyReceipt();
        var messageSubject = TrustSubject.Message(message);
        var receiptBytes = message.GetMstReceiptBytes().Single();
        var receiptSubject = TrustSubject.CounterSignature(messageSubject.Id, receiptBytes);
        var context = new TrustFactContext(messageSubject.Id, receiptSubject, new TrustEvaluationOptions(), memoryCache: null, message);

        var result = await pack.ProduceAsync(context, typeof(MstReceiptTrustedFact), CancellationToken.None);

        Assert.That(result.IsMissing, Is.False);

        var typed = (ITrustFactSet<MstReceiptTrustedFact>)result;
        Assert.That(typed.Values, Has.Count.EqualTo(1));
        Assert.That(typed.Values[0].IsTrusted, Is.True);
    }

    [Test]
    public async Task ProduceAsync_WhenReceiptSubjectAndVerificationThrows_ReturnsUntrustedFactWithDetails()
    {
        var options = new MstTrustOptions { VerifyReceipts = true, OfflineOnly = false };
        var pack = new MstTrustPack(options, new ThrowingVerifier());

        var message = CreateMessageWithSingleEmptyReceipt();
        var messageSubject = TrustSubject.Message(message);
        var receiptBytes = message.GetMstReceiptBytes().Single();
        var receiptSubject = TrustSubject.CounterSignature(messageSubject.Id, receiptBytes);
        var context = new TrustFactContext(messageSubject.Id, receiptSubject, new TrustEvaluationOptions(), memoryCache: null, message);

        var result = await pack.ProduceAsync(context, typeof(MstReceiptTrustedFact), CancellationToken.None);

        Assert.That(result.IsMissing, Is.False);

        var typed = (ITrustFactSet<MstReceiptTrustedFact>)result;
        Assert.That(typed.Values, Has.Count.EqualTo(1));
        Assert.That(typed.Values[0].IsTrusted, Is.False);
        Assert.That(typed.Values[0].Details, Does.Contain(nameof(InvalidOperationException)));
    }

    private static CoseSign1Message CreateMessageWithSingleEmptyReceipt()
    {
        using var key = ECDsa.Create();
        var payload = "payload"u8.ToArray();

        var protectedHeaders = new CoseHeaderMap();
        var unprotectedHeaders = new CoseHeaderMap();

        unprotectedHeaders[new CoseHeaderLabel(394)] = CborValue(writer =>
        {
            writer.WriteStartArray(1);
            writer.WriteByteString(Array.Empty<byte>());
            writer.WriteEndArray();
        });

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        var encoded = CoseSign1Message.SignEmbedded(payload, signer);
        return CoseSign1Message.DecodeSign1(encoded);
    }

    private static CoseHeaderValue CborValue(Action<CborWriter> write)
    {
        var writer = new CborWriter();
        write(writer);
        return CoseHeaderValue.FromEncodedValue(writer.Encode());
    }

    private sealed class NoopVerifier : ICodeTransparencyVerifier
    {
        public void VerifyTransparentStatement(
            byte[] transparentStatementBytes,
            Azure.Security.CodeTransparency.CodeTransparencyVerificationOptions? verificationOptions = null,
            Azure.Security.CodeTransparency.CodeTransparencyClientOptions? clientOptions = null)
        {
        }
    }

    private sealed class ThrowingVerifier : ICodeTransparencyVerifier
    {
        public void VerifyTransparentStatement(
            byte[] transparentStatementBytes,
            Azure.Security.CodeTransparency.CodeTransparencyVerificationOptions? verificationOptions = null,
            Azure.Security.CodeTransparency.CodeTransparencyClientOptions? clientOptions = null)
        {
            throw new InvalidOperationException("boom");
        }
    }
}
