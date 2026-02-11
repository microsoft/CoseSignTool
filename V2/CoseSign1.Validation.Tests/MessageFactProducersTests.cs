// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Facts;
using CoseSign1.Validation.Trust.Facts.Producers;
using CoseSign1.Validation.Trust.Ids;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Subjects;
using Microsoft.Extensions.Caching.Memory;

[TestFixture]
[Category("Validation")]
public sealed class MessageFactProducersTests
{
    [Test]
    public void CoreMessageFactsProducer_NullContext_ThrowsArgumentNullException()
    {
        var producer = new CoreMessageFactsProducer();
        Assert.That(() => producer.ProduceAsync(null!, typeof(DetachedPayloadPresentFact), CancellationToken.None), Throws.ArgumentNullException);
    }

    [Test]
    public void CoreMessageFactsProducer_NullFactType_ThrowsArgumentNullException()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x01 });
        var messageSubject = TrustSubject.Message(messageId);

        var context = new TrustFactContext(
            messageId,
            messageSubject,
            new TrustEvaluationOptions(),
            memoryCache: null,
            message: null);

        var producer = new CoreMessageFactsProducer();
        Assert.That(() => producer.ProduceAsync(context, null!, CancellationToken.None), Throws.ArgumentNullException);
    }

    [Test]
    public async Task CoreMessageFactsProducer_WhenMessageUnavailable_ReturnsMissingInputUnavailable()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x01 });
        var messageSubject = TrustSubject.Message(messageId);

        var context = new TrustFactContext(
            messageId,
            messageSubject,
            new TrustEvaluationOptions(),
            memoryCache: null,
            message: null);

        var producer = new CoreMessageFactsProducer();
        var factSet = await producer.ProduceAsync(context, typeof(DetachedPayloadPresentFact), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(factSet.IsMissing, Is.True);
            Assert.That(factSet.MissingReason, Is.Not.Null);
            Assert.That(factSet.MissingReason!.Code, Is.EqualTo(TrustFactMissingCodes.InputUnavailable));
        });
    }

    [Test]
    public async Task CoreMessageFactsProducer_WhenMessageUnavailable_AndFactTypeUnsupported_ReturnsMissing()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x01 });
        var messageSubject = TrustSubject.Message(messageId);

        var context = new TrustFactContext(
            messageId,
            messageSubject,
            new TrustEvaluationOptions(),
            memoryCache: null,
            message: null);

        var producer = new CoreMessageFactsProducer();
        var factSet = await producer.ProduceAsync(context, typeof(int), CancellationToken.None);

        Assert.That(factSet.IsMissing, Is.True);
        Assert.That(factSet.MissingReason, Is.Not.Null);
        Assert.That(factSet.MissingReason!.Code, Is.EqualTo(TrustFactMissingCodes.InputUnavailable));
    }

    [Test]
    public async Task CoreMessageFactsProducer_WhenSubjectNotMessage_ReturnsEmptyAvailableSet()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x02 });
        var signingKeySubject = TrustSubject.PrimarySigningKey(messageId);

        var context = new TrustFactContext(
            messageId,
            signingKeySubject,
            new TrustEvaluationOptions(),
            memoryCache: null,
            message: null);

        var producer = new CoreMessageFactsProducer();
        var factSet = (TrustFactSet<DetachedPayloadPresentFact>)await producer.ProduceAsync(context, typeof(DetachedPayloadPresentFact), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(factSet.IsMissing, Is.False);
            Assert.That(factSet.Values, Is.Empty);
        });
    }

    [Test]
    public async Task CoreMessageFactsProducer_WhenSubjectNotMessage_AndFactTypeUnsupported_ReturnsMissing()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x02 });
        var signingKeySubject = TrustSubject.PrimarySigningKey(messageId);

        var context = new TrustFactContext(
            messageId,
            signingKeySubject,
            new TrustEvaluationOptions(),
            memoryCache: null,
            message: null);

        var producer = new CoreMessageFactsProducer();
        var factSet = await producer.ProduceAsync(context, typeof(int), CancellationToken.None);

        Assert.That(factSet.IsMissing, Is.True);
        Assert.That(factSet.MissingReason, Is.Not.Null);
        Assert.That(factSet.MissingReason!.Code, Is.EqualTo(TrustFactMissingCodes.InputUnavailable));
    }

    [Test]
    public async Task CoreMessageFactsProducer_WhenEmbeddedPayload_ReturnsPresentFalse()
    {
        var message = CreateEmbeddedMessage(contentType: "application/cose");
        var messageId = TrustIds.CreateMessageId(message);
        var messageSubject = TrustSubject.Message(message);

        var context = new TrustFactContext(
            messageId,
            messageSubject,
            new TrustEvaluationOptions(),
            memoryCache: null,
            message: message);

        var producer = new CoreMessageFactsProducer();
        var factSet = (TrustFactSet<DetachedPayloadPresentFact>)await producer.ProduceAsync(context, typeof(DetachedPayloadPresentFact), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(factSet.IsMissing, Is.False);
            Assert.That(factSet.Values, Has.Count.EqualTo(1));
            Assert.That(factSet.Values[0].Present, Is.False);
        });
    }

    [Test]
    public async Task CoreMessageFactsProducer_WhenDetachedPayload_ReturnsPresentTrue()
    {
        var message = CreateDetachedMessage(contentType: "application/cose");
        var messageId = TrustIds.CreateMessageId(message);
        var messageSubject = TrustSubject.Message(message);

        var context = new TrustFactContext(
            messageId,
            messageSubject,
            new TrustEvaluationOptions(),
            memoryCache: null,
            message: message);

        var producer = new CoreMessageFactsProducer();
        var factSet = (TrustFactSet<DetachedPayloadPresentFact>)await producer.ProduceAsync(context, typeof(DetachedPayloadPresentFact), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(factSet.IsMissing, Is.False);
            Assert.That(factSet.Values, Has.Count.EqualTo(1));
            Assert.That(factSet.Values[0].Present, Is.True);
        });
    }

    [Test]
    public async Task CoreMessageFactsProducer_DetachedPayload_UsesCrossEvaluationCache()
    {
        var message = CreateDetachedMessage(contentType: "application/cose");
        var messageId = TrustIds.CreateMessageId(message);
        var messageSubject = TrustSubject.Message(message);

        using var cache = new MemoryCache(new MemoryCacheOptions());
        var options = new TrustEvaluationOptions();

        var context1 = new TrustFactContext(
            messageId,
            messageSubject,
            options,
            memoryCache: cache,
            message: message);

        var context2 = new TrustFactContext(
            messageId,
            messageSubject,
            options,
            memoryCache: cache,
            message: message);

        var producer = new CoreMessageFactsProducer();

        var first = (TrustFactSet<DetachedPayloadPresentFact>)await producer.ProduceAsync(context1, typeof(DetachedPayloadPresentFact), CancellationToken.None);
        var second = (TrustFactSet<DetachedPayloadPresentFact>)await producer.ProduceAsync(context2, typeof(DetachedPayloadPresentFact), CancellationToken.None);

        Assert.That(ReferenceEquals(first, second), Is.True);
    }

    [Test]
    public async Task CoreMessageFactsProducer_WhenFactTypeUnsupported_ReturnsMissing()
    {
        var message = CreateEmbeddedMessage(contentType: "application/cose");
        var messageId = TrustIds.CreateMessageId(message);
        var messageSubject = TrustSubject.Message(message);

        var context = new TrustFactContext(
            messageId,
            messageSubject,
            new TrustEvaluationOptions(),
            memoryCache: null,
            message: message);

        var producer = new CoreMessageFactsProducer();
        var factSet = await producer.ProduceAsync(context, typeof(int), CancellationToken.None);

        Assert.That(factSet.IsMissing, Is.True);
        Assert.That(factSet.MissingReason, Is.Not.Null);
        Assert.That(factSet.MissingReason!.Code, Is.EqualTo(TrustFactMissingCodes.InputUnavailable));
    }

    [Test]
    public void CoreMessageFactsProducer_ContentType_NullContext_ThrowsArgumentNullException()
    {
        var producer = new CoreMessageFactsProducer();
        Assert.That(() => producer.ProduceAsync(null!, typeof(ContentTypeFact), CancellationToken.None), Throws.ArgumentNullException);
    }

    [Test]
    public async Task CoreMessageFactsProducer_ContentType_WhenMessageUnavailable_ReturnsMissingInputUnavailable()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x03 });
        var messageSubject = TrustSubject.Message(messageId);

        var context = new TrustFactContext(
            messageId,
            messageSubject,
            new TrustEvaluationOptions(),
            memoryCache: null,
            message: null);

        var producer = new CoreMessageFactsProducer();
        var factSet = await producer.ProduceAsync(context, typeof(ContentTypeFact), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(factSet.IsMissing, Is.True);
            Assert.That(factSet.MissingReason, Is.Not.Null);
            Assert.That(factSet.MissingReason!.Code, Is.EqualTo(TrustFactMissingCodes.InputUnavailable));
        });
    }

    [Test]
    public async Task CoreMessageFactsProducer_ContentType_WhenContentTypeHeaderMissing_ReturnsEmptyAvailableSet()
    {
        var message = CreateEmbeddedMessage(contentType: null);
        var messageId = TrustIds.CreateMessageId(message);
        var messageSubject = TrustSubject.Message(message);

        var context = new TrustFactContext(
            messageId,
            messageSubject,
            new TrustEvaluationOptions(),
            memoryCache: null,
            message: message);

        var producer = new CoreMessageFactsProducer();
        var factSet = (TrustFactSet<ContentTypeFact>)await producer.ProduceAsync(context, typeof(ContentTypeFact), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(factSet.IsMissing, Is.False);
            Assert.That(factSet.Values, Is.Empty);
        });
    }

    [Test]
    public async Task CoreMessageFactsProducer_ContentType_WhenContentTypeHeaderPresent_ReturnsFact()
    {
        var message = CreateEmbeddedMessage(contentType: "application/json");
        var messageId = TrustIds.CreateMessageId(message);
        var messageSubject = TrustSubject.Message(message);

        var context = new TrustFactContext(
            messageId,
            messageSubject,
            new TrustEvaluationOptions(),
            memoryCache: null,
            message: message);

        var producer = new CoreMessageFactsProducer();
        var factSet = (TrustFactSet<ContentTypeFact>)await producer.ProduceAsync(context, typeof(ContentTypeFact), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(factSet.IsMissing, Is.False);
            Assert.That(factSet.Values, Has.Count.EqualTo(1));
            Assert.That(factSet.Values[0].ContentType, Is.EqualTo("application/json"));
        });
    }

    [Test]
    public async Task CoreMessageFactsProducer_ContentType_UsesCrossEvaluationCache()
    {
        var message = CreateEmbeddedMessage(contentType: "application/json");
        var messageId = TrustIds.CreateMessageId(message);
        var messageSubject = TrustSubject.Message(message);

        using var cache = new MemoryCache(new MemoryCacheOptions());
        var options = new TrustEvaluationOptions();

        var context1 = new TrustFactContext(
            messageId,
            messageSubject,
            options,
            memoryCache: cache,
            message: message);

        var context2 = new TrustFactContext(
            messageId,
            messageSubject,
            options,
            memoryCache: cache,
            message: message);

        var producer = new CoreMessageFactsProducer();

        var first = (TrustFactSet<ContentTypeFact>)await producer.ProduceAsync(context1, typeof(ContentTypeFact), CancellationToken.None);
        var second = (TrustFactSet<ContentTypeFact>)await producer.ProduceAsync(context2, typeof(ContentTypeFact), CancellationToken.None);

        Assert.That(ReferenceEquals(first, second), Is.True);
    }

    [Test]
    public async Task CoreMessageFactsProducer_ContentType_WhenIndirectCoseHashVHeaderPresent_StripsExtension()
    {
        var message = CreateEmbeddedMessage(contentType: "application/json+cose-hash-v");
        var messageId = TrustIds.CreateMessageId(message);
        var messageSubject = TrustSubject.Message(message);

        var context = new TrustFactContext(
            messageId,
            messageSubject,
            new TrustEvaluationOptions(),
            memoryCache: null,
            message: message);

        var producer = new CoreMessageFactsProducer();
        var factSet = (TrustFactSet<ContentTypeFact>)await producer.ProduceAsync(context, typeof(ContentTypeFact), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(factSet.IsMissing, Is.False);
            Assert.That(factSet.Values, Has.Count.EqualTo(1));
            Assert.That(factSet.Values[0].ContentType, Is.EqualTo("application/json"));
        });
    }

    private static CoseSign1Message CreateEmbeddedMessage(string? contentType)
    {
        using var key = ECDsa.Create();

        var protectedHeaders = new CoseHeaderMap();
        if (contentType != null)
        {
            protectedHeaders.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString(contentType));
        }

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders);
        byte[] signedBytes = CoseSign1Message.SignEmbedded("payload"u8.ToArray(), signer);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    private static CoseSign1Message CreateDetachedMessage(string? contentType)
    {
        using var key = ECDsa.Create();

        var protectedHeaders = new CoseHeaderMap();
        if (contentType != null)
        {
            protectedHeaders.Add(CoseHeaderLabel.ContentType, CoseHeaderValue.FromString(contentType));
        }

        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders);
        byte[] signedBytes = CoseSign1Message.SignDetached("payload"u8.ToArray(), signer);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    [Test]
    public async Task CoreMessageFactsProducer_WhenMessageUnavailable_CounterSignatureSubjectFact_ReturnsMissing()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x01 });
        var messageSubject = TrustSubject.Message(messageId);

        var context = new TrustFactContext(
            messageId,
            messageSubject,
            new TrustEvaluationOptions(),
            memoryCache: null,
            message: null);

        var producer = new CoreMessageFactsProducer();
        var factSet = await producer.ProduceAsync(context, typeof(CounterSignatureSubjectFact), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(factSet.IsMissing, Is.True);
            Assert.That(factSet.MissingReason, Is.Not.Null);
            Assert.That(factSet.MissingReason!.Code, Is.EqualTo(TrustFactMissingCodes.InputUnavailable));
        });
    }

    [Test]
    public async Task CoreMessageFactsProducer_WhenMessageUnavailable_UnknownCounterSignatureBytesFact_ReturnsMissing()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes(new byte[] { 0x01 });
        var messageSubject = TrustSubject.Message(messageId);

        var context = new TrustFactContext(
            messageId,
            messageSubject,
            new TrustEvaluationOptions(),
            memoryCache: null,
            message: null);

        var producer = new CoreMessageFactsProducer();
        var factSet = await producer.ProduceAsync(context, typeof(UnknownCounterSignatureBytesFact), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(factSet.IsMissing, Is.True);
            Assert.That(factSet.MissingReason, Is.Not.Null);
            Assert.That(factSet.MissingReason!.Code, Is.EqualTo(TrustFactMissingCodes.InputUnavailable));
        });
    }
}
