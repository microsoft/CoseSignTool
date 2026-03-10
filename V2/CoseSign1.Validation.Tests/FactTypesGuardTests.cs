// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using CoseSign1.Validation.Trust.Facts;
using CoseSign1.Validation.Trust.Subjects;

[TestFixture]
[Category("Validation")]
public sealed class FactTypesGuardTests
{
    [Test]
    public void ContentTypeFact_NullContentType_ThrowsArgumentNullException()
    {
        Assert.That(() => _ = new ContentTypeFact(null!), Throws.ArgumentNullException);
    }

    [Test]
    public void CounterSignatureSubjectFact_NullSubject_ThrowsArgumentNullException()
    {
        Assert.That(() => _ = new CounterSignatureSubjectFact(null!, isProtectedHeader: false), Throws.ArgumentNullException);
    }

    [Test]
    public void UnknownCounterSignatureBytesFact_NullBytes_ThrowsArgumentNullException()
    {
        var counterSignatureId = TrustSubjectId.FromSha256OfBytes("cs"u8);
        Assert.That(() => _ = new UnknownCounterSignatureBytesFact(counterSignatureId, null!), Throws.ArgumentNullException);
    }

    [Test]
    public void DetachedPayloadPresentFact_RoundTripsValue()
    {
        var fact = new DetachedPayloadPresentFact(present: true);

        Assert.Multiple(() =>
        {
            Assert.That(fact.Scope, Is.EqualTo(TrustFactScope.Message));
            Assert.That(fact.Present, Is.True);
        });
    }

    [Test]
    public void ContentTypeFact_RoundTripsValue()
    {
        var fact = new ContentTypeFact("application/test");

        Assert.Multiple(() =>
        {
            Assert.That(fact.Scope, Is.EqualTo(TrustFactScope.Message));
            Assert.That(fact.ContentType, Is.EqualTo("application/test"));
        });
    }

    [Test]
    public void CounterSignatureSubjectFact_RoundTripsValue()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes("m"u8);
        var counterSignature = TrustSubject.CounterSignature(messageId, "cs"u8);

        var fact = new CounterSignatureSubjectFact(counterSignature, isProtectedHeader: true);

        Assert.Multiple(() =>
        {
            Assert.That(fact.Scope, Is.EqualTo(TrustFactScope.Message));
            Assert.That(fact.Subject.Id, Is.EqualTo(counterSignature.Id));
            Assert.That(fact.IsProtectedHeader, Is.True);
        });
    }

    [Test]
    public void UnknownCounterSignatureBytesFact_RoundTripsValue()
    {
        var counterSignatureId = TrustSubjectId.FromSha256OfBytes("cs"u8);
        byte[] bytes = [1, 2, 3];

        var fact = new UnknownCounterSignatureBytesFact(counterSignatureId, bytes);

        Assert.Multiple(() =>
        {
            Assert.That(fact.Scope, Is.EqualTo(TrustFactScope.CounterSignature));
            Assert.That(fact.CounterSignatureId, Is.EqualTo(counterSignatureId));
            Assert.That(fact.RawCounterSignatureBytes, Is.EqualTo(bytes));
        });
    }
}
