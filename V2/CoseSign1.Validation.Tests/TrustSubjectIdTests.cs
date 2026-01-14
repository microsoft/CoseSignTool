// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;

[TestFixture]
[Category("Validation")]
public class TrustSubjectIdTests
{
    [Test]
    public void FromSha256OfBytes_MatchesSha256HashData()
    {
        byte[] input = "hello world"u8.ToArray();

        var expectedHash = SHA256.HashData(input);
        var expectedHex = Convert.ToHexString(expectedHash).ToLowerInvariant();

        var id = TrustSubjectId.FromSha256OfBytes(input);

        Assert.Multiple(() =>
        {
            Assert.That(id.Bytes.ToArray(), Is.EqualTo(expectedHash));
            Assert.That(id.Hex, Is.EqualTo(expectedHex));
            Assert.That(id.ToString(), Is.EqualTo(expectedHex));
        });
    }

    [Test]
    public void DefaultValue_IsUninitialized_ThrowsOnBytes()
    {
        TrustSubjectId id = default;

        Assert.That(() => _ = id.Bytes, Throws.InvalidOperationException);
    }

    [Test]
    public void DefaultValue_IsUninitialized_ThrowsOnHex()
    {
        TrustSubjectId id = default;

        Assert.That(() => _ = id.Hex, Throws.InvalidOperationException);
    }

    [Test]
    public void DefaultValue_EqualsDefaultValue()
    {
        TrustSubjectId left = default;
        TrustSubjectId right = default;

        Assert.Multiple(() =>
        {
            Assert.That(left.Equals(right), Is.True);
            Assert.That(left == right, Is.True);
            Assert.That(left != right, Is.False);
            Assert.That(left.GetHashCode(), Is.EqualTo(0));
        });
    }

    [Test]
    public void DefaultValue_NotEqualToNonDefaultValue()
    {
        TrustSubjectId left = default;
        var right = TrustSubjectId.FromSha256OfBytes("x"u8);

        Assert.Multiple(() =>
        {
            Assert.That(left.Equals(right), Is.False);
            Assert.That(left == right, Is.False);
            Assert.That(left != right, Is.True);
        });
    }

    [Test]
    public void Equals_Object_UsesStructuralEquality()
    {
        var id1 = TrustSubjectId.FromSha256OfBytes("x"u8);
        var id2 = TrustSubjectId.FromSha256OfBytes("x"u8);
        var id3 = TrustSubjectId.FromSha256OfBytes("y"u8);

        Assert.Multiple(() =>
        {
            Assert.That(id1.Equals((object)id2), Is.True);
            Assert.That(id1.Equals((object)id3), Is.False);
            Assert.That(id1.Equals(new object()), Is.False);
            Assert.That(id1.GetHashCode(), Is.Not.EqualTo(0));
        });
    }

    [Test]
    public void TrustIds_CreateMessageId_NullMessage_Throws()
    {
        Assert.That(() => TrustIds.CreateMessageId((CoseSign1Message)null!), Throws.ArgumentNullException);
    }

    [Test]
    public void TrustFactMissing_NullInputs_Throw()
    {
        Assert.Multiple(() =>
        {
            Assert.That(() => _ = new TrustFactMissing(null!, "m"), Throws.ArgumentNullException);
            Assert.That(() => _ = new TrustFactMissing("c", null!), Throws.ArgumentNullException);
        });
    }

    [Test]
    public void CreateMessageId_FromMessage_MatchesCreateMessageId_FromBytes()
    {
        using var key = ECDsa.Create();
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);

        byte[] payload = "payload"u8.ToArray();
        byte[] signedBytes = CoseSign1Message.SignEmbedded(payload, signer);

        var message = CoseMessage.DecodeSign1(signedBytes);

        var fromMessage = TrustIds.CreateMessageId(message);
        var fromBytes = TrustIds.CreateMessageId(signedBytes);

        Assert.Multiple(() =>
        {
            Assert.That(fromMessage, Is.EqualTo(fromBytes));
            Assert.That(fromMessage == fromBytes, Is.True);
            Assert.That(fromMessage != fromBytes, Is.False);
        });
    }

    [Test]
    public void TrustSubject_Message_UsesMessageId()
    {
        using var key = ECDsa.Create();
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);

        byte[] payload = "payload"u8.ToArray();
        byte[] signedBytes = CoseSign1Message.SignEmbedded(payload, signer);
        var message = CoseMessage.DecodeSign1(signedBytes);

        var subject = TrustSubject.Message(message);
        var expectedId = TrustIds.CreateMessageId(message);

        Assert.Multiple(() =>
        {
            Assert.That(subject.Kind, Is.EqualTo(TrustSubjectKind.Message));
            Assert.That(subject.ParentId, Is.Null);
            Assert.That(subject.Id, Is.EqualTo(expectedId));
        });
    }

    [Test]
    public void TrustSubject_CounterSignature_UsesParentIdAndStableId()
    {
        var messageId = TrustSubjectId.FromSha256OfBytes("message"u8);
        byte[] counterSignatureBytes = "countersig"u8.ToArray();

        var subject = TrustSubject.CounterSignature(messageId, counterSignatureBytes);
        var expectedId = TrustIds.CreateCounterSignatureId(counterSignatureBytes);

        Assert.Multiple(() =>
        {
            Assert.That(subject.Kind, Is.EqualTo(TrustSubjectKind.CounterSignature));
            Assert.That(subject.ParentId, Is.EqualTo(messageId));
            Assert.That(subject.Id, Is.EqualTo(expectedId));
        });
    }
}
