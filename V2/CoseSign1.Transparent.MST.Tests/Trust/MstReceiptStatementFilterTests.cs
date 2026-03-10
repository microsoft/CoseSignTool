// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests.Trust;

using System.Formats.Cbor;
using CoseSign1.Transparent.MST.Trust;

[TestFixture]
public sealed class MstReceiptStatementFilterTests
{
    [Test]
    public void CreateStatementWithOnlyReceipt_WhenArrayLengthIsNotFour_ThrowsCborContentException()
    {
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartArray(3);
        writer.WriteByteString(Array.Empty<byte>());
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteNull();
        writer.WriteEndArray();

        var bytes = writer.Encode();

        Assert.Throws<CborContentException>(() =>
            MstReceiptStatementFilter.CreateStatementWithOnlyReceipt(bytes, receiptBytes: Array.Empty<byte>()));
    }

    [Test]
    public void CreateStatementWithOnlyReceipt_WhenUnprotectedHeaderKeyTypeIsUnsupported_ThrowsCborContentException()
    {
        // COSE_Sign1 = [ protected, unprotected, payload, signature ]
        // Use a bytestring key in the unprotected map, which the filter intentionally rejects.
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartArray(4);
        writer.WriteByteString(Array.Empty<byte>());
        writer.WriteStartMap(1);
        writer.WriteByteString([1]);
        writer.WriteInt32(123);
        writer.WriteEndMap();
        writer.WriteByteString([0xAA]);
        writer.WriteByteString([0xBB]);
        writer.WriteEndArray();

        var bytes = writer.Encode();

        Assert.Throws<CborContentException>(() =>
            MstReceiptStatementFilter.CreateStatementWithOnlyReceipt(bytes, receiptBytes: Array.Empty<byte>()));
    }

    [Test]
    public void CreateStatementWithOnlyReceipt_WhenTagged_PreservesTag()
    {
        var coseSign1Tag = (CborTag)18;
        var bytes = CreateTaggedMinimalCoseSign1(tag: coseSign1Tag);

        var filtered = MstReceiptStatementFilter.CreateStatementWithOnlyReceipt(bytes, receiptBytes: Array.Empty<byte>());

        var reader = new CborReader(filtered, CborConformanceMode.Lax);
        Assert.That(reader.PeekState(), Is.EqualTo(CborReaderState.Tag));
        Assert.That(reader.ReadTag(), Is.EqualTo(coseSign1Tag));
    }

    private static byte[] CreateTaggedMinimalCoseSign1(CborTag tag)
    {
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteTag(tag);
        writer.WriteStartArray(4);
        writer.WriteByteString(Array.Empty<byte>());
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteByteString([0x01]);
        writer.WriteByteString([0x02]);
        writer.WriteEndArray();
        return writer.Encode();
    }
}
