// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Trust;

using System.Formats.Cbor;
using System.Globalization;

internal static class MstReceiptStatementFilter
{
    internal static class ClassStrings
    {
        public const string CoseSign1ExpectedArrayLengthPrefix = "Expected COSE_Sign1 array length 4 but got ";
        public const string UnsupportedCoseHeaderKeyType = "Unsupported COSE header key type";
    }

    internal const int MstReceiptHeaderLabel = 394;

    internal static byte[] CreateStatementWithOnlyReceipt(byte[] coseSign1Bytes, byte[] receiptBytes)
    {
        // COSE_Sign1 may be wrapped in tag 18 (COSE_Sign1), followed by the structure:
        // [protected, unprotected, payload, signature]
        // We must accept tagged COSE values (e.g., tag 18). CTAP2 canonical mode rejects tags.
        var reader = new CborReader(coseSign1Bytes, CborConformanceMode.Lax);

        CborTag? tag = null;
        if (reader.PeekState() == CborReaderState.Tag)
        {
            tag = reader.ReadTag();
        }

        var arrayLength = reader.ReadStartArray();
        if (arrayLength.HasValue && arrayLength.Value != 4)
        {
            throw new CborContentException(string.Concat(ClassStrings.CoseSign1ExpectedArrayLengthPrefix, arrayLength.Value.ToString(CultureInfo.InvariantCulture)));
        }

        var protectedHeaders = reader.ReadByteString();

        var mapLength = reader.ReadStartMap();
        var preserved = new List<(object Key, byte[] EncodedValue)>();

        // Preserve all unprotected headers except the MST receipt label; we will overwrite it.
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            object key = reader.PeekState() switch
            {
                CborReaderState.UnsignedInteger or CborReaderState.NegativeInteger => reader.ReadInt32(),
                CborReaderState.TextString => reader.ReadTextString(),
                _ => throw new CborContentException(ClassStrings.UnsupportedCoseHeaderKeyType),
            };

            var encodedValue = reader.ReadEncodedValue().ToArray();

            if (key is int i && i == MstReceiptHeaderLabel)
            {
                // drop existing value
                continue;
            }

            preserved.Add((key, encodedValue));
        }

        reader.ReadEndMap();

        // Payload and signature can be copied verbatim.
        var payloadEncoded = reader.ReadEncodedValue().ToArray();
        var signatureEncoded = reader.ReadEncodedValue().ToArray();

        reader.ReadEndArray();

        // New receipt array: [ bstr(receiptBytes) ]
        var receiptArrayWriter = new CborWriter(CborConformanceMode.Lax);
        receiptArrayWriter.WriteStartArray(1);
        receiptArrayWriter.WriteByteString(receiptBytes);
        receiptArrayWriter.WriteEndArray();
        var receiptArrayEncoded = receiptArrayWriter.Encode();

        var writer = new CborWriter(CborConformanceMode.Lax);
        if (tag.HasValue)
        {
            writer.WriteTag(tag.Value);
        }
        writer.WriteStartArray(4);
        writer.WriteByteString(protectedHeaders);

        // Add back preserved headers + the MST receipt header.
        writer.WriteStartMap(preserved.Count + 1);

        foreach (var (key, encodedValue) in preserved)
        {
            if (key is int i)
            {
                writer.WriteInt32(i);
            }
            else
            {
                writer.WriteTextString((string)key);
            }

            writer.WriteEncodedValue(encodedValue);
        }

        writer.WriteInt32(MstReceiptHeaderLabel);
        writer.WriteEncodedValue(receiptArrayEncoded);

        writer.WriteEndMap();
        writer.WriteEncodedValue(payloadEncoded);
        writer.WriteEncodedValue(signatureEncoded);
        writer.WriteEndArray();

        return writer.Encode();
    }
}
