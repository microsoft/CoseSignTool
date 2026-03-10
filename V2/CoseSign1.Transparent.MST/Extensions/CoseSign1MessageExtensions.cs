// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Extensions;

using System.Formats.Cbor;
using System.Security.Cryptography.Cose;

/// <summary>
/// Extension methods for <see cref="CoseSign1Message"/> to work with MST receipts.
/// </summary>
public static class CoseSign1MessageExtensions
{
    // MST uses the same CBOR Web Token (CWT) header as defined in RFC 8392
    // Header label 394 is used for receipts
    private static readonly CoseHeaderLabel ReceiptLabel = new(394);

    /// <summary>
    /// Checks if the message contains MST receipt(s) in its unprotected headers.
    /// </summary>
    /// <param name="message">The COSE Sign1 message to check.</param>
    /// <returns>True if the message has MST receipt(s); otherwise, false.</returns>
    public static bool HasMstReceipt(this CoseSign1Message message)
    {
        return message?.UnprotectedHeaders?.TryGetValue(ReceiptLabel, out _) == true;
    }

    /// <summary>
    /// Gets the MST receipts from the message's unprotected headers.
    /// </summary>
    /// <param name="message">The COSE Sign1 message.</param>
    /// <returns>A list of receipt COSE_Sign1 messages, or an empty list if no receipts are present.</returns>
    public static IReadOnlyList<CoseSign1Message> GetMstReceipts(this CoseSign1Message message)
    {
        var receipts = new List<CoseSign1Message>();
        var receiptBytes = message.GetMstReceiptBytes();

        foreach (var bytes in receiptBytes)
        {
            try
            {
                receipts.Add(CoseMessage.DecodeSign1(bytes));
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                // Skip receipts that fail to decode
            }
            catch (CborContentException)
            {
                // Skip receipts with invalid CBOR structure
            }
        }

        return receipts;
    }

    /// <summary>
    /// Gets the raw MST receipt bytes from the message's unprotected headers.
    /// </summary>
    /// <param name="message">The COSE Sign1 message.</param>
    /// <returns>A list of receipt byte arrays, or an empty list if no receipts are present.</returns>
    public static IReadOnlyList<byte[]> GetMstReceiptBytes(this CoseSign1Message message)
    {
        var receiptBytes = new List<byte[]>();

        if (message?.UnprotectedHeaders?.TryGetValue(ReceiptLabel, out var value) == true)
        {
            try
            {
                // The receipts are stored as a CBOR array of byte strings
                var reader = new CborReader(value.EncodedValue);

                if (reader.PeekState() != CborReaderState.StartArray)
                {
                    return receiptBytes;
                }

                reader.ReadStartArray();
                while (reader.PeekState() != CborReaderState.EndArray)
                {
                    receiptBytes.Add(reader.ReadByteString());
                }
                reader.ReadEndArray();
            }
            catch (CborContentException)
            {
                // If parsing fails, return empty list
                return receiptBytes;
            }
        }

        return receiptBytes;
    }
}