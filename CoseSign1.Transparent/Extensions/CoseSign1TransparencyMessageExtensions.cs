// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.Extensions;

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Security.Cryptography.Cose;
using System.Threading;
using System.Threading.Tasks;
using CoseSign1.Transparent.Interfaces;

/// <summary>
/// Provides extension methods for enhancing the functionality of <see cref="CoseSign1Message"/> 
/// with transparency features using an <see cref="ITransparencyService"/>.
/// </summary>
public static class CoseSign1TransparencyMessageExtensions
{
    /// <summary>
    /// The header label used to indicate transparency in COSE Sign1 messages in SCITT.
    /// </summary>
    /// <remarks>
    /// The label value 394 was a previously proposed identifier for transparency in COSE Sign1 messages.
    /// However, it is not yet finalized in the IANA registry. The SCITT draft now uses a placeholder
    /// value (TBD_0) for this label:
    /// https://github.com/ietf-wg-scitt/draft-ietf-scitt-architecture/commit/fbcb3715e95ee709da6b1051498cf561bc5069a4
    /// </remarks>
    public static CoseHeaderLabel TransparencyHeaderLabel = new CoseHeaderLabel(394);

    /// <summary>
    /// Asynchronously transforms a <see cref="CoseSign1Message"/> into a transparent message 
    /// by leveraging the provided <see cref="ITransparencyService"/>.
    /// </summary>
    /// <param name="message">The original <see cref="CoseSign1Message"/> to be made transparent.</param>
    /// <param name="transparencyService">The <see cref="ITransparencyService"/> used to apply transparency.</param>
    /// <param name="cancellationToken">
    /// A <see cref="CancellationToken"/> to observe while waiting for the task to complete.
    /// </param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result contains a new 
    /// <see cref="CoseSign1Message"/> with transparency metadata or headers applied.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="message"/> or <paramref name="transparencyService"/> is null.
    /// </exception>
    public static Task<CoseSign1Message> MakeTransparentAsync(this CoseSign1Message message, ITransparencyService transparencyService, CancellationToken cancellationToken = default)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }
        if (transparencyService == null)
        {
            throw new ArgumentNullException(nameof(transparencyService));
        }

        return transparencyService.MakeTransparentAsync(message, cancellationToken);
    }

    /// <summary>
    /// Checks whether the given <see cref="CoseSign1Message"/> contains a transparency-related header.
    /// </summary>
    /// <param name="message">The <see cref="CoseSign1Message"/> to check for transparency headers.</param>
    /// <returns>
    /// True if the message contains the transparency header in either the protected or unprotected headers; otherwise, false.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="message"/> is null.</exception>
    public static bool ContainsTransparencyHeader(this CoseSign1Message message)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        // Check for the presence of transparency-related headers
        return message.UnprotectedHeaders.ContainsKey(TransparencyHeaderLabel);
    }

    /// <summary>
    /// Asynchronously verifies the transparency of a given <see cref="CoseSign1Message"/> 
    /// using the provided <see cref="ITransparencyService"/>.
    /// </summary>
    /// <param name="message">The <see cref="CoseSign1Message"/> to verify for transparency.</param>
    /// <param name="transparencyService">The <see cref="ITransparencyService"/> used to perform the verification.</param>
    /// <param name="cancellationToken">
    /// A <see cref="CancellationToken"/> to observe while waiting for the task to complete.
    /// </param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result is a boolean value indicating
    /// whether the message meets the transparency requirements (true if valid, false otherwise).
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="message"/> or <paramref name="transparencyService"/> is null.
    /// </exception>
    public static Task<bool> VerifyTransparencyAsync(this CoseSign1Message message, ITransparencyService transparencyService, CancellationToken cancellationToken = default)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }
        if (transparencyService == null)
        {
            throw new ArgumentNullException(nameof(transparencyService));
        }

        // Verify the transparency of the message using the provided service
        return transparencyService.VerifyTransparencyAsync(message, cancellationToken);
    }

    /// <summary>
    /// Attempts to extract receipts from the transparency-related header of a <see cref="CoseSign1Message"/>.
    /// </summary>
    /// <param name="message">The <see cref="CoseSign1Message"/> to extract receipts from.</param>
    /// <param name="receipts">
    /// When this method returns, contains a list of byte arrays representing the receipts if the operation was successful;
    /// otherwise, contains <c>null</c>.
    /// </param>
    /// <returns>
    /// True if the receipts were successfully extracted; otherwise, false.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="message"/> is null.</exception>
    public static bool TryGetReceipts(this CoseSign1Message message, out List<byte[]>? receipts)
    {
        receipts = null;
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        // The Transparency header is required for receipts to be embedded.
        if (!message.UnprotectedHeaders.TryGetValue(TransparencyHeaderLabel, out CoseHeaderValue receiptValue))
        {
            return false;
        }

        // parse the header value into a list of byte arrays
        try
        {
            receipts = receiptValue.ParseCoseHeaderToArray();
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Adds receipts to the transparency-related header of a <see cref="CoseSign1Message"/>.
    /// </summary>
    /// <param name="message">The <see cref="CoseSign1Message"/> to which receipts will be added.</param>
    /// <param name="receipts">The list of byte arrays representing the receipts to add.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="message"/> is null or if <paramref name="receipts"/> is null.
    /// </exception>
    public static void AddReceipts(this CoseSign1Message message, List<byte[]> receipts)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }
        if (receipts == null)
        {
            throw new ArgumentNullException(nameof(receipts));
        }
        if(receipts.Count == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(receipts), "Receipts cannot be empty.");
        }

        bool existingReceipts = message.TryGetReceipts(out List<byte[]>? existingReceiptsList);

        List<byte[]> totalReceipts = new List<byte[]>(receipts.Count + (existingReceiptsList?.Count ?? 0));
        if (existingReceiptsList != null)
        {
            foreach (byte[] receipt in existingReceiptsList)
            {
                totalReceipts.Add(receipt);
            }
        }
        foreach (byte[] receipt in receipts)
        {
            totalReceipts.Add(receipt);
        }

        // Write the receipts to a CBOR-encoded array
        CborWriter cborWriter = new();
        cborWriter.WriteStartArray(totalReceipts.Count);
        
        foreach (byte[] receipt in totalReceipts)
        {
            cborWriter.WriteByteString(receipt);
        }
        cborWriter.WriteEndArray();

        if (existingReceipts)
        {
            // Remove the existing receipts from the unprotected headers
            if (message.UnprotectedHeaders.ContainsKey(TransparencyHeaderLabel))
            {
                message.UnprotectedHeaders.Remove(TransparencyHeaderLabel);
            }
        }
        // Add the new receipts to the unprotected headers
        message.UnprotectedHeaders.Add(TransparencyHeaderLabel, CoseHeaderValue.FromEncodedValue(cborWriter.Encode()));
    }

    /// <summary>
    /// Parses a <see cref="CoseHeaderValue"/> into a list of byte arrays.
    /// </summary>
    /// <param name="headerValue">The <see cref="CoseHeaderValue"/> to parse.</param>
    /// <returns>A list of byte arrays extracted from the header value.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown if the header value is not in a valid CBOR array format.
    /// </exception>
    private static List<byte[]> ParseCoseHeaderToArray(this CoseHeaderValue headerValue)
    {
        List<byte[]> values = new();
        CborReader cborReader = new(headerValue.EncodedValue);
        if (cborReader.PeekState() != CborReaderState.StartArray)
        {
            throw new InvalidOperationException("Invalid CBOR format for receipts, they must be an array.");
        }
        cborReader.ReadStartArray();

        while (cborReader.PeekState() != CborReaderState.EndArray)
        {
            if (cborReader.PeekState() == CborReaderState.ByteString)
            {
                values.Add(cborReader.ReadByteString());
            }
            else
            {
                cborReader.SkipValue();
            }
        }
        return values;
    }
}
