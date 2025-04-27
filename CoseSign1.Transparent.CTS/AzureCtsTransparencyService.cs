// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.CTS;

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Security.Cryptography.Cose;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.CTS.Extensions;
using CoseSign1.Transparent.Extensions;
using CoseSign1.Transparent.Interfaces;

/// <summary>
/// Provides an implementation of the <see cref="ITransparencyService"/> interface using Azure Code Transparency Service (CTS).
/// This service enables the creation and verification of transparent COSE Sign1 messages.
/// </summary>
public class AzureCtsTransparencyService : ITransparencyService
{
    private readonly CodeTransparencyClient TransparencyClient;

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureCtsTransparencyService"/> class.
    /// </summary>
    /// <param name="transparencyClient">The <see cref="CodeTransparencyClient"/> used to interact with the Azure CTS.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="transparencyClient"/> is null.</exception>
    public AzureCtsTransparencyService(CodeTransparencyClient transparencyClient)
    {
        TransparencyClient = transparencyClient ?? throw new ArgumentNullException(nameof(transparencyClient));
    }

    /// <summary>
    /// Creates a new transparent COSE Sign1 message by embedding additional metadata or headers
    /// into the provided COSE Sign1 message using Azure CTS.
    /// </summary>
    /// <param name="message">The original <see cref="CoseSign1Message"/> to be transformed into a transparent message.</param>
    /// <param name="cancellationToken">
    /// A <see cref="CancellationToken"/> to observe while waiting for the task to complete.
    /// </param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result contains a new 
    /// <see cref="CoseSign1Message"/> with the transparency metadata or headers applied.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="message"/> is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the transparency operation fails.</exception>
    public async Task<CoseSign1Message> MakeTransparentAsync(CoseSign1Message message, CancellationToken cancellationToken = default)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        // Encode the CoseSign1Message to a byte array
        BinaryData content = BinaryData.FromBytes(message.Encode());

        // Request the entry be created in the transparency service
        Operation<BinaryData> operation = await TransparencyClient.CreateEntryAsync(WaitUntil.Completed, content, cancellationToken).ConfigureAwait(false);

        // Check if the operation was successful
        if (!operation.HasValue)
        {
            throw new InvalidOperationException($"The transparency operation CreateEntryAsync failed to return a response: {operation.GetRawResponse().ReasonPhrase}");
        }

        // Get the entryId from the operation result
        if (!operation.Value.TryGetCtsEntryId(out string entryId))
        {
            throw new InvalidOperationException($"The transparency operation failed, content was not a valid CBOR-encoded entryId.");
        }

        // Query the transparency service for the entry statement
        Response<BinaryData> transparentStatement = await TransparencyClient.GetEntryStatementAsync(entryId, cancellationToken).ConfigureAwait(false);

        // Azure CTS replies with the full CoseSign1Message which will include the receipts already, so return it to the caller.
        return CoseMessage.DecodeSign1(transparentStatement.Value.ToArray());
    }

    /// <summary>
    /// Verifies the transparency of a given COSE Sign1 message by checking its metadata or headers
    /// against the expected transparency rules using Azure CTS.
    /// </summary>
    /// <param name="message">The <see cref="CoseSign1Message"/> to verify for transparency.</param>
    /// <param name="cancellationToken">
    /// A <see cref="CancellationToken"/> to observe while waiting for the task to complete.
    /// </param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result is a boolean value indicating
    /// whether the message meets the transparency requirements (true if valid, false otherwise).
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="message"/> is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the message does not contain a transparency header.</exception>
    public Task<bool> VerifyTransparencyAsync(CoseSign1Message message, CancellationToken cancellationToken = default)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        // Check if the message contains a transparency header
        if (!message.ContainsTransparencyHeader())
        {
            throw new InvalidOperationException($"The message does not contain a transparency header and cannot be verified.");
        }
        cancellationToken.ThrowIfCancellationRequested();

        // Ask CTS to verify the entry
        try
        {
            TransparencyClient.RunTransparentStatementVerification(message.Encode());
            return Task.FromResult(true);
        }
        catch(InvalidOperationException)
        {
            return Task.FromResult(false);
        }
        catch(CborContentException)
        {
            return Task.FromResult(false);
        }
        catch(ArgumentException)
        {
            return Task.FromResult(false);
        }
    }

    /// <summary>
    /// Verifies the transparency of a given COSE Sign1 message using a specific receipt.
    /// </summary>
    /// <param name="message">The <see cref="CoseSign1Message"/> to verify for transparency.</param>
    /// <param name="receipt">The receipt to use for verification.</param>
    /// <param name="cancellationToken">
    /// A <see cref="CancellationToken"/> to observe while waiting for the task to complete.
    /// </param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result is a boolean value indicating
    /// whether the message meets the transparency requirements when verified with the provided receipt (true if valid, false otherwise).
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="message"/> or <paramref name="receipt"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="receipt"/> is empty.</exception>
    public Task<bool> VerifyTransparencyAsync(CoseSign1Message message, byte[] receipt, CancellationToken cancellationToken = default)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }
        if (receipt == null)
        {
            throw new ArgumentNullException(nameof(receipt));
        }
        if (receipt.Length == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(receipt), "The receipt cannot be empty");
        }

        // CTS requires the receipt to be embedded in the CoseSign1Message for verification, so embed it
        message.AddReceipts(new List<byte[]> { receipt });

        // Verify the transparency of the message using the provided service
        return VerifyTransparencyAsync(message, cancellationToken);
    }
}
