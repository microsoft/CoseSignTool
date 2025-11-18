// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.CTS;

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Security.Cryptography;
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
    private readonly CodeTransparencyVerificationOptions? VerificationOptions;
    private readonly CodeTransparencyClientOptions? ClientOptions;
    private readonly Action<string>? LogVerbose;
    private readonly Action<string>? LogError;

    // LogWarning is reserved for future use when warning scenarios are identified
    #pragma warning disable IDE0052 // Remove unread private members
    private readonly Action<string>? LogWarning;
    #pragma warning restore IDE0052 // Remove unread private members

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureCtsTransparencyService"/> class.
    /// </summary>
    /// <param name="transparencyClient">The <see cref="CodeTransparencyClient"/> used to interact with the Azure CTS.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="transparencyClient"/> is null.</exception>
    public AzureCtsTransparencyService(CodeTransparencyClient transparencyClient)
        : this(transparencyClient, null, null, null, null, null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureCtsTransparencyService"/> class with verification options.
    /// </summary>
    /// <param name="transparencyClient">The <see cref="CodeTransparencyClient"/> used to interact with the Azure CTS.</param>
    /// <param name="verificationOptions">Optional verification options for controlling receipt validation behavior.</param>
    /// <param name="clientOptions">Optional client options for configuring client instances used during verification.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="transparencyClient"/> is null.</exception>
    public AzureCtsTransparencyService(
        CodeTransparencyClient transparencyClient,
        CodeTransparencyVerificationOptions? verificationOptions,
        CodeTransparencyClientOptions? clientOptions)
        : this(transparencyClient, verificationOptions, clientOptions, null, null, null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureCtsTransparencyService"/> class with verification options and logging.
    /// </summary>
    /// <param name="transparencyClient">The <see cref="CodeTransparencyClient"/> used to interact with the Azure CTS.</param>
    /// <param name="verificationOptions">Optional verification options for controlling receipt validation behavior.</param>
    /// <param name="clientOptions">Optional client options for configuring client instances used during verification.</param>
    /// <param name="logVerbose">Optional verbose logging callback.</param>
    /// <param name="logWarning">Optional warning logging callback.</param>
    /// <param name="logError">Optional error logging callback.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="transparencyClient"/> is null.</exception>
    public AzureCtsTransparencyService(
        CodeTransparencyClient transparencyClient,
        CodeTransparencyVerificationOptions? verificationOptions,
        CodeTransparencyClientOptions? clientOptions,
        Action<string>? logVerbose,
        Action<string>? logWarning,
        Action<string>? logError)
    {
        TransparencyClient = transparencyClient ?? throw new ArgumentNullException(nameof(transparencyClient));
        VerificationOptions = verificationOptions;
        ClientOptions = clientOptions;
        LogVerbose = logVerbose;
        LogWarning = logWarning;
        LogError = logError;
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

        LogVerbose?.Invoke("Starting MakeTransparentAsync operation");

        // Encode the CoseSign1Message to a byte array
        BinaryData content = BinaryData.FromBytes(message.Encode());
        LogVerbose?.Invoke($"Encoded message size: {content.ToArray().Length} bytes");

        // Request the entry be created in the transparency service
        LogVerbose?.Invoke("Calling CreateEntryAsync...");
        Operation<BinaryData> operation = await TransparencyClient.CreateEntryAsync(WaitUntil.Completed, content, cancellationToken).ConfigureAwait(false);

        // Check if the operation was successful
        if (!operation.HasValue)
        {
            string error = $"The transparency operation CreateEntryAsync failed to return a response: {operation.GetRawResponse().ReasonPhrase}";
            LogError?.Invoke(error);
            throw new InvalidOperationException(error);
        }

        LogVerbose?.Invoke("CreateEntryAsync completed successfully");

        // Get the entryId from the operation result
        if (!operation.Value.TryGetCtsEntryId(out string entryId))
        {
            string error = "The transparency operation failed, content was not a valid CBOR-encoded entryId.";
            LogError?.Invoke(error);
            throw new InvalidOperationException(error);
        }

        LogVerbose?.Invoke($"Entry ID: {entryId}");

        // Query the transparency service for the entry statement
        LogVerbose?.Invoke("Retrieving entry statement...");
        Response<BinaryData> transparentStatement = await TransparencyClient.GetEntryStatementAsync(entryId, cancellationToken).ConfigureAwait(false);
        LogVerbose?.Invoke($"Entry statement size: {transparentStatement.Value.ToArray().Length} bytes");

        // Azure CTS replies with the full CoseSign1Message which will include the receipts already, so return it to the caller.
        LogVerbose?.Invoke("Decoding transparent statement");
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

        LogVerbose?.Invoke("Starting transparency verification");

        // Check if the message contains a transparency header
        if (!message.ContainsTransparencyHeader())
        {
            string error = "The message does not contain a transparency header and cannot be verified.";
            LogError?.Invoke(error);
            throw new InvalidOperationException(error);
        }
        
        LogVerbose?.Invoke("Transparency header found in message");
        cancellationToken.ThrowIfCancellationRequested();

        // Log verification options if configured
        if (VerificationOptions != null && LogVerbose != null)
        {
            if (VerificationOptions.AuthorizedDomains?.Count > 0)
            {
                LogVerbose?.Invoke($"Authorized domains: {string.Join(", ", VerificationOptions.AuthorizedDomains)}");
            }
            LogVerbose?.Invoke($"Authorized receipt behavior: {VerificationOptions.AuthorizedReceiptBehavior}");
            LogVerbose?.Invoke($"Unauthorized receipt behavior: {VerificationOptions.UnauthorizedReceiptBehavior}");
        }

        // Ask CTS to verify the entry
        try
        {
            LogVerbose?.Invoke("Calling CodeTransparencyClient.VerifyTransparentStatement");
            CodeTransparencyClient.VerifyTransparentStatement(message.Encode(), VerificationOptions, ClientOptions);
            LogVerbose?.Invoke("Transparency verification succeeded");
            return Task.FromResult(true);
        }
        catch(InvalidOperationException ex)
        {
            LogError?.Invoke($"Verification failed: {ex.Message}");
            LogVerbose?.Invoke($"InvalidOperationException details: {ex}");
            return Task.FromResult(false);
        }
        catch(CryptographicException ex)
        {
            LogError?.Invoke($"Cryptographic error during verification: {ex.Message}");
            LogVerbose?.Invoke($"CryptographicException details: {ex}");
            return Task.FromResult(false);
        }
        catch(CborContentException ex)
        {
            LogError?.Invoke($"CBOR content error during verification: {ex.Message}");
            LogVerbose?.Invoke($"CborContentException details: {ex}");
            return Task.FromResult(false);
        }
        catch(ArgumentException ex)
        {
            LogError?.Invoke($"Invalid argument during verification: {ex.Message}");
            LogVerbose?.Invoke($"ArgumentException details: {ex}");
            return Task.FromResult(false);
        }
        catch(AggregateException ex)
        {
            LogError?.Invoke($"Multiple verification failures occurred");
            
            if (LogVerbose != null)
            {
                foreach (var innerEx in ex.InnerExceptions)
                {
                    LogVerbose?.Invoke($"  - {innerEx.Message}");
                }
            }
            
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
