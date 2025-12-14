// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.Security.CodeTransparency;
using CoseSign1.Abstractions.Transparency;
using CoseSign1.Transparent.MST.Extensions;

namespace CoseSign1.Transparent.MST;

/// <summary>
/// Transparency provider for Microsoft's Signing Transparency (MST) service.
/// Implements the V2 transparency architecture pattern.
/// </summary>
public class MstTransparencyProvider : ITransparencyProvider
{
    private readonly CodeTransparencyClient Client;
    private readonly CodeTransparencyVerificationOptions? VerificationOptions;
    private readonly CodeTransparencyClientOptions? ClientOptions;
    private readonly Action<string>? LogVerbose;
    private readonly Action<string>? LogError;

    /// <summary>
    /// Gets the name of this transparency provider.
    /// </summary>
    public string ProviderName => "Microsoft Signing Transparency";

    /// <summary>
    /// Initializes a new instance of the <see cref="MstTransparencyProvider"/> class.
    /// </summary>
    /// <param name="client">The CodeTransparency client for MST operations.</param>
    public MstTransparencyProvider(CodeTransparencyClient client)
        : this(client, null, null, null, null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MstTransparencyProvider"/> class with verification options.
    /// </summary>
    /// <param name="client">The CodeTransparency client for MST operations.</param>
    /// <param name="verificationOptions">Optional verification options for controlling receipt validation behavior.</param>
    /// <param name="clientOptions">Optional client options for the transparency client.</param>
    public MstTransparencyProvider(
        CodeTransparencyClient client,
        CodeTransparencyVerificationOptions? verificationOptions,
        CodeTransparencyClientOptions? clientOptions)
        : this(client, verificationOptions, clientOptions, null, null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MstTransparencyProvider"/> class with logging.
    /// </summary>
    /// <param name="client">The CodeTransparency client for MST operations.</param>
    /// <param name="verificationOptions">Optional verification options for controlling receipt validation behavior.</param>
    /// <param name="clientOptions">Optional client options for configuring client instances used during verification.</param>
    /// <param name="logVerbose">Optional verbose logging callback.</param>
    /// <param name="logError">Optional error logging callback.</param>
    public MstTransparencyProvider(
        CodeTransparencyClient client,
        CodeTransparencyVerificationOptions? verificationOptions,
        CodeTransparencyClientOptions? clientOptions,
        Action<string>? logVerbose,
        Action<string>? logError)
    {
        Client = client ?? throw new ArgumentNullException(nameof(client));
        VerificationOptions = verificationOptions;
        ClientOptions = clientOptions;
        LogVerbose = logVerbose;
        LogError = logError;
    }

    /// <summary>
    /// Adds MST transparency proof to the signed COSE message.
    /// </summary>
    /// <param name="message">The signed COSE Sign1 message.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A new message with MST receipt embedded in unprotected headers.</returns>
    public async Task<CoseSign1Message> AddTransparencyProofAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        LogVerbose?.Invoke($"[{ProviderName}] Starting transparency proof addition");

        // Encode the CoseSign1Message to a byte array
        BinaryData content = BinaryData.FromBytes(message.Encode());
        LogVerbose?.Invoke($"[{ProviderName}] Encoded message size: {content.ToArray().Length} bytes");

        // Submit to MST service
        LogVerbose?.Invoke($"[{ProviderName}] Submitting to transparency service...");
        Operation<BinaryData> operation = await Client.CreateEntryAsync(
            WaitUntil.Completed,
            content,
            cancellationToken).ConfigureAwait(false);

        // Check if the operation was successful
        if (!operation.HasValue)
        {
            string error = $"CreateEntryAsync failed: {operation.GetRawResponse().ReasonPhrase}";
            LogError?.Invoke($"[{ProviderName}] {error}");
            throw new InvalidOperationException($"MST transparency submission failed. {error}");
        }

        LogVerbose?.Invoke($"[{ProviderName}] Entry created successfully");

        // Get the entryId from the operation result
        if (!operation.Value.TryGetMstEntryId(out string? entryId) || entryId is null)
        {
            string error = "Response did not contain a valid CBOR-encoded entryId";
            LogError?.Invoke($"[{ProviderName}] {error}");
            throw new InvalidOperationException($"MST transparency submission failed. {error}");
        }

        LogVerbose?.Invoke($"[{ProviderName}] Entry ID: {entryId}");

        // Retrieve the transparent statement with embedded receipts
        LogVerbose?.Invoke($"[{ProviderName}] Retrieving transparent statement...");
        Response<BinaryData> transparentStatement = await Client.GetEntryStatementAsync(
            entryId,
            cancellationToken).ConfigureAwait(false);

        LogVerbose?.Invoke($"[{ProviderName}] Statement size: {transparentStatement.Value.ToArray().Length} bytes");

        // MST returns the full CoseSign1Message with receipts embedded
        LogVerbose?.Invoke($"[{ProviderName}] Decoding transparent statement");
        return CoseMessage.DecodeSign1(transparentStatement.Value.ToArray());
    }

    /// <summary>
    /// Verifies the MST transparency proof in the message.
    /// </summary>
    /// <param name="message">The COSE Sign1 message with MST receipt.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Validation result with status and details.</returns>
    public Task<TransparencyValidationResult> VerifyTransparencyProofAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        LogVerbose?.Invoke($"[{ProviderName}] Starting transparency verification");

        // Check if the message contains a transparency header
        if (!message.HasMstReceipt())
        {
            string error = "Message does not contain an MST receipt";
            LogError?.Invoke($"[{ProviderName}] {error}");
            return Task.FromResult(TransparencyValidationResult.Failure(ProviderName, error));
        }

        LogVerbose?.Invoke($"[{ProviderName}] MST receipt found in message");
        cancellationToken.ThrowIfCancellationRequested();

        // Log verification options if configured
        if (VerificationOptions != null && LogVerbose != null)
        {
            if (VerificationOptions.AuthorizedDomains?.Count > 0)
            {
                LogVerbose.Invoke($"[{ProviderName}] Authorized domains: {string.Join(", ", VerificationOptions.AuthorizedDomains)}");
            }
            LogVerbose.Invoke($"[{ProviderName}] Authorized receipt behavior: {VerificationOptions.AuthorizedReceiptBehavior}");
            LogVerbose.Invoke($"[{ProviderName}] Unauthorized receipt behavior: {VerificationOptions.UnauthorizedReceiptBehavior}");
        }

        // Verify using MST client
        try
        {
            LogVerbose?.Invoke($"[{ProviderName}] Calling VerifyTransparentStatement");
            CodeTransparencyClient.VerifyTransparentStatement(
                message.Encode(),
                VerificationOptions,
                ClientOptions);

            LogVerbose?.Invoke($"[{ProviderName}] Verification succeeded");

            return Task.FromResult(TransparencyValidationResult.Success(
                ProviderName,
                new Dictionary<string, object>
                {
                    ["verified"] = true,
                    ["timestamp"] = DateTimeOffset.UtcNow
                }));
        }
        catch (InvalidOperationException ex)
        {
            LogError?.Invoke($"[{ProviderName}] Verification failed: {ex.Message}");
            return Task.FromResult(TransparencyValidationResult.Failure(ProviderName, ex.Message));
        }
        catch (CryptographicException ex)
        {
            LogError?.Invoke($"[{ProviderName}] Cryptographic error: {ex.Message}");
            return Task.FromResult(TransparencyValidationResult.Failure(ProviderName, $"Cryptographic error: {ex.Message}"));
        }
        catch (CborContentException ex)
        {
            LogError?.Invoke($"[{ProviderName}] CBOR content error: {ex.Message}");
            return Task.FromResult(TransparencyValidationResult.Failure(ProviderName, $"CBOR content error: {ex.Message}"));
        }
        catch (ArgumentException ex)
        {
            LogError?.Invoke($"[{ProviderName}] Invalid argument: {ex.Message}");
            return Task.FromResult(TransparencyValidationResult.Failure(ProviderName, $"Invalid argument: {ex.Message}"));
        }
        catch (AggregateException ex)
        {
            LogError?.Invoke($"[{ProviderName}] Multiple verification failures");
            var errors = new List<string>();
            foreach (var innerEx in ex.InnerExceptions)
            {
                errors.Add(innerEx.Message);
                LogVerbose?.Invoke($"[{ProviderName}]   - {innerEx.Message}");
            }
            return Task.FromResult(TransparencyValidationResult.Failure(ProviderName, errors));
        }
    }
}