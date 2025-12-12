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
    private readonly CodeTransparencyClient _client;
    private readonly CodeTransparencyVerificationOptions? _verificationOptions;
    private readonly CodeTransparencyClientOptions? _clientOptions;
    private readonly Action<string>? _logVerbose;
    private readonly Action<string>? _logError;

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
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _verificationOptions = verificationOptions;
        _clientOptions = clientOptions;
        _logVerbose = logVerbose;
        _logError = logError;
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

        _logVerbose?.Invoke($"[{ProviderName}] Starting transparency proof addition");

        // Encode the CoseSign1Message to a byte array
        BinaryData content = BinaryData.FromBytes(message.Encode());
        _logVerbose?.Invoke($"[{ProviderName}] Encoded message size: {content.ToArray().Length} bytes");

        // Submit to MST service
        _logVerbose?.Invoke($"[{ProviderName}] Submitting to transparency service...");
        Operation<BinaryData> operation = await _client.CreateEntryAsync(
            WaitUntil.Completed,
            content,
            cancellationToken).ConfigureAwait(false);

        // Check if the operation was successful
        if (!operation.HasValue)
        {
            string error = $"CreateEntryAsync failed: {operation.GetRawResponse().ReasonPhrase}";
            _logError?.Invoke($"[{ProviderName}] {error}");
            throw new InvalidOperationException($"MST transparency submission failed. {error}");
        }

        _logVerbose?.Invoke($"[{ProviderName}] Entry created successfully");

        // Get the entryId from the operation result
        if (!operation.Value.TryGetMstEntryId(out string entryId))
        {
            string error = "Response did not contain a valid CBOR-encoded entryId";
            _logError?.Invoke($"[{ProviderName}] {error}");
            throw new InvalidOperationException($"MST transparency submission failed. {error}");
        }

        _logVerbose?.Invoke($"[{ProviderName}] Entry ID: {entryId}");

        // Retrieve the transparent statement with embedded receipts
        _logVerbose?.Invoke($"[{ProviderName}] Retrieving transparent statement...");
        Response<BinaryData> transparentStatement = await _client.GetEntryStatementAsync(
            entryId,
            cancellationToken).ConfigureAwait(false);

        _logVerbose?.Invoke($"[{ProviderName}] Statement size: {transparentStatement.Value.ToArray().Length} bytes");

        // MST returns the full CoseSign1Message with receipts embedded
        _logVerbose?.Invoke($"[{ProviderName}] Decoding transparent statement");
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

        _logVerbose?.Invoke($"[{ProviderName}] Starting transparency verification");

        // Check if the message contains a transparency header
        if (!message.HasMstReceipt())
        {
            string error = "Message does not contain an MST receipt";
            _logError?.Invoke($"[{ProviderName}] {error}");
            return Task.FromResult(TransparencyValidationResult.Failure(ProviderName, error));
        }

        _logVerbose?.Invoke($"[{ProviderName}] MST receipt found in message");
        cancellationToken.ThrowIfCancellationRequested();

        // Log verification options if configured
        if (_verificationOptions != null && _logVerbose != null)
        {
            if (_verificationOptions.AuthorizedDomains?.Count > 0)
            {
                _logVerbose.Invoke($"[{ProviderName}] Authorized domains: {string.Join(", ", _verificationOptions.AuthorizedDomains)}");
            }
            _logVerbose.Invoke($"[{ProviderName}] Authorized receipt behavior: {_verificationOptions.AuthorizedReceiptBehavior}");
            _logVerbose.Invoke($"[{ProviderName}] Unauthorized receipt behavior: {_verificationOptions.UnauthorizedReceiptBehavior}");
        }

        // Verify using MST client
        try
        {
            _logVerbose?.Invoke($"[{ProviderName}] Calling VerifyTransparentStatement");
            CodeTransparencyClient.VerifyTransparentStatement(
                message.Encode(),
                _verificationOptions,
                _clientOptions);

            _logVerbose?.Invoke($"[{ProviderName}] Verification succeeded");

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
            _logError?.Invoke($"[{ProviderName}] Verification failed: {ex.Message}");
            return Task.FromResult(TransparencyValidationResult.Failure(ProviderName, ex.Message));
        }
        catch (CryptographicException ex)
        {
            _logError?.Invoke($"[{ProviderName}] Cryptographic error: {ex.Message}");
            return Task.FromResult(TransparencyValidationResult.Failure(ProviderName, $"Cryptographic error: {ex.Message}"));
        }
        catch (CborContentException ex)
        {
            _logError?.Invoke($"[{ProviderName}] CBOR content error: {ex.Message}");
            return Task.FromResult(TransparencyValidationResult.Failure(ProviderName, $"CBOR content error: {ex.Message}"));
        }
        catch (ArgumentException ex)
        {
            _logError?.Invoke($"[{ProviderName}] Invalid argument: {ex.Message}");
            return Task.FromResult(TransparencyValidationResult.Failure(ProviderName, $"Invalid argument: {ex.Message}"));
        }
        catch (AggregateException ex)
        {
            _logError?.Invoke($"[{ProviderName}] Multiple verification failures");
            var errors = new List<string>();
            foreach (var innerEx in ex.InnerExceptions)
            {
                errors.Add(innerEx.Message);
                _logVerbose?.Invoke($"[{ProviderName}]   - {innerEx.Message}");
            }
            return Task.FromResult(TransparencyValidationResult.Failure(ProviderName, errors));
        }
    }
}