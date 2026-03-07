// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST;

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent;
using CoseSign1.Transparent.Extensions;
using CoseSign1.Transparent.MST.Extensions;

/// <summary>
/// Provides an implementation of the <see cref="TransparencyService"/> base class using Microsoft's Signing Transparency (MST).
/// This service enables the creation and verification of transparent COSE Sign1 messages.
/// </summary>
public class MstTransparencyService : TransparencyService
{
    private readonly CodeTransparencyClient TransparencyClient;
    private readonly CodeTransparencyVerificationOptions? VerificationOptions;
    private readonly CodeTransparencyClientOptions? ClientOptions;
    private readonly MstPollingOptions? PollingOptions;
    private readonly Uri? _serviceEndpoint;

    /// <inheritdoc />
    public override Uri? ServiceEndpoint => _serviceEndpoint;

    /// <summary>
    /// Initializes a new instance of the <see cref="MstTransparencyService"/> class.
    /// </summary>
    /// <param name="transparencyClient">The <see cref="CodeTransparencyClient"/> used to interact with the Azure CTS.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="transparencyClient"/> is null.</exception>
    public MstTransparencyService(CodeTransparencyClient transparencyClient)
        : this(transparencyClient, null, null, null, null, null, null, null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MstTransparencyService"/> class with a service endpoint.
    /// </summary>
    /// <param name="transparencyClient">The <see cref="CodeTransparencyClient"/> used to interact with the Azure CTS.</param>
    /// <param name="serviceEndpoint">The URI of the Azure CTS endpoint this service communicates with.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="transparencyClient"/> is null.</exception>
    public MstTransparencyService(CodeTransparencyClient transparencyClient, Uri serviceEndpoint)
        : this(transparencyClient, null, null, null, serviceEndpoint, null, null, null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MstTransparencyService"/> class with verification options.
    /// </summary>
    /// <param name="transparencyClient">The <see cref="CodeTransparencyClient"/> used to interact with the Azure CTS.</param>
    /// <param name="verificationOptions">Optional verification options for controlling receipt validation behavior.</param>
    /// <param name="clientOptions">Optional client options for the transparency client.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="transparencyClient"/> is null.</exception>
    public MstTransparencyService(
        CodeTransparencyClient transparencyClient,
        CodeTransparencyVerificationOptions? verificationOptions,
        CodeTransparencyClientOptions? clientOptions)
        : this(transparencyClient, verificationOptions, clientOptions, null, null, null, null, null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MstTransparencyService"/> class with polling options.
    /// </summary>
    /// <param name="transparencyClient">The <see cref="CodeTransparencyClient"/> used to interact with the Azure CTS.</param>
    /// <param name="pollingOptions">Options controlling the polling behavior for long-running operations.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="transparencyClient"/> is null.</exception>
    public MstTransparencyService(
        CodeTransparencyClient transparencyClient,
        MstPollingOptions pollingOptions)
        : this(transparencyClient, null, null, pollingOptions, null, null, null, null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MstTransparencyService"/> class with verification and polling options.
    /// </summary>
    /// <param name="transparencyClient">The <see cref="CodeTransparencyClient"/> used to interact with the Azure CTS.</param>
    /// <param name="verificationOptions">Optional verification options for controlling receipt validation behavior.</param>
    /// <param name="clientOptions">Optional client options for configuring client instances used during verification.</param>
    /// <param name="pollingOptions">Options controlling the polling behavior for long-running operations.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="transparencyClient"/> is null.</exception>
    public MstTransparencyService(
        CodeTransparencyClient transparencyClient,
        CodeTransparencyVerificationOptions? verificationOptions,
        CodeTransparencyClientOptions? clientOptions,
        MstPollingOptions? pollingOptions)
        : this(transparencyClient, verificationOptions, clientOptions, pollingOptions, null, null, null, null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MstTransparencyService"/> class with verification options and logging.
    /// </summary>
    /// <param name="transparencyClient">The <see cref="CodeTransparencyClient"/> used to interact with the Azure CTS.</param>
    /// <param name="verificationOptions">Optional verification options for controlling receipt validation behavior.</param>
    /// <param name="clientOptions">Optional client options for configuring client instances used during verification.</param>
    /// <param name="logVerbose">Optional verbose logging callback.</param>
    /// <param name="logWarning">Optional warning logging callback.</param>
    /// <param name="logError">Optional error logging callback.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="transparencyClient"/> is null.</exception>
    public MstTransparencyService(
        CodeTransparencyClient transparencyClient,
        CodeTransparencyVerificationOptions? verificationOptions,
        CodeTransparencyClientOptions? clientOptions,
        Action<string>? logVerbose,
        Action<string>? logWarning,
        Action<string>? logError)
        : this(transparencyClient, verificationOptions, clientOptions, null, null, logVerbose, logWarning, logError)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MstTransparencyService"/> class with all options.
    /// </summary>
    /// <param name="transparencyClient">The <see cref="CodeTransparencyClient"/> used to interact with the Azure CTS.</param>
    /// <param name="verificationOptions">Optional verification options for controlling receipt validation behavior.</param>
    /// <param name="clientOptions">Optional client options for configuring client instances used during verification.</param>
    /// <param name="pollingOptions">Options controlling the polling behavior for long-running operations.</param>
    /// <param name="serviceEndpoint">The URI of the Azure CTS endpoint this service communicates with.</param>
    /// <param name="logVerbose">Optional verbose logging callback.</param>
    /// <param name="logWarning">Optional warning logging callback.</param>
    /// <param name="logError">Optional error logging callback.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="transparencyClient"/> is null.</exception>
    public MstTransparencyService(
        CodeTransparencyClient transparencyClient,
        CodeTransparencyVerificationOptions? verificationOptions,
        CodeTransparencyClientOptions? clientOptions,
        MstPollingOptions? pollingOptions,
        Uri? serviceEndpoint,
        Action<string>? logVerbose,
        Action<string>? logWarning,
        Action<string>? logError)
        : base(logVerbose, logWarning, logError)
    {
        TransparencyClient = transparencyClient ?? throw new ArgumentNullException(nameof(transparencyClient));
        VerificationOptions = verificationOptions;
        ClientOptions = clientOptions;
        PollingOptions = pollingOptions;
        _serviceEndpoint = serviceEndpoint ?? TryGetEndpointFromClient(transparencyClient);
    }

    /// <summary>
    /// Attempts to derive the service endpoint URI from the <see cref="CodeTransparencyClient"/>
    /// by reading its internal <c>_endpoint</c> field via reflection.
    /// </summary>
    /// <remarks>
    /// The Azure.Security.CodeTransparency SDK does not currently expose the endpoint as a public
    /// property. This method uses reflection as a best-effort fallback so callers don't need to
    /// pass the URI twice. Returns <c>null</c> if the field is not found or inaccessible.
    /// </remarks>
    private static Uri? TryGetEndpointFromClient(CodeTransparencyClient client)
    {
        try
        {
            var field = typeof(CodeTransparencyClient)
                .GetField("_endpoint", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            return field?.GetValue(client) as Uri;
        }
        catch (System.Reflection.TargetInvocationException)
        {
            return null;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
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
    /// <exception cref="MstServiceException">Thrown if the MST service returns an error with CBOR problem details.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the transparency operation fails.</exception>
    protected override async Task<CoseSign1Message> MakeTransparentCoreAsync(CoseSign1Message message, CancellationToken cancellationToken = default)
    {
        LogVerbose?.Invoke("Starting MakeTransparentAsync operation");

        // Encode the CoseSign1Message to a byte array
        BinaryData content = BinaryData.FromBytes(message.Encode());
        LogVerbose?.Invoke($"Encoded message size: {content.ToArray().Length} bytes");

        Operation<BinaryData> operation;
        try
        {
            // Request the entry be created in the transparency service
            LogVerbose?.Invoke("Calling CreateEntryAsync...");
            operation = await TransparencyClient.CreateEntryAsync(WaitUntil.Started, content, cancellationToken).ConfigureAwait(false);

            // Wait for the operation to complete, respecting polling options.
            // DelayStrategy takes precedence over PollingInterval if both are set.
            LogVerbose?.Invoke("Waiting for CreateEntryAsync operation to complete...");
            if (PollingOptions?.DelayStrategy != null)
            {
                LogVerbose?.Invoke($"Using custom DelayStrategy: {PollingOptions.DelayStrategy.GetType().Name}");
                await operation.WaitForCompletionAsync(PollingOptions.DelayStrategy, cancellationToken).ConfigureAwait(false);
            }
            else if (PollingOptions?.PollingInterval != null)
            {
                LogVerbose?.Invoke($"Using fixed polling interval: {PollingOptions.PollingInterval.Value.TotalMilliseconds}ms");
                await operation.WaitForCompletionAsync(PollingOptions.PollingInterval.Value, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await operation.WaitForCompletionAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Azure.RequestFailedException rfEx)
        {
            // Parse CBOR problem details from the MST error response (RFC 9290)
            var mstEx = MstServiceException.FromRequestFailedException(rfEx);
            LogError?.Invoke(mstEx.Message);
            if (mstEx.ProblemDetails != null)
            {
                LogVerbose?.Invoke($"Problem details: {mstEx.ProblemDetails}");
            }
            throw mstEx;
        }

        // Check if the operation was successful
        if (!operation.HasValue)
        {
            string error = $"The transparency operation CreateEntryAsync failed to return a response: {operation.GetRawResponse().ReasonPhrase}";
            LogError?.Invoke(error);
            throw new InvalidOperationException(error);
        }

        LogVerbose?.Invoke("CreateEntryAsync completed successfully");

        // Get the entryId from the operation result
        if (!operation.Value.TryGetMstEntryId(out string entryId))
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
    public override Task<bool> VerifyTransparencyAsync(CoseSign1Message message, CancellationToken cancellationToken = default)
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
                LogVerbose.Invoke($"Authorized domains: {string.Join(", ", VerificationOptions.AuthorizedDomains)}");
            }
            LogVerbose.Invoke($"Authorized receipt behavior: {VerificationOptions.AuthorizedReceiptBehavior}");
            LogVerbose.Invoke($"Unauthorized receipt behavior: {VerificationOptions.UnauthorizedReceiptBehavior}");
        }

        // Ask CTS to verify the entry
        try
        {
            LogVerbose?.Invoke("Calling CodeTransparencyClient.VerifyTransparentStatement");
            CodeTransparencyClient.VerifyTransparentStatement(message.Encode(), VerificationOptions, ClientOptions);
            LogVerbose?.Invoke("Transparency verification succeeded");
            return Task.FromResult(true);
        }
        catch (InvalidOperationException ex)
        {
            LogError?.Invoke($"Verification failed: {ex.Message}");
            LogVerbose?.Invoke($"InvalidOperationException details: {ex}");
            return Task.FromResult(false);
        }
        catch (CryptographicException ex)
        {
            LogError?.Invoke($"Cryptographic error during verification: {ex.Message}");
            LogVerbose?.Invoke($"CryptographicException details: {ex}");
            return Task.FromResult(false);
        }
        catch (CborContentException ex)
        {
            LogError?.Invoke($"CBOR content error during verification: {ex.Message}");
            LogVerbose?.Invoke($"CborContentException details: {ex}");
            return Task.FromResult(false);
        }
        catch (ArgumentException ex)
        {
            LogError?.Invoke($"Invalid argument during verification: {ex.Message}");
            LogVerbose?.Invoke($"ArgumentException details: {ex}");
            return Task.FromResult(false);
        }
        catch (AggregateException ex)
        {
            LogError?.Invoke($"Multiple verification failures occurred");

            foreach (var innerEx in ex.InnerExceptions)
            {
                LogVerbose?.Invoke($"  - {innerEx.Message}");
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
    public override Task<bool> VerifyTransparencyAsync(CoseSign1Message message, byte[] receipt, CancellationToken cancellationToken = default)
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