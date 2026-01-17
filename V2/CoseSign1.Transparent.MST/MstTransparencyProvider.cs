// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST;

using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using Azure;
using Azure.Security.CodeTransparency;
using CoseSign1.Abstractions;
using CoseSign1.Abstractions.Transparency;
using CoseSign1.Transparent.MST.Extensions;

/// <summary>
/// Transparency provider for Microsoft's Signing Transparency (MST) service.
/// Implements the V2 transparency architecture pattern.
/// </summary>
public class MstTransparencyProvider : ITransparencyProvider
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ProviderName = "Microsoft Signing Transparency";

        public const string LogPrefixedMessageFormat = "[{0}] {1}";

        public const string LogStartingProofAdditionFormat = "[{0}] Starting transparency proof addition";
        public const string LogEncodedMessageSizeFormat = "[{0}] Encoded message size: {1} bytes";
        public const string LogSubmittingToServiceFormat = "[{0}] Submitting to transparency service...";
        public const string LogEntryCreatedSuccessfullyFormat = "[{0}] Entry created successfully";
        public const string LogEntryIdFormat = "[{0}] Entry ID: {1}";
        public const string LogRetrievingTransparentStatementFormat = "[{0}] Retrieving transparent statement...";
        public const string LogStatementSizeFormat = "[{0}] Statement size: {1} bytes";
        public const string LogDecodingTransparentStatementFormat = "[{0}] Decoding transparent statement";

        public const string ErrorCreateEntryFailedFormat = "CreateEntryAsync failed: {0}";
        public const string ErrorInvalidEntryId = "Response did not contain a valid CBOR-encoded entryId";
        public const string ErrorSubmissionFailedFormat = "MST transparency submission failed. {0}";

        public const string LogStartingVerificationFormat = "[{0}] Starting transparency verification";
        public const string ErrorNoReceipt = "Message does not contain an MST receipt";
        public const string LogReceiptFoundFormat = "[{0}] MST receipt found in message";
        public const string AuthorizedDomainsSeparator = ", ";
        public const string LogAuthorizedDomainsFormat = "[{0}] Authorized domains: {1}";
        public const string LogAuthorizedReceiptBehaviorFormat = "[{0}] Authorized receipt behavior: {1}";
        public const string LogUnauthorizedReceiptBehaviorFormat = "[{0}] Unauthorized receipt behavior: {1}";

        public const string LogCallingVerifyFormat = "[{0}] Calling VerifyTransparentStatement";
        public const string LogVerificationSucceededFormat = "[{0}] Verification succeeded";
        public const string LogVerificationFailedFormat = "[{0}] Verification failed: {1}";

        public const string ErrorCryptographicFormat = "Cryptographic error: {0}";
        public const string ErrorCborContentFormat = "CBOR content error: {0}";
        public const string ErrorInvalidArgumentFormat = "Invalid argument: {0}";

        public const string LogMultipleFailuresFormat = "[{0}] Multiple verification failures";
        public const string LogInnerFailureFormat = "[{0}]   - {1}";

        public const string MetadataKeyVerified = "verified";
        public const string MetadataKeyTimestamp = "timestamp";
    }

    private readonly CodeTransparencyClient Client;
    private readonly ICodeTransparencyVerifier Verifier;
    private readonly CodeTransparencyVerificationOptions? VerificationOptions;
    private readonly CodeTransparencyClientOptions? ClientOptions;
    private readonly Action<string>? LogVerbose;
    private readonly Action<string>? LogError;

    /// <summary>
    /// Gets the name of this transparency provider.
    /// </summary>
    public string ProviderName => ClassStrings.ProviderName;

    /// <summary>
    /// Initializes a new instance of the <see cref="MstTransparencyProvider"/> class.
    /// </summary>
    /// <param name="client">The CodeTransparency client for MST operations.</param>
    public MstTransparencyProvider(CodeTransparencyClient client)
        : this(client, CodeTransparencyVerifierAdapter.Default, null, null, null, null)
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
        : this(client, CodeTransparencyVerifierAdapter.Default, verificationOptions, clientOptions, null, null)
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
        : this(client, CodeTransparencyVerifierAdapter.Default, verificationOptions, clientOptions, logVerbose, logError)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MstTransparencyProvider"/> class with a custom verifier.
    /// </summary>
    /// <param name="client">The CodeTransparency client for MST operations.</param>
    /// <param name="verifier">The verifier for transparent statement validation. Use a mock implementation for testing.</param>
    /// <param name="verificationOptions">Optional verification options for controlling receipt validation behavior.</param>
    /// <param name="clientOptions">Optional client options for configuring client instances used during verification.</param>
    /// <param name="logVerbose">Optional verbose logging callback.</param>
    /// <param name="logError">Optional error logging callback.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="client"/> is null.</exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="verifier"/> is null.</exception>
    public MstTransparencyProvider(
        CodeTransparencyClient client,
        ICodeTransparencyVerifier verifier,
        CodeTransparencyVerificationOptions? verificationOptions,
        CodeTransparencyClientOptions? clientOptions,
        Action<string>? logVerbose,
        Action<string>? logError)
    {
        Guard.ThrowIfNull(client);
        Guard.ThrowIfNull(verifier);

        Client = client;
        Verifier = verifier;
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
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="message"/> is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when MST transparency submission fails.</exception>
    public async Task<CoseSign1Message> AddTransparencyProofAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default)
    {
        Guard.ThrowIfNull(message);

        LogVerbose?.Invoke(string.Format(ClassStrings.LogStartingProofAdditionFormat, ProviderName));

        // Encode the CoseSign1Message to a byte array
        BinaryData content = BinaryData.FromBytes(message.Encode());
        LogVerbose?.Invoke(string.Format(ClassStrings.LogEncodedMessageSizeFormat, ProviderName, content.ToArray().Length));

        // Submit to MST service
        LogVerbose?.Invoke(string.Format(ClassStrings.LogSubmittingToServiceFormat, ProviderName));
        Operation<BinaryData> operation = await Client.CreateEntryAsync(
            WaitUntil.Completed,
            content,
            cancellationToken).ConfigureAwait(false);

        // Check if the operation was successful
        if (!operation.HasValue)
        {
            string error = string.Format(ClassStrings.ErrorCreateEntryFailedFormat, operation.GetRawResponse().ReasonPhrase);
            LogError?.Invoke(string.Format(ClassStrings.LogPrefixedMessageFormat, ProviderName, error));
            throw new InvalidOperationException(string.Format(ClassStrings.ErrorSubmissionFailedFormat, error));
        }

        LogVerbose?.Invoke(string.Format(ClassStrings.LogEntryCreatedSuccessfullyFormat, ProviderName));

        // Get the entryId from the operation result
        if (!operation.Value.TryGetMstEntryId(out string? entryId) || entryId is null)
        {
            string error = ClassStrings.ErrorInvalidEntryId;
            LogError?.Invoke(string.Format(ClassStrings.LogPrefixedMessageFormat, ProviderName, error));
            throw new InvalidOperationException(string.Format(ClassStrings.ErrorSubmissionFailedFormat, error));
        }

        LogVerbose?.Invoke(string.Format(ClassStrings.LogEntryIdFormat, ProviderName, entryId));

        // Retrieve the transparent statement with embedded receipts
        LogVerbose?.Invoke(string.Format(ClassStrings.LogRetrievingTransparentStatementFormat, ProviderName));
        Response<BinaryData> transparentStatement = await Client.GetEntryStatementAsync(
            entryId,
            cancellationToken).ConfigureAwait(false);

        LogVerbose?.Invoke(string.Format(ClassStrings.LogStatementSizeFormat, ProviderName, transparentStatement.Value.ToArray().Length));

        // MST returns the full CoseSign1Message with receipts embedded
        LogVerbose?.Invoke(string.Format(ClassStrings.LogDecodingTransparentStatementFormat, ProviderName));
        return CoseMessage.DecodeSign1(transparentStatement.Value.ToArray());
    }

    /// <summary>
    /// Verifies the MST transparency proof in the message.
    /// </summary>
    /// <param name="message">The COSE Sign1 message with MST receipt.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Validation result with status and details.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="message"/> is null.</exception>
    public Task<TransparencyValidationResult> VerifyTransparencyProofAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default)
    {
        Guard.ThrowIfNull(message);

        LogVerbose?.Invoke(string.Format(ClassStrings.LogStartingVerificationFormat, ProviderName));

        // Check if the message contains a transparency header
        if (!message.HasMstReceipt())
        {
            string error = ClassStrings.ErrorNoReceipt;
            LogError?.Invoke(string.Format(ClassStrings.LogPrefixedMessageFormat, ProviderName, error));
            return Task.FromResult(TransparencyValidationResult.Failure(ProviderName, error));
        }

        LogVerbose?.Invoke(string.Format(ClassStrings.LogReceiptFoundFormat, ProviderName));
        cancellationToken.ThrowIfCancellationRequested();

        // Log verification options if configured
        if (VerificationOptions != null && LogVerbose != null)
        {
            if (VerificationOptions.AuthorizedDomains?.Count > 0)
            {
                LogVerbose.Invoke(string.Format(
                    ClassStrings.LogAuthorizedDomainsFormat,
                    ProviderName,
                    string.Join(ClassStrings.AuthorizedDomainsSeparator, VerificationOptions.AuthorizedDomains)));
            }
            LogVerbose.Invoke(string.Format(
                ClassStrings.LogAuthorizedReceiptBehaviorFormat,
                ProviderName,
                VerificationOptions.AuthorizedReceiptBehavior));
            LogVerbose.Invoke(string.Format(
                ClassStrings.LogUnauthorizedReceiptBehaviorFormat,
                ProviderName,
                VerificationOptions.UnauthorizedReceiptBehavior));
        }

        // Verify using injected verifier (allows mocking for tests)
        try
        {
            LogVerbose?.Invoke(string.Format(ClassStrings.LogCallingVerifyFormat, ProviderName));
            Verifier.VerifyTransparentStatement(
                message.Encode(),
                VerificationOptions,
                ClientOptions);

            LogVerbose?.Invoke(string.Format(ClassStrings.LogVerificationSucceededFormat, ProviderName));

            return Task.FromResult(TransparencyValidationResult.Success(
                ProviderName,
                new Dictionary<string, object>
                {
                    [ClassStrings.MetadataKeyVerified] = true,
                    [ClassStrings.MetadataKeyTimestamp] = DateTimeOffset.UtcNow
                }));
        }
        catch (InvalidOperationException ex)
        {
            LogError?.Invoke(string.Format(ClassStrings.LogVerificationFailedFormat, ProviderName, ex.Message));
            return Task.FromResult(TransparencyValidationResult.Failure(ProviderName, ex.Message));
        }
        catch (CryptographicException ex)
        {
            LogError?.Invoke(string.Format(ClassStrings.LogPrefixedMessageFormat, ProviderName, string.Format(ClassStrings.ErrorCryptographicFormat, ex.Message)));
            return Task.FromResult(TransparencyValidationResult.Failure(
                ProviderName,
                string.Format(ClassStrings.ErrorCryptographicFormat, ex.Message)));
        }
        catch (CborContentException ex)
        {
            LogError?.Invoke(string.Format(ClassStrings.LogPrefixedMessageFormat, ProviderName, string.Format(ClassStrings.ErrorCborContentFormat, ex.Message)));
            return Task.FromResult(TransparencyValidationResult.Failure(
                ProviderName,
                string.Format(ClassStrings.ErrorCborContentFormat, ex.Message)));
        }
        catch (ArgumentException ex)
        {
            LogError?.Invoke(string.Format(ClassStrings.LogPrefixedMessageFormat, ProviderName, string.Format(ClassStrings.ErrorInvalidArgumentFormat, ex.Message)));
            return Task.FromResult(TransparencyValidationResult.Failure(
                ProviderName,
                string.Format(ClassStrings.ErrorInvalidArgumentFormat, ex.Message)));
        }
        catch (AggregateException ex)
        {
            LogError?.Invoke(string.Format(ClassStrings.LogMultipleFailuresFormat, ProviderName));
            var errors = new List<string>();
            foreach (var innerEx in ex.InnerExceptions)
            {
                errors.Add(innerEx.Message);
                LogVerbose?.Invoke(string.Format(ClassStrings.LogInnerFailureFormat, ProviderName, innerEx.Message));
            }
            return Task.FromResult(TransparencyValidationResult.Failure(ProviderName, errors));
        }
    }
}