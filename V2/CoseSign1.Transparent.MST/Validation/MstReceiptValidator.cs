// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Security.Cryptography.Cose;
using System.Threading;
using System.Threading.Tasks;
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST.Extensions;
using CoseSign1.Validation;

namespace CoseSign1.Transparent.MST.Validation;

/// <summary>
/// Validates that a COSE Sign1 message contains valid MST (Microsoft Signing Transparency) receipts.
/// </summary>
/// <remarks>
/// This validator checks for the presence of MST receipts in the message's unprotected headers
/// and verifies their validity using the Azure Code Transparency client.
/// </remarks>
public sealed class MstReceiptValidator : IValidator<CoseSign1Message>
{
    private readonly MstTransparencyProvider Provider;

    /// <summary>
    /// Initializes a new instance of the <see cref="MstReceiptValidator"/> class.
    /// </summary>
    /// <param name="client">The CodeTransparency client for MST verification.</param>
    public MstReceiptValidator(CodeTransparencyClient client)
    {
        if (client == null)
        {
            throw new ArgumentNullException(nameof(client));
        }

        Provider = new MstTransparencyProvider(client);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MstReceiptValidator"/> class with verification options.
    /// </summary>
    /// <param name="client">The CodeTransparency client for MST verification.</param>
    /// <param name="verificationOptions">Options for controlling receipt validation behavior.</param>
    /// <param name="clientOptions">Optional client options for the transparency client.</param>
    public MstReceiptValidator(
        CodeTransparencyClient client,
        CodeTransparencyVerificationOptions verificationOptions,
        CodeTransparencyClientOptions? clientOptions = null)
    {
        if (client == null)
        {
            throw new ArgumentNullException(nameof(client));
        }

        if (verificationOptions == null)
        {
            throw new ArgumentNullException(nameof(verificationOptions));
        }

        Provider = new MstTransparencyProvider(client, verificationOptions, clientOptions);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MstReceiptValidator"/> class using an existing provider.
    /// </summary>
    /// <param name="provider">The MST transparency provider to use for validation.</param>
    public MstReceiptValidator(MstTransparencyProvider provider)
    {
        Provider = provider ?? throw new ArgumentNullException(nameof(provider));
    }

    /// <summary>
    /// Validates that the message contains valid MST receipts.
    /// </summary>
    /// <param name="input">The COSE Sign1 message to validate.</param>
    /// <returns>A validation result indicating success or failure.</returns>
    public ValidationResult Validate(CoseSign1Message input)
    {
        // Synchronous validation - run async method synchronously
        return ValidateAsync(input, CancellationToken.None).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Asynchronously validates that the message contains valid MST receipts.
    /// </summary>
    /// <param name="input">The COSE Sign1 message to validate.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task that represents the asynchronous validation operation.</returns>
    public async Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
    {
        if (input == null)
        {
            return ValidationResult.Failure(
                "MstReceiptValidator",
                "Input message cannot be null",
                "MST_NULL_INPUT");
        }

        // Check if message has MST receipt
        if (!input.HasMstReceipt())
        {
            return ValidationResult.Failure(
                "MstReceiptValidator",
                "Message does not contain an MST receipt in unprotected headers",
                "MST_NO_RECEIPT");
        }

        // Verify the receipt using the MST provider
        try
        {
            var transparencyResult = await Provider.VerifyTransparencyProofAsync(input, cancellationToken)
                .ConfigureAwait(false);

            if (!transparencyResult.IsValid)
            {
                // Convert transparency validation errors to validator failures
                var failures = new ValidationFailure[transparencyResult.Errors.Count];
                for (int i = 0; i < transparencyResult.Errors.Count; i++)
                {
                    failures[i] = new ValidationFailure
                    {
                        Message = transparencyResult.Errors[i],
                        ErrorCode = "MST_VERIFICATION_FAILED"
                    };
                }

                return ValidationResult.Failure("MstReceiptValidator", failures);
            }

            // Success - optionally include metadata from transparency result
            var metadata = new Dictionary<string, object>
            {
                ["ProviderName"] = transparencyResult.ProviderName ?? "MST"
            };

            if (transparencyResult.Metadata != null)
            {
                foreach (var kvp in transparencyResult.Metadata)
                {
                    metadata[kvp.Key] = kvp.Value;
                }
            }

            return ValidationResult.Success("MstReceiptValidator", metadata);
        }
        catch (Exception ex)
        {
            return ValidationResult.Failure(
                "MstReceiptValidator",
                new ValidationFailure
                {
                    Message = $"MST receipt verification failed with exception: {ex.Message}",
                    ErrorCode = "MST_VERIFICATION_EXCEPTION",
                    Exception = ex
                });
        }
    }
}