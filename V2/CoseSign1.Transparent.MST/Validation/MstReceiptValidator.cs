// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Validation;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.Cose;
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST.Extensions;
using CoseSign1.Validation;
using CoseSign1.Validation.Builders;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;

/// <summary>
/// Validates that a COSE Sign1 message contains valid MST (Microsoft Signing Transparency) receipts.
/// </summary>
/// <remarks>
/// This validator checks for the presence of MST receipts in the message's unprotected headers
/// and verifies their validity using the Azure Code Transparency client.
/// </remarks>
public sealed class MstReceiptValidator : IConditionalValidator, IProvidesDefaultTrustPolicy
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ValidatorName = nameof(MstReceiptValidator);

        public const string NotApplicableReasonUnsupportedStageFormat = "Unsupported validation stage: {0}";

        public const string ErrorMessageNullInput = "Input message cannot be null";
        public const string ErrorCodeNullInput = "MST_NULL_INPUT";

        public const string TrustDetailsNoReceipt = "NoReceipt";
        public const string TrustDetailsVerificationFailed = "VerificationFailed";
        public const string TrustDetailsException = "Exception";

        public const string MetadataKeyProviderName = "ProviderName";
        public const string MetadataKeyErrors = "Errors";
        public const string MetadataKeyExceptionType = "ExceptionType";
        public const string MetadataKeyExceptionMessage = "ExceptionMessage";

        public const string DefaultProviderName = "MST";
    }

    private readonly MstTransparencyProvider Provider;

    private static readonly IReadOnlyCollection<ValidationStage> StagesField = new[] { ValidationStage.KeyMaterialTrust };

    /// <inheritdoc/>
    public IReadOnlyCollection<ValidationStage> Stages => StagesField;

    /// <summary>
    /// Initializes a new instance of the <see cref="MstReceiptValidator"/> class.
    /// </summary>
    /// <param name="client">The CodeTransparency client for MST verification.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="client"/> is null.</exception>
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
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="client"/> is null.</exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="verificationOptions"/> is null.</exception>
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
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="provider"/> is null.</exception>
    public MstReceiptValidator(MstTransparencyProvider provider)
    {
        Provider = provider ?? throw new ArgumentNullException(nameof(provider));
    }

    /// <summary>
    /// Validates that the message contains valid MST receipts.
    /// </summary>
    /// <param name="input">The COSE Sign1 message to validate.</param>
    /// <param name="stage">The validation stage being executed.</param>
    /// <returns>A validation result indicating success or failure.</returns>
    public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
    {
        if (stage != ValidationStage.KeyMaterialTrust)
        {
            return ValidationResult.NotApplicable(
                ClassStrings.ValidatorName,
                stage,
                string.Format(ClassStrings.NotApplicableReasonUnsupportedStageFormat, stage));
        }

        // Synchronous validation - run async method synchronously
        return ValidateAsync(input, stage, CancellationToken.None).GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public bool IsApplicable(CoseSign1Message input, ValidationStage stage)
    {
        if (input == null)
        {
            return false;
        }

        if (stage != ValidationStage.KeyMaterialTrust)
        {
            return false;
        }

        return input.HasMstReceipt();
    }

    /// <summary>
    /// Asynchronously validates that the message contains valid MST receipts.
    /// </summary>
    /// <param name="input">The COSE Sign1 message to validate.</param>
    /// <param name="stage">The validation stage being executed.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task that represents the asynchronous validation operation.</returns>
    public async Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
    {
        if (stage != ValidationStage.KeyMaterialTrust)
        {
            return ValidationResult.NotApplicable(
                ClassStrings.ValidatorName,
                stage,
                string.Format(ClassStrings.NotApplicableReasonUnsupportedStageFormat, stage));
        }

        if (input == null)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                stage,
                ClassStrings.ErrorMessageNullInput,
                ClassStrings.ErrorCodeNullInput);
        }

        // Check if message has MST receipt
        if (!input.HasMstReceipt())
        {
            // For trust policy evaluation: emit a negative receipt-present claim.
            return ValidationResult.Success(ClassStrings.ValidatorName, stage, new Dictionary<string, object>
            {
                [TrustAssertionMetadata.AssertionsKey] = new[]
                {
                    new TrustAssertion(MstTrustClaims.ReceiptPresent, satisfied: false),
                    new TrustAssertion(MstTrustClaims.ReceiptTrusted, satisfied: false, details: ClassStrings.TrustDetailsNoReceipt)
                }
            });
        }

        // Verify the receipt using the MST provider
        try
        {
            var transparencyResult = await Provider.VerifyTransparencyProofAsync(input, cancellationToken)
                .ConfigureAwait(false);

            if (!transparencyResult.IsValid)
            {
                // Emit negative trust claim; details remain in metadata.
                var metadata = new Dictionary<string, object>
                {
                    [TrustAssertionMetadata.AssertionsKey] = new[]
                    {
                        new TrustAssertion(MstTrustClaims.ReceiptPresent, satisfied: true),
                        new TrustAssertion(MstTrustClaims.ReceiptTrusted, satisfied: false, details: ClassStrings.TrustDetailsVerificationFailed)
                    },
                    [ClassStrings.MetadataKeyProviderName] = transparencyResult.ProviderName ?? ClassStrings.DefaultProviderName,
                    [ClassStrings.MetadataKeyErrors] = transparencyResult.Errors.ToArray()
                };

                if (transparencyResult.Metadata != null)
                {
                    foreach (var kvp in transparencyResult.Metadata)
                    {
                        metadata[kvp.Key] = kvp.Value;
                    }
                }

                return ValidationResult.Success(ClassStrings.ValidatorName, stage, metadata);
            }

            // Success - optionally include metadata from transparency result
            var successMetadata = new Dictionary<string, object>
            {
                [ClassStrings.MetadataKeyProviderName] = transparencyResult.ProviderName ?? ClassStrings.DefaultProviderName,
                [TrustAssertionMetadata.AssertionsKey] = new[]
                {
                    new TrustAssertion(MstTrustClaims.ReceiptPresent, satisfied: true),
                    new TrustAssertion(MstTrustClaims.ReceiptTrusted, satisfied: true)
                }
            };

            if (transparencyResult.Metadata != null)
            {
                foreach (var kvp in transparencyResult.Metadata)
                {
                    successMetadata[kvp.Key] = kvp.Value;
                }
            }

            return ValidationResult.Success(ClassStrings.ValidatorName, stage, successMetadata);
        }
        catch (Exception ex)
        {
            // Treat exceptions as a negative trust claim (so policy can decide), but preserve details.
            return ValidationResult.Success(ClassStrings.ValidatorName, stage, new Dictionary<string, object>
            {
                [TrustAssertionMetadata.AssertionsKey] = new[]
                {
                    new TrustAssertion(MstTrustClaims.ReceiptPresent, satisfied: true),
                    new TrustAssertion(MstTrustClaims.ReceiptTrusted, satisfied: false, details: ClassStrings.TrustDetailsException)
                },
                [ClassStrings.MetadataKeyExceptionType] = ex.GetType().FullName ?? ex.GetType().Name,
                [ClassStrings.MetadataKeyExceptionMessage] = ex.Message
            });
        }
    }

    /// <inheritdoc/>
    public TrustPolicy GetDefaultTrustPolicy(ValidationBuilderContext context)
    {
        return TrustPolicy.And(
            TrustPolicy.Claim(MstTrustClaims.ReceiptPresent),
            TrustPolicy.Claim(MstTrustClaims.ReceiptTrusted));
    }
}